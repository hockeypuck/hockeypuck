/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package gdpr

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Action is the operation an audit Entry records.
type Action string

const (
	ActionExport Action = "export"
	ActionErase  Action = "erase"
	ActionVerify Action = "verify"
)

// Result is the outcome of the Action for one key.
type Result string

const (
	// ResultExported means key material was written to an evidence file.
	ResultExported Result = "exported"
	// ResultErased means the key was removed from storage.
	ResultErased Result = "erased"
	// ResultNotFound means there was nothing to erase.
	ResultNotFound Result = "notFound"
	// ResultFailed means the erasure was attempted and errored.
	ResultFailed Result = "failed"
	// ResultPresent means a previously erased key has reappeared, which almost
	// always means it was re-offered by a reconciliation partner because the
	// fingerprint is not blacklisted.
	ResultPresent Result = "present"
)

// Entry is one line of the append-only audit trail. It is the record that
// demonstrates which erasure request was actioned, by whom, and with what
// outcome, without itself becoming a fresh store of the personal data that was
// erased: user IDs are summarised as UserIDHash unless the operator explicitly
// asks for them to be retained.
type Entry struct {
	Time        time.Time `json:"time"`
	Action      Action    `json:"action"`
	Result      Result    `json:"result"`
	Case        string    `json:"case,omitempty"`
	Operator    string    `json:"operator,omitempty"`
	Requester   string    `json:"requester,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	MD5         string    `json:"md5,omitempty"`
	UserIDs     []string  `json:"userIDs,omitempty"`
	UserIDHash  string    `json:"userIDHash,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	DryRun      bool      `json:"dryRun,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// HashUserIDs summarises a key's user IDs as a short digest. It lets an auditor
// confirm that the key erased was the key described in the request, without the
// audit trail retaining the addresses that the request asked to erase.
func HashUserIDs(uids []string) string {
	if len(uids) == 0 {
		return ""
	}
	normalised := make([]string, len(uids))
	for i, uid := range uids {
		normalised[i] = strings.ToLower(strings.TrimSpace(uid))
	}
	sort.Strings(normalised)
	sum := sha256.Sum256([]byte(strings.Join(normalised, "\n")))
	return hex.EncodeToString(sum[:16])
}

// Log is an append-only JSON Lines audit trail.
type Log struct {
	path string
	f    *os.File
}

// OpenLog opens (creating if necessary) the audit trail at path. The file is
// opened for append only and kept private to its owner, because it names the
// data subjects whose requests were actioned.
func OpenLog(path string) (*Log, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, errors.Wrapf(err, "cannot create audit log directory %q", dir)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot open audit log %q", path)
	}
	return &Log{path: path, f: f}, nil
}

// Path returns the location of the audit trail.
func (l *Log) Path() string { return l.path }

// Append writes one entry, timestamping it if the caller did not. It syncs on
// every write: an erasure that is not durably recorded is worse than useless.
func (l *Log) Append(entry Entry) error {
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	} else {
		entry.Time = entry.Time.UTC()
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return errors.Wrapf(err, "cannot write to audit log %q", l.path)
	}
	return errors.Wrapf(l.f.Sync(), "cannot flush audit log %q", l.path)
}

// Close releases the audit trail.
func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	return errors.WithStack(l.f.Close())
}

// ReadLog returns every entry in the audit trail at path, oldest first. A trail
// that does not exist yet reads as empty rather than as an error.
func ReadLog(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "cannot read audit log %q", path)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var entry Entry
		if err := json.Unmarshal([]byte(text), &entry); err != nil {
			return nil, errors.Wrapf(err, "corrupt audit log %q at line %d", path, line)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrapf(err, "cannot read audit log %q", path)
	}
	return entries, nil
}

// Filter selects a subset of audit entries. Zero-valued fields do not restrict.
type Filter struct {
	Case   string
	Action Action
	Result Result
	Since  time.Time
	// IncludeDryRun keeps entries that only previewed an erasure.
	IncludeDryRun bool
}

// Match reports whether entry satisfies every set field of f.
func (f Filter) Match(entry Entry) bool {
	if f.Case != "" && !strings.EqualFold(f.Case, entry.Case) {
		return false
	}
	if f.Action != "" && f.Action != entry.Action {
		return false
	}
	if f.Result != "" && f.Result != entry.Result {
		return false
	}
	if !f.Since.IsZero() && entry.Time.Before(f.Since) {
		return false
	}
	if entry.DryRun && !f.IncludeDryRun {
		return false
	}
	return true
}

// FilterEntries returns the entries satisfying f, in trail order.
func FilterEntries(entries []Entry, f Filter) []Entry {
	var result []Entry
	for _, entry := range entries {
		if f.Match(entry) {
			result = append(result, entry)
		}
	}
	return result
}

// ErasedFingerprints returns the deduplicated, sorted fingerprints that the
// trail records as actually erased (dry runs excluded), narrowed by f. These
// are the fingerprints that must stay blacklisted and that erasure can be
// re-verified against.
func ErasedFingerprints(entries []Entry, f Filter) []string {
	f.Action = ActionErase
	f.Result = ResultErased
	f.IncludeDryRun = false
	var fps []string
	for _, entry := range FilterEntries(entries, f) {
		if entry.Fingerprint != "" {
			fps = append(fps, entry.Fingerprint)
		}
	}
	return NormalizeFingerprints(fps)
}
