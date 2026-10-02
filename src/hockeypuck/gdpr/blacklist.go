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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

// blacklistHeader explains the generated file to whoever finds it next.
const blacklistHeader = `# Fingerprints of key material erased in response to data subject erasure
# requests, maintained by hockeypuck-gdpr.
#
# Erasing a key from the database is not enough on its own: reconciliation
# partners still hold it and will re-offer it, so it must also be blacklisted.
# Merge the array below into the [hockeypuck.openpgp] section of your
# hockeypuck.conf and reload hockeypuck for it to take effect.
`

// NormalizeFingerprints lowercases, deduplicates and sorts fingerprints so that
// comparisons and generated files are stable regardless of input order or case.
func NormalizeFingerprints(fps []string) []string {
	seen := make(map[string]bool, len(fps))
	var result []string
	for _, fp := range fps {
		fp = strings.ToLower(strings.TrimSpace(fp))
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		result = append(result, fp)
	}
	sort.Strings(result)
	return result
}

// MissingFromBlacklist returns the fingerprints that are not covered by the
// given blacklist. Hockeypuck matches blacklist entries case-insensitively, so
// this comparison does too.
func MissingFromBlacklist(blacklist, fps []string) []string {
	listed := make(map[string]bool, len(blacklist))
	for _, entry := range blacklist {
		listed[strings.ToLower(strings.TrimSpace(entry))] = true
	}
	var missing []string
	for _, fp := range NormalizeFingerprints(fps) {
		if !listed[fp] {
			missing = append(missing, fp)
		}
	}
	return missing
}

// BlacklistTOML renders fingerprints as a configuration fragment that can be
// pasted into hockeypuck.conf as-is.
func BlacklistTOML(fps []string) string {
	var b strings.Builder
	b.WriteString("[hockeypuck.openpgp]\nblacklist = [\n")
	for _, fp := range NormalizeFingerprints(fps) {
		fmt.Fprintf(&b, "    %q,\n", fp)
	}
	b.WriteString("]\n")
	return b.String()
}

// blacklistDoc accepts both the nested form written by BlacklistTOML and a bare
// "blacklist = [...]" fragment, so that a hand-edited file still round-trips.
type blacklistDoc struct {
	Hockeypuck struct {
		OpenPGP struct {
			Blacklist []string `toml:"blacklist"`
		} `toml:"openpgp"`
	} `toml:"hockeypuck"`
	Blacklist []string `toml:"blacklist"`
}

// ReadBlacklistFile returns the fingerprints recorded in a blacklist fragment.
// A file that does not exist yet reads as empty rather than as an error.
func ReadBlacklistFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "cannot read blacklist %q", path)
	}
	var doc blacklistDoc
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil, errors.Wrapf(err, "cannot parse blacklist %q", path)
	}
	return NormalizeFingerprints(append(doc.Hockeypuck.OpenPGP.Blacklist, doc.Blacklist...)), nil
}

// WriteBlacklistFile atomically replaces the blacklist fragment at path.
func WriteBlacklistFile(path string, fps []string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return errors.Wrapf(err, "cannot create blacklist directory %q", dir)
		}
	}
	content := blacklistHeader + "\n" + BlacklistTOML(fps)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return errors.Wrapf(err, "cannot write blacklist %q", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return errors.Wrapf(err, "cannot replace blacklist %q", path)
	}
	return nil
}

// MergeBlacklistFile adds fps to the blacklist fragment at path, returning the
// fingerprints that were newly added and the full contents afterwards. It is
// idempotent, so it is safe to re-run over a case that was already actioned.
func MergeBlacklistFile(path string, fps []string) (added, all []string, err error) {
	existing, err := ReadBlacklistFile(path)
	if err != nil {
		return nil, nil, err
	}
	added = MissingFromBlacklist(existing, fps)
	if len(added) == 0 {
		return nil, existing, nil
	}
	all = NormalizeFingerprints(append(existing, added...))
	if err := WriteBlacklistFile(path, all); err != nil {
		return nil, nil, err
	}
	return added, all, nil
}
