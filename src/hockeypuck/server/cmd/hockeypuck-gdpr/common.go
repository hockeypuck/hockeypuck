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

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/pkg/errors"

	"hockeypuck/gdpr"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
)

// cliError is a failure the operator should see as a plain message rather than
// as a stack trace: either a problem with what was asked for, or a finding the
// command exists to report. Genuine faults keep their stack traces, which is
// what makes them worth reading.
type cliError struct {
	code  int
	cause error
}

func (e cliError) Error() string { return e.cause.Error() }
func (e cliError) Unwrap() error { return e.cause }

// exitUsage is returned when the operator asked for something that does not
// make sense, by analogy with the flag package's own exit code.
const exitUsage = 2

// usagef reports a problem with the arguments or flags.
func usagef(format string, args ...any) error {
	return cliError{code: exitUsage, cause: fmt.Errorf(format, args...)}
}

// usage marks an existing error as a problem with the arguments or flags.
func usage(err error) error {
	if err == nil {
		return nil
	}
	return cliError{code: exitUsage, cause: err}
}

// ptreeRepair says how to bring a stale reconciliation prefix tree back into
// line with the database. hockeypuck-pbuild only inserts, so it cannot retract
// the digest of an erased key on its own: the tree has to be removed first and
// rebuilt from what the database actually holds.
const ptreeRepair = "remove the prefix tree and rebuild it with hockeypuck-pbuild"

// preconditionf reports an environmental precondition the operator has to
// resolve before the command can run, such as a lock the running server holds.
func preconditionf(format string, args ...any) error {
	return cliError{code: exitUsage, cause: fmt.Errorf(format, args...)}
}

// findingf reports something the command was asked to look for, such as key
// material that has come back after erasure. It fails so that a scheduled run
// is noticed, but it is not a malfunction.
func findingf(format string, args ...any) error {
	return cliError{code: 1, cause: fmt.Errorf(format, args...)}
}

// Flags shared by more than one subcommand. They are registered per subcommand
// so that each -h listing only shows what that subcommand actually honours.
var (
	flagCase      string
	flagOperator  string
	flagRequester string
	flagReason    string
	flagAudit     string
	flagTermsFile string
	flagJSON      bool
)

func addCaseFlags(fs *flag.FlagSet) {
	fs.StringVar(&flagCase, "case", "", "erasure request reference, recorded in the audit trail")
	fs.StringVar(&flagOperator, "operator", defaultOperator(), "person actioning the request, recorded in the audit trail")
}

func addRequestFlags(fs *flag.FlagSet) {
	fs.StringVar(&flagRequester, "requester", "", "data subject who made the request, recorded in the audit trail")
	fs.StringVar(&flagReason, "reason", "", "lawful basis or note, recorded in the audit trail")
}

func addAuditFlag(fs *flag.FlagSet) {
	fs.StringVar(&flagAudit, "audit", "", "audit trail path (default $"+auditEnv+", else alongside the recon database)")
}

func addTermsFileFlag(fs *flag.FlagSet) {
	fs.StringVar(&flagTermsFile, "f", "", `read search terms from a file, one per line ("-" for stdin)`)
}

func addJSONFlag(fs *flag.FlagSet) {
	fs.BoolVar(&flagJSON, "json", false, "emit JSON instead of human readable output")
}

// defaultOperator identifies who is running the tool, preferring the human
// behind a sudo invocation over the service account it elevated to.
func defaultOperator() string {
	if sudo := os.Getenv("SUDO_USER"); sudo != "" {
		return sudo
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// auditPath resolves the audit trail location for this run.
func auditPath(settings *server.Settings) string {
	if flagAudit != "" {
		return flagAudit
	}
	return defaultAuditPath(settings)
}

// collectTargets gathers search terms from the command line and, if -f was
// given, from a file or stdin, then normalises them.
func collectTargets(args []string) ([]gdpr.Target, error) {
	terms := append([]string(nil), args...)
	if flagTermsFile != "" {
		fromFile, err := readTermsFile(flagTermsFile)
		if err != nil {
			return nil, err
		}
		terms = append(terms, fromFile...)
	}
	if len(terms) == 0 {
		return nil, usagef("no search terms given; pass them as arguments or with -f")
	}
	targets, err := gdpr.ParseTargets(terms)
	if err != nil {
		return nil, usage(err)
	}
	gdpr.SortTargets(targets)
	return targets, nil
}

func readTermsFile(path string) ([]string, error) {
	if path == "-" {
		return gdpr.ReadTerms(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, usage(errors.Wrapf(err, "cannot read search terms from %q", path))
	}
	defer f.Close()
	return gdpr.ReadTerms(f)
}

// collectFingerprints gathers bare fingerprints from the command line and -f.
// Unlike collectTargets it rejects anything that is not a fingerprint, because
// its callers act on an already-decided set of keys rather than searching.
func collectFingerprints(args []string) ([]string, error) {
	targets, err := collectTargets(args)
	if err != nil {
		return nil, err
	}
	var fps []string
	var bad []string
	for _, target := range targets {
		if target.Kind != gdpr.KindFingerprint {
			bad = append(bad, target.Raw)
			continue
		}
		fps = append(fps, target.Value)
	}
	if len(bad) > 0 {
		return nil, usagef("expected full fingerprints, got: %s", strings.Join(bad, ", "))
	}
	return gdpr.NormalizeFingerprints(fps), nil
}

// userIDStrings returns a record's user IDs, or nil if the stored key material
// could not be parsed.
func userIDStrings(record *storage.Record) []string {
	if record.PrimaryKey == nil {
		return nil
	}
	uids := make([]string, 0, len(record.PrimaryKey.UserIDs))
	for _, uid := range record.PrimaryKey.UserIDs {
		text := uid.Keywords
		if uid.IsRevoked {
			text += " (revoked)"
		}
		uids = append(uids, text)
	}
	return uids
}

// describeRecord renders one key the way an operator needs to see it before
// deciding to erase it: what it is, when it was seen, and who it claims to be.
func describeRecord(w io.Writer, record *storage.Record) {
	if record.PrimaryKey == nil {
		fmt.Fprintf(w, "0x%s  <unparseable key material>  md5 %s  modified %s\n",
			record.Fingerprint, record.MD5, record.MTime.UTC().Format(time.RFC3339))
		return
	}
	pk := record.PrimaryKey
	flags := ""
	if pk.IsRevoked {
		flags = "  revoked"
	}
	fmt.Fprintf(w, "0x%s  v%d %s%s\n", record.Fingerprint, pk.Version,
		openpgp.AlgorithmName(pk.Algorithm, pk.BitLen, pk.Curve), flags)
	fmt.Fprintf(w, "    created %s  modified %s  md5 %s\n",
		pk.Creation.UTC().Format("2006-01-02"),
		record.MTime.UTC().Format("2006-01-02"), record.MD5)
	for _, uid := range userIDStrings(record) {
		fmt.Fprintf(w, "    uid  %s\n", uid)
	}
	for _, sub := range pk.SubKeys {
		fmt.Fprintf(w, "    sub  0x%s  %s\n", sub.Fingerprint,
			openpgp.AlgorithmName(sub.Algorithm, sub.BitLen, sub.Curve))
	}
}

// recordJSON is the stable, scriptable view of a key. It deliberately does not
// reproduce the full jsonhkp document: these are the fields an erasure workflow
// needs, and nothing more.
type recordJSON struct {
	Fingerprint string   `json:"fingerprint"`
	MD5         string   `json:"md5"`
	Created     string   `json:"created,omitempty"`
	Modified    string   `json:"modified"`
	Algorithm   string   `json:"algorithm,omitempty"`
	Revoked     bool     `json:"revoked,omitempty"`
	UserIDs     []string `json:"userIDs,omitempty"`
	Parseable   bool     `json:"parseable"`
}

func newRecordJSON(record *storage.Record) recordJSON {
	out := recordJSON{
		Fingerprint: record.Fingerprint,
		MD5:         record.MD5,
		Modified:    record.MTime.UTC().Format(time.RFC3339),
		UserIDs:     userIDStrings(record),
	}
	if pk := record.PrimaryKey; pk != nil {
		out.Parseable = true
		out.Created = pk.Creation.UTC().Format(time.RFC3339)
		out.Algorithm = openpgp.AlgorithmName(pk.Algorithm, pk.BitLen, pk.Curve)
		out.Revoked = pk.IsRevoked
	}
	return out
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return errors.WithStack(enc.Encode(value))
}

// writeArmoredKey serialises one key as an ASCII-armored certificate, using the
// same armor headers the server itself would emit.
func writeArmoredKey(w io.Writer, settings *server.Settings, record *storage.Record) error {
	if record.PrimaryKey == nil {
		return errors.Errorf("no parseable key material stored for 0x%s", record.Fingerprint)
	}
	return errors.WithStack(openpgp.WriteArmoredPackets(w,
		[]*openpgp.PrimaryKey{record.PrimaryKey}, false, server.KeyWriterOptions(settings)...))
}

// newEntry seeds an audit entry with the provenance flags common to every
// action, and with a digest of the user IDs rather than the user IDs
// themselves. Retaining the addresses a subject asked to have erased would
// defeat the point of the exercise, so recordUserIDs is opt-in.
func newEntry(action gdpr.Action, record *storage.Record, recordUserIDs bool) gdpr.Entry {
	uids := userIDStrings(record)
	entry := gdpr.Entry{
		Time:        time.Now().UTC(),
		Action:      action,
		Case:        flagCase,
		Operator:    flagOperator,
		Requester:   flagRequester,
		Reason:      flagReason,
		Fingerprint: record.Fingerprint,
		MD5:         record.MD5,
		UserIDHash:  gdpr.HashUserIDs(uids),
	}
	if recordUserIDs {
		entry.UserIDs = uids
	}
	return entry
}

// noConfirmation is what an operator is told when consent could not be sought.
const noConfirmation = "refusing to erase key material without confirmation: " +
	"re-run with -yes, or with -dry-run to preview"

// maybeTerminal reports whether stdin could plausibly carry a typed answer.
// A pipe or a redirected file certainly cannot; a character device usually can,
// though /dev/null (which cron and systemd hand over) also looks like one, so
// the caller must still handle reading nothing.
func maybeTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// confirm demands an explicit "yes" on the terminal. It fails rather than
// assuming consent when there is nobody to ask, so that an unattended run can
// only erase key material if it was told to with -yes.
func confirm(prompt string) error {
	if !maybeTerminal(os.Stdin) {
		return usagef("%s", noConfirmation)
	}
	fmt.Fprint(os.Stderr, prompt)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return errors.WithStack(err)
	}
	answer = strings.TrimSpace(answer)
	if answer == "" && err == io.EOF {
		// Nothing was on the far end after all, e.g. stdin is /dev/null.
		fmt.Fprintln(os.Stderr)
		return usagef("%s", noConfirmation)
	}
	if !strings.EqualFold(answer, "yes") {
		return cliError{code: 1, cause: errors.New("aborted at confirmation prompt")}
	}
	return nil
}

// plural is a small helper for readable summaries.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}
