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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"hockeypuck/gdpr"
	"hockeypuck/server"
)

var (
	auditSince    string
	auditAction   string
	auditDryRuns  bool
	auditPathOnly bool
)

var auditCommand = &command{
	name:    "audit",
	aliases: []string{"log"},
	args:    "",
	summary: "show what has been erased, when, and on whose request",
	description: `
Show the audit trail: the append-only record of which erasure requests were
actioned against this keyserver, by whom, and with what outcome. It is what
demonstrates compliance after the fact, and what "verify" and "blacklist" read
their fingerprints from.

By default user IDs are recorded only as a digest, so that the trail does not
itself become a store of the personal data that was erased. The digest is still
enough to confirm that the key erased was the key the request described.

The trail lives beside the reconciliation database unless -audit or $` + auditEnv + `
says otherwise. This command reads it and nothing else; it does not touch the
database.`,
	setup: func(fs *flag.FlagSet) {
		fs.StringVar(&auditSince, "since", "", "only entries at or after this time (2006-01-02, RFC 3339, or a duration such as 720h)")
		fs.StringVar(&auditAction, "action", "", "only entries for this action (export, erase or verify)")
		fs.BoolVar(&auditDryRuns, "dry-runs", false, "include entries that only previewed an erasure")
		fs.BoolVar(&auditPathOnly, "path", false, "print the resolved audit trail path and exit")
		addCaseFlags(fs)
		addAuditFlag(fs)
		addJSONFlag(fs)
	},
	run: runAudit,
}

func runAudit(settings *server.Settings, args []string) error {
	if len(args) > 0 {
		return usagef("unexpected arguments: %s", strings.Join(args, " "))
	}
	path := auditPath(settings)
	if auditPathOnly {
		fmt.Fprintln(os.Stdout, path)
		return nil
	}

	since, err := parseSince(auditSince)
	if err != nil {
		return err
	}
	entries, err := gdpr.ReadLog(path)
	if err != nil {
		return err
	}
	entries = gdpr.FilterEntries(entries, gdpr.Filter{
		Case:          flagCase,
		Action:        gdpr.Action(auditAction),
		Since:         since,
		IncludeDryRun: auditDryRuns,
	})

	if flagJSON {
		if entries == nil {
			entries = []gdpr.Entry{}
		}
		return writeJSON(os.Stdout, entries)
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "no matching entries in %s\n", path)
		return nil
	}
	for _, entry := range entries {
		printEntry(entry)
	}
	fmt.Fprintf(os.Stderr, "\n%s from %s\n", plural(len(entries), "entry", "entries"), path)
	return nil
}

func printEntry(entry gdpr.Entry) {
	line := fmt.Sprintf("%s  %-6s  %-9s  0x%s",
		entry.Time.UTC().Format(time.RFC3339), entry.Action, entry.Result, entry.Fingerprint)
	if entry.DryRun {
		line += "  [dry run]"
	}
	fmt.Fprintln(os.Stdout, line)

	var details []string
	if entry.Case != "" {
		details = append(details, "case "+entry.Case)
	}
	if entry.Operator != "" {
		details = append(details, "by "+entry.Operator)
	}
	if entry.Requester != "" {
		details = append(details, "for "+entry.Requester)
	}
	if entry.Reason != "" {
		details = append(details, entry.Reason)
	}
	if len(details) > 0 {
		fmt.Fprintf(os.Stdout, "    %s\n", strings.Join(details, "  |  "))
	}
	if entry.UserIDHash != "" {
		fmt.Fprintf(os.Stdout, "    uid digest %s\n", entry.UserIDHash)
	}
	for _, uid := range entry.UserIDs {
		fmt.Fprintf(os.Stdout, "    uid  %s\n", uid)
	}
	if entry.Evidence != "" {
		fmt.Fprintf(os.Stdout, "    evidence %s\n", entry.Evidence)
	}
	if entry.Error != "" {
		fmt.Fprintf(os.Stdout, "    error %s\n", entry.Error)
	}
}

// parseSince accepts an absolute date, an RFC 3339 timestamp, or a duration to
// look back by, because all three are natural ways to ask "what happened
// recently".
func parseSince(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		return time.Now().UTC().Add(-d), nil
	}
	return time.Time{}, usagef("cannot parse -since %q as a date, an RFC 3339 timestamp or a duration", value)
}
