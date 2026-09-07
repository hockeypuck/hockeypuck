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

	"github.com/pkg/errors"

	"hockeypuck/gdpr"
	"hockeypuck/server"
)

var verifyCommand = &command{
	name:    "verify",
	args:    "[FINGERPRINT ...]",
	summary: "check that previously erased keys are still absent",
	description: `
Check that key material erased earlier has stayed erased. With no arguments the
fingerprints are taken from the audit trail, so "verify -case REF" re-checks one
request and a bare "verify" re-checks every erasure this server has performed.

A key that has come back was almost certainly re-offered by a reconciliation
partner because its fingerprint is not blacklisted; "blacklist -check" will say
whether that is the case. Reappearances are recorded in the audit trail, and the
command exits non-zero when it finds any, so it can be run from cron.

This command only reads from the database; it takes no locks and is safe to run
against a live server.`,
	setup: func(fs *flag.FlagSet) {
		addTermsFileFlag(fs)
		addCaseFlags(fs)
		addAuditFlag(fs)
		addJSONFlag(fs)
	},
	run: runVerify,
}

// verifyResult is one line of the verification report.
type verifyResult struct {
	Fingerprint string `json:"fingerprint"`
	Present     bool   `json:"present"`
}

func runVerify(settings *server.Settings, args []string) error {
	fps, err := fingerprintsToVerify(settings, args)
	if err != nil {
		return err
	}
	if len(fps) == 0 {
		fmt.Fprintln(os.Stderr, "no erased fingerprints to verify")
		return nil
	}

	s, err := openSession(settings, false)
	if err != nil {
		return err
	}
	defer s.Close()

	records, err := s.storage.FetchRecordsByFp(fps)
	if err != nil {
		return errors.WithStack(err)
	}
	present := make(map[string]bool, len(records))
	for _, record := range records {
		present[record.Fingerprint] = true
	}

	results := make([]verifyResult, 0, len(fps))
	for _, fp := range fps {
		results = append(results, verifyResult{Fingerprint: fp, Present: present[fp]})
	}

	if err := recordReappearances(settings, results); err != nil {
		return err
	}

	if flagJSON {
		if err := writeJSON(os.Stdout, results); err != nil {
			return err
		}
	} else {
		for _, result := range results {
			status := "absent"
			if result.Present {
				status = "PRESENT AGAIN"
			}
			fmt.Fprintf(os.Stdout, "0x%s  %s\n", result.Fingerprint, status)
		}
	}

	if len(present) > 0 {
		return findingf("%s reappeared after erasure; check that they are blacklisted "+
			"(hockeypuck-gdpr blacklist -check) and re-run the erasure",
			plural(len(present), "key", "keys"))
	}
	fmt.Fprintf(os.Stderr, "%s still absent\n", plural(len(fps), "key", "keys"))
	return nil
}

// fingerprintsToVerify takes the fingerprints from the command line if any were
// given, and otherwise from what the audit trail records as erased.
func fingerprintsToVerify(settings *server.Settings, args []string) ([]string, error) {
	if len(args) > 0 || flagTermsFile != "" {
		return collectFingerprints(args)
	}
	entries, err := gdpr.ReadLog(auditPath(settings))
	if err != nil {
		return nil, err
	}
	return gdpr.ErasedFingerprints(entries, gdpr.Filter{Case: flagCase}), nil
}

// recordReappearances logs the keys that came back. Successful verifications
// are deliberately not logged: a periodic check would otherwise bury the
// erasures themselves under its own noise.
func recordReappearances(settings *server.Settings, results []verifyResult) error {
	var regressions []verifyResult
	for _, result := range results {
		if result.Present {
			regressions = append(regressions, result)
		}
	}
	if len(regressions) == 0 {
		return nil
	}
	auditLog, err := gdpr.OpenLog(auditPath(settings))
	if err != nil {
		return err
	}
	defer auditLog.Close()
	for _, regression := range regressions {
		err := auditLog.Append(gdpr.Entry{
			Action:      gdpr.ActionVerify,
			Result:      gdpr.ResultPresent,
			Case:        flagCase,
			Operator:    flagOperator,
			Fingerprint: regression.Fingerprint,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
