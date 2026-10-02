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

	"hockeypuck/gdpr"
	"hockeypuck/server"
)

var (
	blacklistCheck bool
	blacklistOut   string
)

var blacklistCommand = &command{
	name:    "blacklist",
	args:    "[FINGERPRINT ...]",
	summary: "keep erased key material from returning via reconciliation",
	description: `
Print the blacklist configuration for erased key material. With no arguments the
fingerprints are taken from the audit trail, narrowed by -case if given.

Erasing a key from the database does not keep it erased: reconciliation partners
still hold it and re-offer it, so a blacklisted fingerprint is what actually makes
the erasure stick. Merge the printed fragment into the [hockeypuck.openpgp]
section of hockeypuck.conf and reload hockeypuck.

With -check, nothing is printed except the fingerprints the loaded configuration
fails to cover, and the command exits non-zero if there are any, so it can be run
from cron.`,
	setup: func(fs *flag.FlagSet) {
		fs.BoolVar(&blacklistCheck, "check", false, "report only the erased fingerprints the configuration fails to blacklist")
		fs.StringVar(&blacklistOut, "out", "", "merge the fingerprints into this blacklist fragment instead of printing them")
		addTermsFileFlag(fs)
		addCaseFlags(fs)
		addAuditFlag(fs)
	},
	run: runBlacklist,
}

func runBlacklist(settings *server.Settings, args []string) error {
	fps, err := fingerprintsToBlacklist(settings, args)
	if err != nil {
		return err
	}
	if len(fps) == 0 {
		fmt.Fprintln(os.Stderr, "no erased fingerprints recorded")
		return nil
	}

	missing := gdpr.MissingFromBlacklist(settings.OpenPGP.Blacklist, fps)

	if blacklistCheck {
		for _, fp := range missing {
			fmt.Fprintf(os.Stdout, "0x%s\n", fp)
		}
		if len(missing) > 0 {
			return findingf("%s erased but not blacklisted; the key material will return "+
				"via reconciliation until hockeypuck.conf covers it",
				plural(len(missing), "fingerprint is", "fingerprints are"))
		}
		fmt.Fprintf(os.Stderr, "all %s blacklisted\n",
			plural(len(fps), "erased fingerprint is", "erased fingerprints are"))
		return nil
	}

	if blacklistOut != "" {
		added, all, err := gdpr.MergeBlacklistFile(blacklistOut, fps)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "added %s to %s (%d total)\n",
			plural(len(added), "fingerprint", "fingerprints"), blacklistOut, len(all))
		return nil
	}

	// Print the configuration's existing entries alongside the erased ones, so
	// that the fragment can replace the current blacklist wholesale.
	fmt.Fprint(os.Stdout, gdpr.BlacklistTOML(append(append([]string(nil), settings.OpenPGP.Blacklist...), fps...)))
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s not yet blacklisted; merge the above into hockeypuck.conf and reload hockeypuck\n",
			plural(len(missing), "fingerprint is", "fingerprints are"))
	}
	return nil
}

func fingerprintsToBlacklist(settings *server.Settings, args []string) ([]string, error) {
	if len(args) > 0 || flagTermsFile != "" {
		return collectFingerprints(args)
	}
	entries, err := gdpr.ReadLog(auditPath(settings))
	if err != nil {
		return nil, err
	}
	return gdpr.ErasedFingerprints(entries, gdpr.Filter{Case: flagCase}), nil
}
