/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2026 Casey Marshall and the Hockeypuck Contributors

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

	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
)

var listCommand = &command{
	name:    "list",
	args:    "",
	summary: "show which origins this server honours blocks from",
	description: `
Show the blocklist configuration this server is running with: the origin it
stamps on the blocks it issues, and the origins whose blocks it honours.

A block is only honoured if its origin appears here and its signature verifies
against one of that origin's keys, so an empty trust list means every tombstone
offered to this server is refused. That is the default, and it is the safe way
round for a mechanism whose effect is to remove keys.

This reads configuration only; it does not touch the database.`,
	run: runList,
}

func runList(settings *server.Settings, args []string) error {
	if len(args) > 0 {
		return usagef("unexpected arguments: %s", strings.Join(args, " "))
	}
	blocklist := settings.OpenPGP.Blocklist

	if blocklist.Origin == "" {
		fmt.Fprintln(os.Stdout, "issuing origin:  (none configured - this server cannot issue blocks)")
	} else {
		fmt.Fprintf(os.Stdout, "issuing origin:  %s\n", blocklist.Origin)
	}

	if len(blocklist.TrustedOrigins) == 0 {
		fmt.Fprintln(os.Stdout, "trusted origins: (none - every block offered to this server is refused)")
		return nil
	}
	fmt.Fprintln(os.Stdout, "trusted origins:")
	for origin, fingerprints := range blocklist.TrustedOrigins {
		fmt.Fprintf(os.Stdout, "  %s\n", origin)
		for _, fp := range fingerprints {
			// Print what the policy will actually match on, folded the same way
			// it folds the configuration.
			fmt.Fprintf(os.Stdout, "      0x%s\n", openpgp.NormalizeFingerprint(fp))
		}
	}
	return nil
}

var showVerify bool

var showCommand = &command{
	name:    "show",
	args:    "FINGERPRINT [FINGERPRINT ...]",
	summary: "report whether a fingerprint is blocked, and on whose authority",
	description: `
Report the block held for each fingerprint: which origin issued it, the reason
code it carries if any, and how many signatures vouch for it.

With -verify, each block's signature is checked against the keys currently
trusted for its origin. That answers a different question from whether the block
was accepted when it arrived: trust can be withdrawn, and a signing key can be
rotated or removed from the keyserver, leaving blocks in place that would no
longer be admitted today.

This command only reads; it takes no locks and is safe to run against a live
server.`,
	setup: func(fs *flag.FlagSet) {
		fs.BoolVar(&showVerify, "verify", false, "re-check each block against the origins trusted now")
	},
	run: runShow,
}

func runShow(settings *server.Settings, args []string) error {
	fingerprints, err := normaliseFingerprints(args)
	if err != nil {
		return err
	}
	s, err := openSession(settings, false)
	if err != nil {
		return err
	}
	defer s.Close()

	records, err := s.storage.FetchRecordsByFp(fingerprints, storage.IncludeTombstones)
	if err != nil {
		return err
	}
	found := map[string]*storage.Record{}
	for _, record := range records {
		found[record.Fingerprint] = record
	}

	var unverified int
	for _, fp := range fingerprints {
		record, ok := found[fp]
		switch {
		case !ok:
			fmt.Fprintf(os.Stdout, "0x%s  not present\n", fp)
			continue
		case !openpgp.IsTombstone(record.PrimaryKey):
			fmt.Fprintf(os.Stdout, "0x%s  not blocked (key material present)\n", fp)
			continue
		}
		line := describeTombstone(record)
		if showVerify {
			if err := s.verifyBlock(record); err != nil {
				line += "  UNTRUSTED NOW"
				unverified++
			} else {
				line += "  trusted"
			}
		}
		fmt.Fprintln(os.Stdout, line)
	}
	if unverified > 0 {
		return findingf("%s would not be admitted by the trust configuration in force now",
			plural(unverified, "block", "blocks"))
	}
	return nil
}

// verifyBlock re-checks a stored tombstone against the origins trusted now.
func (s *session) verifyBlock(record *storage.Record) error {
	ts, sigs, err := openpgp.TombstoneOf(record.PrimaryKey)
	if err != nil {
		return err
	}
	fingerprints := s.policy.TrustedBlocklistKeys(ts.Origin)
	if len(fingerprints) == 0 {
		return fmt.Errorf("no keys trusted for origin %q", ts.Origin)
	}
	trustedRecords, err := s.storage.FetchRecordsByFp(fingerprints)
	if err != nil {
		return err
	}
	var trusted []*openpgp.PrimaryKey
	for _, r := range trustedRecords {
		if r.PrimaryKey != nil {
			trusted = append(trusted, r.PrimaryKey)
		}
	}
	_, err = openpgp.VerifyTombstone(*ts, sigs, trusted)
	return err
}
