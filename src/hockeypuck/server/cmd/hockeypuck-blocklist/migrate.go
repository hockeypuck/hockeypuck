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

	log "github.com/sirupsen/logrus"

	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
)

var (
	migrateSignKey string
	migrateReason  string
	migrateOrigin  string
	migrateDryRun  bool
	migrateOut     string
	migrateServer  string
)

var migrateCommand = &command{
	name:    "migrate",
	args:    "",
	summary: "turn the configured blacklist array into signed blocks",
	description: `
Issue a signed tombstone for every fingerprint in the blacklist array of
hockeypuck.conf, so the list can move out of the configuration file and into the
database.

The two are not equivalent, which is the reason for moving. The blacklist array
is only consulted while reading key material, so it stops a blocked key being
taken in but does nothing about a copy already stored, and nothing about what
this server hands to its partners. A tombstone occupies the key's place, so the
key is gone from lookups and from what is offered to peers, and the block travels
to partners that trust the origin.

Fingerprints that already hold a block are left alone, so this is safe to re-run
and safe to interrupt.

Nothing is removed from hockeypuck.conf: check the result with "show", then
delete the blacklist array by hand. Leaving it in place is harmless, only
redundant.`,
	setup: func(fs *flag.FlagSet) {
		fs.StringVar(&migrateSignKey, "sign-key", "", "private key to sign the blocks with")
		fs.StringVar(&migrateReason, "reason", "", "short reason code, published to peers (optional)")
		fs.StringVar(&migrateOrigin, "origin", "", "override the origin from the configuration")
		fs.BoolVar(&migrateDryRun, "dry-run", false, "report what would be migrated, change nothing")
		fs.StringVar(&migrateOut, "o", "", `write the tombstones to a file instead of storing them ("-" for stdout)`)
		fs.StringVar(&migrateServer, "server", "", "submit to a running server over HKP instead of writing to the database directly")
	},
	run: runMigrate,
}

func runMigrate(settings *server.Settings, args []string) error {
	if len(args) > 0 {
		return usagef("migrate takes no arguments; it reads the blacklist from the configuration")
	}
	if migrateOut != "" && migrateServer != "" {
		return usagef("-o and -server are alternatives; pick one")
	}

	configured := settings.OpenPGP.Blacklist
	if len(configured) == 0 {
		fmt.Fprintln(os.Stderr, "no blacklist array in the configuration; nothing to migrate")
		return nil
	}
	fingerprints, err := normaliseFingerprints(configured)
	if err != nil {
		return err
	}

	origin := migrateOrigin
	if origin == "" {
		origin = settings.OpenPGP.Blocklist.Origin
	}
	if origin == "" {
		return usagef("no blocklist origin configured; set hockeypuck.openpgp.blocklist.origin or pass -origin")
	}

	// Skip anything already blocked, so a re-run after an interruption picks up
	// where it left off rather than reissuing every block.
	pending, err := unblockedOf(settings, fingerprints)
	if err != nil {
		return err
	}
	alreadyBlocked := len(fingerprints) - len(pending)
	if alreadyBlocked > 0 {
		fmt.Fprintf(os.Stderr, "%s already blocked, skipping\n",
			plural(alreadyBlocked, "fingerprint", "fingerprints"))
	}
	if len(pending) == 0 {
		fmt.Fprintln(os.Stderr, "every configured fingerprint is already blocked; nothing to do")
		return nil
	}

	signer, err := readSigningKey(migrateSignKey)
	if err != nil {
		return err
	}

	tombstones := make([]*openpgp.PrimaryKey, 0, len(pending))
	for _, fp := range pending {
		ts := openpgp.Tombstone{Fingerprint: fp, Origin: origin, Reason: migrateReason}
		sig, err := openpgp.SignTombstone(ts, signer)
		if err != nil {
			return err
		}
		tombstone, err := openpgp.NewTombstone(ts, sig)
		if err != nil {
			return err
		}
		tombstones = append(tombstones, tombstone)
	}

	if migrateDryRun {
		for _, fp := range pending {
			fmt.Fprintf(os.Stderr, "would block 0x%s\n", fp)
		}
		fmt.Fprintf(os.Stderr, "dry run: %s would be migrated, nothing was changed\n",
			plural(len(pending), "fingerprint", "fingerprints"))
		return nil
	}
	if migrateOut != "" {
		return writeTombstones(settings, migrateOut, tombstones)
	}
	if migrateServer != "" {
		return submitTombstones(migrateServer, settings, tombstones)
	}

	s, err := openSession(settings, true)
	if err != nil {
		return err
	}
	defer s.Close()

	var stored int
	for _, tombstone := range tombstones {
		if _, err := s.storage.Replace(tombstone); err != nil {
			log.Errorf("could not block 0x%s: %v", tombstone.Fingerprint, err)
			continue
		}
		stored++
	}
	fmt.Fprintf(os.Stderr, "migrated %s\n", plural(stored, "fingerprint", "fingerprints"))
	fmt.Fprintln(os.Stderr, "check with \"hockeypuck-blocklist show\", then remove the blacklist array from the configuration")
	if stored < len(tombstones) {
		return findingf("%d of %d could not be migrated", len(tombstones)-stored, len(tombstones))
	}
	return nil
}

// unblockedOf returns the fingerprints that do not already hold a block.
func unblockedOf(settings *server.Settings, fingerprints []string) ([]string, error) {
	s, err := openSession(settings, false)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	records, err := s.storage.FetchRecordsByFp(fingerprints, storage.IncludeTombstones)
	if err != nil {
		return nil, err
	}
	blocked := map[string]bool{}
	for _, record := range records {
		if openpgp.IsTombstone(record.PrimaryKey) {
			blocked[record.Fingerprint] = true
		}
	}
	var pending []string
	for _, fp := range fingerprints {
		if !blocked[fp] {
			pending = append(pending, fp)
		}
	}
	return pending, nil
}
