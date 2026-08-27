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
	blockSignKey string
	blockReason  string
	blockOrigin  string
	blockDryRun  bool
	blockOut     string
	blockServer  string
)

var blockCommand = &command{
	name:    "block",
	args:    "FINGERPRINT [FINGERPRINT ...]",
	summary: "refuse key material for a fingerprint, and say so to peers",
	description: `
Issue a signed tombstone for each fingerprint: a certificate that takes the
blocked key's place, so that any copy of that key offered to this server is
refused, and the block is visible to reconciliation partners that trust this
origin.

The tombstone is signed with -sign-key, which binds this node's configured
origin to the block. Peers that do not trust that origin ignore it; this server
will refuse its own tombstone too, unless the configuration trusts the signing
key, so a block that is accepted here is one a peer could also accept.

Blocking replaces key material rather than deleting it, so the fingerprint's row
stays occupied and the key cannot simply be re-offered. Existing key material for
the fingerprint is replaced.

Writing to the database directly needs the reconciliation prefix tree, which a
running server holds, so it wants the server stopped. With -server the block is
submitted over HKP instead and the running server stores it, which needs no
downtime. With -o it is written to a file for submission elsewhere.`,
	setup: func(fs *flag.FlagSet) {
		fs.StringVar(&blockSignKey, "sign-key", "", "private key to sign the block with (required)")
		fs.StringVar(&blockReason, "reason", "", "short reason code, published to peers (optional)")
		fs.StringVar(&blockOrigin, "origin", "", "override the origin from the configuration")
		fs.BoolVar(&blockDryRun, "dry-run", false, "report what would be blocked, change nothing")
		fs.StringVar(&blockOut, "o", "", `write the tombstones to a file instead of storing them ("-" for stdout)`)
		fs.StringVar(&blockServer, "server", "", "submit to a running server over HKP instead of writing to the database directly")
	},
	run: runBlock,
}

func runBlock(settings *server.Settings, args []string) error {
	fingerprints, err := normaliseFingerprints(args)
	if err != nil {
		return err
	}

	origin := blockOrigin
	if origin == "" {
		origin = settings.OpenPGP.Blocklist.Origin
	}
	if origin == "" {
		return usagef("no blocklist origin configured; set hockeypuck.openpgp.blocklist.origin or pass -origin")
	}

	signer, err := readSigningKey(blockSignKey)
	if err != nil {
		return err
	}

	tombstones := make([]*openpgp.PrimaryKey, 0, len(fingerprints))
	for _, fp := range fingerprints {
		ts := openpgp.Tombstone{Fingerprint: fp, Origin: origin, Reason: blockReason}
		sig, err := openpgp.SignTombstone(ts, signer)
		if err != nil {
			return err
		}
		tombstone, err := openpgp.NewTombstone(ts, sig)
		if err != nil {
			return err
		}
		tombstones = append(tombstones, tombstone)
		fmt.Fprintf(os.Stderr, "%s\n", ts)
	}

	if blockOut != "" && blockServer != "" {
		return usagef("-o and -server are alternatives; pick one")
	}
	if blockDryRun {
		fmt.Fprintf(os.Stderr, "dry run: %s would be blocked, nothing was changed\n",
			plural(len(tombstones), "key", "keys"))
		return nil
	}
	if blockOut != "" {
		return writeTombstones(settings, blockOut, tombstones)
	}
	if blockServer != "" {
		return submitTombstones(blockServer, settings, tombstones)
	}
	s, err := openSession(settings, true)
	if err != nil {
		return err
	}
	defer s.Close()

	var stored int
	for _, tombstone := range tombstones {
		// Replace rather than Upsert: the fingerprint may already hold key
		// material, and the tombstone is meant to take its place.
		change, err := s.storage.Replace(tombstone)
		if err != nil {
			log.Errorf("could not block 0x%s: %v", tombstone.Fingerprint, err)
			continue
		}
		stored++
		log.Debugf("blocked 0x%s: %v", tombstone.Fingerprint, change)
	}
	fmt.Fprintf(os.Stderr, "blocked %s\n", plural(stored, "key", "keys"))
	if stored < len(tombstones) {
		return findingf("%d of %d blocks could not be stored", len(tombstones)-stored, len(tombstones))
	}
	return nil
}

func writeTombstones(settings *server.Settings, path string, tombstones []*openpgp.PrimaryKey) error {
	out := os.Stdout
	if path != "-" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return usagef("cannot write %q: %v", path, err)
		}
		defer f.Close()
		out = f
	}
	for _, tombstone := range tombstones {
		if err := openpgp.WritePackets(out, tombstone); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s to %s\n", plural(len(tombstones), "tombstone", "tombstones"), path)
	return nil
}

var unblockDryRun bool

var unblockCommand = &command{
	name:    "unblock",
	args:    "FINGERPRINT [FINGERPRINT ...]",
	summary: "withdraw a block, allowing the key to return",
	description: `
Remove the tombstone for each fingerprint, so this server will accept that key
material again.

Withdrawing a block does not restore the key: it only stops refusing it. The key
returns when a reconciliation partner next offers it, or when someone submits it.

Note that peers which accepted the block still hold the tombstone. Nothing in the
protocol retracts it for them, so a block shared with peers has to be withdrawn
on each of them.`,
	setup: func(fs *flag.FlagSet) {
		fs.BoolVar(&unblockDryRun, "dry-run", false, "report what would be unblocked, change nothing")
	},
	run: runUnblock,
}

func runUnblock(settings *server.Settings, args []string) error {
	fingerprints, err := normaliseFingerprints(args)
	if err != nil {
		return err
	}
	s, err := openSession(settings, !unblockDryRun)
	if err != nil {
		return err
	}
	defer s.Close()

	records, err := s.storage.FetchRecordsByFp(fingerprints, storage.IncludeTombstones)
	if err != nil {
		return err
	}
	var blocked []*storage.Record
	for _, record := range records {
		if openpgp.IsTombstone(record.PrimaryKey) {
			blocked = append(blocked, record)
		}
	}
	if len(blocked) == 0 {
		fmt.Fprintln(os.Stderr, "no blocks found for those fingerprints")
		return nil
	}
	for _, record := range blocked {
		fmt.Fprintf(os.Stderr, "%s\n", describeTombstone(record))
	}
	if unblockDryRun {
		fmt.Fprintf(os.Stderr, "dry run: %s would be unblocked, nothing was changed\n",
			plural(len(blocked), "key", "keys"))
		return nil
	}

	var removed int
	for _, record := range blocked {
		if _, err := s.storage.Delete(record.Fingerprint); err != nil {
			log.Errorf("could not unblock 0x%s: %v", record.Fingerprint, err)
			continue
		}
		removed++
	}
	fmt.Fprintf(os.Stderr, "unblocked %s\n", plural(removed, "key", "keys"))
	if removed < len(blocked) {
		return findingf("%d of %d blocks could not be withdrawn", len(blocked)-removed, len(blocked))
	}
	return nil
}
