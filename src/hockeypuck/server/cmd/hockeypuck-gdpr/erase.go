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
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"hockeypuck/gdpr"
	"hockeypuck/hkp/storage"
	"hockeypuck/server"
)

var (
	eraseDryRun       bool
	eraseYes          bool
	eraseEvidenceDir  string
	eraseNoPtree      bool
	eraseUserIDs      bool
	eraseBlacklistOut string
)

var eraseCommand = &command{
	name:    "erase",
	aliases: []string{"delete", "forget"},
	args:    "TERM [TERM ...]",
	summary: "erase matching keys from the database and prefix tree",
	description: `
Erase the keys matching TERM from this keyserver. Terms are classified exactly as
for "search", and the keys that would be erased are always listed before anything
is removed.

The erasure goes through the server's own storage layer, so the reconciliation
prefix tree is updated along with the database and this node stops offering the
key material to its partners. That requires exclusive access to the prefix tree,
which a running hockeypuck holds: stop the server first. A -dry-run needs no such
access and can be run at any time.

Passing -no-ptree erases from the database alone, which lets an urgent request be
actioned against a live server. The prefix tree then still advertises the erased
key material, and has to be removed and rebuilt with hockeypuck-pbuild before the
server is restarted, because hockeypuck-pbuild only inserts and cannot retract a
digest on its own.

Erasing a key does not keep it erased. Partners still hold it and will re-offer it
within hours unless its fingerprint is blacklisted, so this command reports any
erased fingerprint that the loaded configuration does not blacklist, and
-blacklist-out maintains a configuration fragment you can include and reload.`,
	setup: func(fs *flag.FlagSet) {
		fs.BoolVar(&eraseDryRun, "dry-run", false, "report what would be erased, change nothing")
		fs.BoolVar(&eraseYes, "yes", false, "do not prompt for confirmation")
		fs.StringVar(&eraseEvidenceDir, "evidence", "", "directory to write an armored copy of each key to before erasing it")
		fs.BoolVar(&eraseNoPtree, "no-ptree", false, "skip the prefix tree update (it must then be removed and rebuilt with hockeypuck-pbuild)")
		fs.BoolVar(&eraseUserIDs, "record-uids", false, "record user IDs verbatim in the audit trail, not just their digest")
		fs.StringVar(&eraseBlacklistOut, "blacklist-out", "", "blacklist fragment to add the erased fingerprints to")
		addTermsFileFlag(fs)
		addCaseFlags(fs)
		addRequestFlags(fs)
		addAuditFlag(fs)
	},
	run: runErase,
}

func runErase(settings *server.Settings, args []string) error {
	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	// A dry run must not take the prefix tree lock, so that it can be used to
	// prepare a case while the server is still serving.
	withPtree := !eraseDryRun && !eraseNoPtree
	s, err := openSession(settings, withPtree)
	if err != nil {
		return err
	}
	defer s.Close()

	records, err := s.resolve(targets)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "no keys matched; nothing to erase")
		return nil
	}

	fmt.Fprintf(os.Stderr, "The following %s will be erased:\n\n", plural(len(records), "key", "keys"))
	for _, record := range records {
		describeRecord(os.Stderr, record)
	}
	fmt.Fprintln(os.Stderr)

	if eraseDryRun {
		fmt.Fprintf(os.Stderr, "dry run: %s would be erased, nothing was changed\n",
			plural(len(records), "key", "keys"))
		reportBlacklist(settings, recordFingerprints(records), true)
		return nil
	}
	if !eraseYes {
		if err := confirm(fmt.Sprintf("Erase %s? Type 'yes' to continue: ",
			plural(len(records), "key", "keys"))); err != nil {
			return err
		}
	}

	auditLog, err := gdpr.OpenLog(auditPath(settings))
	if err != nil {
		return err
	}
	defer auditLog.Close()
	log.Infof("recording this erasure in %s", auditLog.Path())

	if eraseEvidenceDir != "" {
		if err := os.MkdirAll(eraseEvidenceDir, 0o750); err != nil {
			return errors.Wrapf(err, "cannot create evidence directory %q", eraseEvidenceDir)
		}
	}

	var erased []string
	var failed, notFound int
	for _, record := range records {
		entry := newEntry(gdpr.ActionErase, record, eraseUserIDs)

		// Take the evidence copy first: once the key is erased it cannot be
		// recovered from this server.
		if eraseEvidenceDir != "" {
			path := filepath.Join(eraseEvidenceDir, record.Fingerprint+".asc")
			if err := exportOne(settings, path, record); err != nil {
				entry.Result = gdpr.ResultFailed
				entry.Error = err.Error()
				if appendErr := auditLog.Append(entry); appendErr != nil {
					return appendErr
				}
				log.Errorf("not erasing 0x%s: could not write evidence copy: %v", record.Fingerprint, err)
				failed++
				continue
			}
			entry.Evidence = path
		}

		_, err := s.storage.Delete(record.Fingerprint)
		switch {
		case err == nil:
			entry.Result = gdpr.ResultErased
			erased = append(erased, record.Fingerprint)
			log.Infof("erased 0x%s", record.Fingerprint)
		case storage.IsNotFound(err):
			entry.Result = gdpr.ResultNotFound
			notFound++
			log.Warnf("0x%s was already gone", record.Fingerprint)
		default:
			entry.Result = gdpr.ResultFailed
			entry.Error = err.Error()
			failed++
			log.Errorf("could not erase 0x%s: %v", record.Fingerprint, err)
		}
		if err := auditLog.Append(entry); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "\nerased %s", plural(len(erased), "key", "keys"))
	if notFound > 0 {
		fmt.Fprintf(os.Stderr, ", %d already absent", notFound)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, ", %d failed", failed)
	}
	fmt.Fprintf(os.Stderr, "; recorded in %s\n", auditLog.Path())

	if len(erased) > 0 {
		if eraseNoPtree {
			log.Warnf("the prefix tree at %q still advertises the erased key material; "+
				"%s before restarting hockeypuck",
				settings.Conflux.Recon.LevelDB.Path, ptreeRepair)
		}
		reportBlacklist(settings, erased, false)
	}

	if failed > 0 {
		return findingf("%d of %d keys could not be erased", failed, len(records))
	}
	return nil
}

func recordFingerprints(records []*storage.Record) []string {
	fps := make([]string, len(records))
	for i, record := range records {
		fps[i] = record.Fingerprint
	}
	return fps
}

// reportBlacklist warns about erased fingerprints that the running
// configuration does not blacklist, and maintains the -blacklist-out fragment.
// Without this step the erasure is undone by the next reconciliation round.
func reportBlacklist(settings *server.Settings, fps []string, dryRun bool) {
	missing := gdpr.MissingFromBlacklist(settings.OpenPGP.Blacklist, fps)
	if len(missing) == 0 {
		fmt.Fprintln(os.Stderr, "all of these fingerprints are already blacklisted in the loaded configuration")
		return
	}

	if eraseBlacklistOut != "" && !dryRun {
		added, all, err := gdpr.MergeBlacklistFile(eraseBlacklistOut, missing)
		if err != nil {
			log.Errorf("could not update blacklist %q: %v", eraseBlacklistOut, err)
		} else {
			fmt.Fprintf(os.Stderr, "\nadded %s to %s (%d total); merge it into hockeypuck.conf and reload hockeypuck\n",
				plural(len(added), "fingerprint", "fingerprints"), eraseBlacklistOut, len(all))
			return
		}
	}

	fmt.Fprintf(os.Stderr, `
WARNING: %s not blacklisted in the loaded configuration.
Reconciliation partners still hold this key material and will re-offer it,
usually within hours. Add the following to hockeypuck.conf and reload:

%s`, plural(len(missing), "fingerprint is", "fingerprints are"),
		gdpr.BlacklistTOML(append(append([]string(nil), settings.OpenPGP.Blacklist...), missing...)))
}
