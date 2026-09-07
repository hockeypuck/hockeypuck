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
	exportDir     string
	exportUserIDs bool
)

var exportCommand = &command{
	name:    "export",
	args:    "TERM [TERM ...]",
	summary: "write matching keys out as evidence before erasing them",
	description: `
Write the keys matching TERM to ASCII-armored files, one per key, before they are
erased. Keeping a copy makes the erasure reversible if the request turns out to
have been mistaken or fraudulent, and evidences what was actually removed.

Note that the exported files contain the very personal data the request asks you
to erase. Store them accordingly, and delete them once your appeal window closes.

Terms are classified exactly as for "search". This command only reads from the
database; it takes no locks and is safe to run against a live server.`,
	setup: func(fs *flag.FlagSet) {
		fs.StringVar(&exportDir, "o", ".", `output directory ("-" writes all keys to stdout)`)
		fs.BoolVar(&exportUserIDs, "record-uids", false, "record user IDs verbatim in the audit trail, not just their digest")
		addTermsFileFlag(fs)
		addCaseFlags(fs)
		addRequestFlags(fs)
		addAuditFlag(fs)
	},
	run: runExport,
}

func runExport(settings *server.Settings, args []string) error {
	targets, err := collectTargets(args)
	if err != nil {
		return err
	}
	s, err := openSession(settings, false)
	if err != nil {
		return err
	}
	defer s.Close()

	records, err := s.resolve(targets)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "no keys matched; nothing to export")
		return nil
	}

	auditLog, err := gdpr.OpenLog(auditPath(settings))
	if err != nil {
		return err
	}
	defer auditLog.Close()

	if exportDir == "-" {
		return exportToStdout(settings, auditLog, records)
	}
	if err := os.MkdirAll(exportDir, 0o750); err != nil {
		return errors.Wrapf(err, "cannot create output directory %q", exportDir)
	}

	var exported int
	var firstErr error
	for _, record := range records {
		path := filepath.Join(exportDir, record.Fingerprint+".asc")
		if err := exportOne(settings, path, record); err != nil {
			log.Errorf("could not export 0x%s: %v", record.Fingerprint, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		exported++
		entry := newEntry(gdpr.ActionExport, record, exportUserIDs)
		entry.Result = gdpr.ResultExported
		entry.Evidence = path
		if err := auditLog.Append(entry); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "exported %s to %s\n", plural(exported, "key", "keys"), exportDir)
	return firstErr
}

func exportOne(settings *server.Settings, path string, record *storage.Record) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.Wrapf(err, "cannot create %q", path)
	}
	defer f.Close()
	if err := writeArmoredKey(f, settings, record); err != nil {
		return err
	}
	return errors.WithStack(f.Close())
}

func exportToStdout(settings *server.Settings, auditLog *gdpr.Log, records []*storage.Record) error {
	for _, record := range records {
		if err := writeArmoredKey(os.Stdout, settings, record); err != nil {
			return err
		}
		entry := newEntry(gdpr.ActionExport, record, exportUserIDs)
		entry.Result = gdpr.ResultExported
		entry.Evidence = "stdout"
		if err := auditLog.Append(entry); err != nil {
			return err
		}
	}
	return nil
}
