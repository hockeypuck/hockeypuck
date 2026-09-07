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

	"hockeypuck/server"
)

var searchCommand = &command{
	name:    "search",
	aliases: []string{"find"},
	args:    "TERM [TERM ...]",
	summary: "find the keys a data subject is asking about",
	description: `
Find the keys named by an erasure request. Each TERM is classified automatically:
a hexadecimal key ID or fingerprint (with or without "0x", spaces or colons) is
looked up as an identifier, an address or "Name <address>" form is looked up as a
user ID identity, and anything else is a free text key word search. Prefix a term
with "fp:", "keyid:", "email:" or "keyword:" to override the classification.

Key IDs and subkey fingerprints resolve to the primary key that owns them, since
that is the unit that can be erased. This command only reads; it takes no locks
and is safe to run against a live server.`,
	setup: func(fs *flag.FlagSet) {
		addTermsFileFlag(fs)
		addJSONFlag(fs)
	},
	run: runSearch,
}

func runSearch(settings *server.Settings, args []string) error {
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

	if flagJSON {
		out := make([]recordJSON, 0, len(records))
		for _, record := range records {
			out = append(out, newRecordJSON(record))
		}
		return writeJSON(os.Stdout, out)
	}

	for _, record := range records {
		describeRecord(os.Stdout, record)
	}
	fmt.Fprintf(os.Stderr, "%s matched\n", plural(len(records), "key", "keys"))
	return nil
}
