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

package pghkp

import (
	"database/sql"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"

	hkpstorage "hockeypuck/hkp/storage"

	log "github.com/sirupsen/logrus"
)

//
// Notifier implementation
//

func (st *storage) Subscribe(f func(hkpstorage.KeyChange) error) {
	st.mu.Lock()
	st.listeners = append(st.listeners, f)
	st.mu.Unlock()
}

func (st *storage) Notify(change hkpstorage.KeyChange) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	log.Debugf("%v", change)
	for _, f := range st.listeners {
		err := f(change)
		if err != nil {
			log.Errorf("notify failed: %v", err)
		}
	}
	return nil
}

// BulkNotify calls Notify for an arbitrary number of database records.
// It takes one or two strings containing SQL queries, each of which SHOULD
// return one value. The first query returns the md5 digests that were added,
// and the second the md5s that were removed.
//
// TODO: why are we calling Notify one md5 at a time, when it is inherently bulk-y?
func (st *storage) BulkNotify(sqlStrs ...string) error {
	if len(sqlStrs) == 0 {
		return nil
	}
	rows, err := st.Query(sqlStrs[0])
	if err != nil {
		return errors.WithStack(err)
	}

	defer rows.Close()
	for rows.Next() {
		var md5 string
		err := rows.Scan(&md5)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil
			} else {
				return errors.WithStack(err)
			}
		}
		st.Notify(hkpstorage.KeyAdded{Digest: md5})
	}
	err = rows.Err()
	if err != nil {
		return errors.WithStack(err)
	}

	if len(sqlStrs) == 1 {
		return nil
	}
	rows.Close()
	rows, err = st.Query(sqlStrs[1])
	if err != nil {
		return errors.WithStack(err)
	}

	defer rows.Close()
	for rows.Next() {
		var md5 string
		err := rows.Scan(&md5)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil
			} else {
				return errors.WithStack(err)
			}
		}
		st.Notify(hkpstorage.KeyRemoved{Digest: md5})
	}
	err = rows.Err()
	return errors.WithStack(err)
}

func (st *storage) RenotifyAll() error {
	return st.BulkNotify("SELECT md5 FROM keys")
}
