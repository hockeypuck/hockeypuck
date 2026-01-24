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
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"

	pksstorage "hockeypuck/hkp/pks/storage"
)

//
// pks.Storage implementation
//

// Initialise a new PKS peer record if it does not already exist.
func (st *storage) PKSInit(addr string, lastSync time.Time) error {
	stmt, err := st.Prepare("INSERT INTO pks_status ( addr, last_sync, last_error ) VALUES ( $1, $2, $3 ) ON CONFLICT DO NOTHING")
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = stmt.Exec(addr, lastSync, sql.NullString{Valid: false})
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// Return the status of all PKS peers.
func (st *storage) PKSAll() ([]*pksstorage.Status, error) {
	rows, err := st.Query("SELECT addr, last_sync, last_error FROM pks_status")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*pksstorage.Status
	defer rows.Close()
	for rows.Next() {
		var addr string
		var lastErrorString sql.NullString
		var lastError error
		var lastSync time.Time
		err = rows.Scan(&addr, &lastSync, &lastErrorString)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		if lastErrorString.Valid {
			lastError = errors.New(lastErrorString.String)
		}
		result = append(result, &pksstorage.Status{
			Addr:      addr,
			LastSync:  lastSync,
			LastError: lastError,
		})
	}
	return result, nil
}

// Get one PKS peer.
func (st *storage) PKSGet(addr string) (*pksstorage.Status, error) {
	stmt, err := st.Prepare("SELECT addr, last_sync, last_error FROM pks_status WHERE addr = $1")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	rows, err := stmt.Query(addr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result *pksstorage.Status
	defer rows.Close()
	// Only process the first result; the storage SHOULD NOT contain duplicate records
	if rows.Next() {
		var addr string
		var lastErrorString sql.NullString
		var lastError error
		var lastSync time.Time
		err = rows.Scan(&addr, &lastSync, &lastErrorString)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		if lastErrorString.Valid {
			lastError = errors.New(lastErrorString.String)
		}
		result = &pksstorage.Status{
			Addr:      addr,
			LastSync:  lastSync,
			LastError: lastError,
		}
	}
	return result, nil
}

// Update the status of one PKS peer.
func (st *storage) PKSUpdate(status *pksstorage.Status) error {
	stmt, err := st.Prepare("UPDATE pks_status SET last_sync = $2, last_error = $3 WHERE addr = $1")
	if err != nil {
		return errors.WithStack(err)
	}
	lastErrorString := sql.NullString{Valid: false}
	if status.LastError != nil {
		lastErrorString = sql.NullString{String: status.LastError.Error(), Valid: true}
	}
	_, err = stmt.Exec(status.Addr, status.LastSync, lastErrorString)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// Remove a PKS peer.
func (st *storage) PKSRemove(addr string) error {
	stmt, err := st.Prepare("DELETE FROM pks_status WHERE addr = $1")
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = stmt.Exec(&addr)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
