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
)

//
// Deleter implementation
//

func (st *storage) Delete(fp string) (_ string, retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			retErr = tx.Commit()
		}
	}()
	md5, err := st.deleteTx(tx, fp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	st.Notify(hkpstorage.KeyRemoved{ID: fp, Digest: md5})
	return md5, nil
}

// deleteTx does not handle cleanup; the caller MUST defer commit/rollback
func (st *storage) deleteTx(tx *sql.Tx, fp string) (string, error) {
	_, err := tx.Exec("DELETE FROM subkeys WHERE rfingerprint = reverse($1)", fp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	_, err = tx.Exec("DELETE FROM userids WHERE rfingerprint = reverse($1)", fp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var md5 string
	err = tx.QueryRow("DELETE FROM keys WHERE rfingerprint = reverse($1) RETURNING md5", fp).Scan(&md5)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(hkpstorage.ErrKeyNotFound)
		}
		return "", errors.WithStack(err)
	}
	return md5, nil
}
