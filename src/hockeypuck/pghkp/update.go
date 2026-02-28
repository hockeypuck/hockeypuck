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
	"encoding/json"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"
)

//
// Updater implementation
//

func (st *storage) upsertKeyOnInsert(pubkey *openpgp.PrimaryKey) (kc hkpstorage.KeyChange, err error) {
	var lastRecord *hkpstorage.Record
	// Don't use AutoPreen, as this can cause double-updates. We explicitly call preen() below.
	lastRecords, err := st.FetchRecordsByFp([]string{pubkey.Fingerprint})
	if err == nil {
		// match primary fingerprint -- someone might have reused a subkey somewhere
		err = hkpstorage.ErrKeyNotFound
		for _, record := range lastRecords {
			// Take care because FetchRecordsByFp can return nil PrimaryKeys
			if record.PrimaryKey != nil && record.Fingerprint == pubkey.Fingerprint {
				lastRecord, err = record, nil
				break
			}
		}
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if pubkey.UUID != lastRecord.UUID {
		return nil, errors.Errorf("upsert key %q lookup failed, found mismatch %q", pubkey.UUID, lastRecord.UUID)
	}
	lastID := lastRecord.KeyID
	lastMD5 := lastRecord.MD5
	err = st.preen(lastRecord)
	if err == openpgp.ErrKeyEvaporated {
		// Key on disk is invalid. Delete and insert the incoming key directly.
		_, err := st.Delete(lastRecord.Fingerprint)
		if err != nil {
			log.Errorf("could not delete fp=%s: %v", lastRecord.Fingerprint, err)
		}
		needUpsert, err := st.insertKey(pubkey)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if needUpsert {
			return nil, errors.Errorf("evaporated key needs Upsert; this should be impossible!")
		}
		return hkpstorage.KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: lastRecord.KeyID, NewDigest: lastRecord.MD5}, nil
	} else if err != nil && err != hkpstorage.ErrDigestMismatch {
		return nil, errors.WithStack(err)
	}

	err = st.policy.Merge(lastRecord.PrimaryKey, pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if lastMD5 != lastRecord.MD5 {
		err = st.Update(lastRecord.PrimaryKey, lastID, lastMD5)
		if err == errTargetMissing {
			// propagate verbatim so it can be handled
			return nil, err
		} else if err != nil {
			return nil, errors.WithStack(err)
		}
		return hkpstorage.KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: lastRecord.KeyID, NewDigest: lastRecord.MD5}, nil
	}
	return hkpstorage.KeyNotChanged{ID: lastID, Digest: lastMD5}, nil
}

func (st *storage) insertKeyTx(tx *sql.Tx, key *openpgp.PrimaryKey) (needUpsert bool, retErr error) {
	stmt, err := tx.Prepare("INSERT INTO keys (rfingerprint, ctime, mtime, idxtime, md5, doc, keywords, vfingerprint) " +
		"SELECT $1::TEXT, $2::TIMESTAMP, $3::TIMESTAMP, $4::TIMESTAMP, $5::TEXT, $6::JSONB, $7::TSVECTOR, $8::TEXT " +
		"WHERE NOT EXISTS (SELECT 1 FROM keys WHERE rfingerprint = $1)")
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer stmt.Close()

	subStmt, err := tx.Prepare("INSERT INTO subkeys (rfingerprint, rsubfp, vsubfp) " +
		"SELECT $1::TEXT, $2::TEXT, $3::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)")
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer subStmt.Close()

	uidStmt, err := tx.Prepare("INSERT INTO userids (rfingerprint, uidstring, identity, confidence) " +
		"SELECT $1::TEXT, $2::TEXT, $3::TEXT, $4::INTEGER WHERE NOT EXISTS (SELECT 1 FROM userids WHERE rfingerprint = $1 and uidstring = $2)")
	if err != nil {
		log.Errorf("1 SQL: %q", errors.WithStack(err))
		return false, errors.WithStack(err)
	}
	defer subStmt.Close()

	openpgp.Sort(key)

	now := time.Now().UTC()
	jsonKey := jsonhkp.NewPrimaryKey(key)
	jsonBuf, err := json.Marshal(jsonKey)
	if err != nil {
		return false, errors.Wrapf(err, "cannot serialize fp=%q", key.Fingerprint)
	}

	jsonStr := string(jsonBuf)
	keywords, uiddocs := types.KeywordsTSVector(key)
	rfp := types.Reverse(key.Fingerprint)
	result, err := stmt.Exec(&rfp, &now, &now, &now, &key.MD5, &jsonStr, &keywords, &key.VFingerprint)
	if err != nil {
		return false, errors.Wrapf(err, "cannot insert fp=%q", key.Fingerprint)
	}

	var keysInserted int64
	if keysInserted, err = result.RowsAffected(); err != nil {
		// We arrive here if the DB driver doesn't support
		// RowsAffected, although lib/pq is known to support it.
		// If it doesn't, then something has gone badly awry!
		return false, errors.Wrapf(err, "rows affected not available when inserting fp=%q", key.Fingerprint)
	}
	if keysInserted == 0 {
		return true, nil
	}

	for _, subKey := range key.SubKeys {
		rsubfp := types.Reverse(subKey.Fingerprint)
		_, err := subStmt.Exec(&rfp, &rsubfp, &subKey.VFingerprint)
		if err != nil {
			return false, errors.Wrapf(err, "cannot insert subfp=%q", subKey.Fingerprint)
		}
	}
	for _, uid := range uiddocs {
		_, err := uidStmt.Exec(&rfp, &uid.UidString, &uid.Identity, &uid.Confidence)
		if err != nil {
			log.Errorf("2 SQL: %q", errors.WithStack(err))
			return false, errors.Wrapf(err, "cannot insert uid=%q", uid.UidString)
		}
	}
	return false, nil
}

func (st *storage) insertKey(key *openpgp.PrimaryKey) (needUpsert bool, retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()
	return st.insertKeyTx(tx, key)
}

var errTargetMissing = errors.New("errTargetMissing")

func (st *storage) Insert(keys []*openpgp.PrimaryKey) (u, n int, retErr error) {
	var result hkpstorage.InsertError

	bulkOK, bulkSkip := false, false
	if len(keys) >= minKeys2UseBulk {
		// Attempt bulk insertion
		bs, err := st.bulkCreateTempTables()
		if err != nil {
			log.Warnf("could not create temp tables: %v", err)
		} else {
			defer bs.bulkDropTempTables()
			n, _, bulkOK = bs.bulkInsert(keys, &result, []string{})
		}
	} else {
		bulkSkip = true
	}

	if !bulkOK {
		log.Infof("bulk insertion %s; reverting to normal insertion",
			(map[bool]string{true: "skipped (small number of keys)", false: "failed"})[bulkSkip])
		if !bulkSkip {
			log.Debugf("bulkInsert not ok: %q", result.Errors)
		}

		for _, key := range keys {
			if count, max := len(result.Errors), maxInsertErrors; count > max {
				result.Errors = append(result.Errors,
					errors.Errorf("too many insert errors (%d > %d), bailing...", count, max))
				return u, n, result
			}

			if needUpsert, err := st.insertKey(key); err != nil {
				result.Errors = append(result.Errors, err)
				continue
			} else if needUpsert {
				var kc hkpstorage.KeyChange
				// errTargetMissing is thrown if Update() can't find the key it was told to modify.
				// This can happen in case of concurrent updates to the same key. Back off a few times.
				for i := 0; i < 3; i++ {
					kc, err = st.upsertKeyOnInsert(key)
					if err != errTargetMissing {
						log.Infof("key fp(%v) is slippery; backing off", key.Fingerprint)
						break
					}
				}
				if err == errTargetMissing {
					result.Errors = append(result.Errors,
						errors.Errorf("key fp(%v) was changing while we were updating it", key.Fingerprint))
				} else if err != nil {
					result.Errors = append(result.Errors, err)
					continue
				} else {
					switch kc.(type) {
					case hkpstorage.KeyReplaced:
						// FIXME: Listener in hockeypuck-load not really prepared for
						// hkpstorage.KeyReplaced notifications but stats are updated...
						st.Notify(kc)
						u++
					case hkpstorage.KeyNotChanged:
						result.Duplicates = append(result.Duplicates, key)
					}
				}
				continue
			} else {
				st.Notify(hkpstorage.KeyAdded{
					ID:     key.KeyID,
					Digest: key.MD5,
				})
				n++
			}
		}
	}

	if len(result.Duplicates) > 0 || len(result.Errors) > 0 {
		return u, n, result
	}
	return u, n, nil
}

func (st *storage) Replace(key *openpgp.PrimaryKey) (_ string, retErr error) {
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
	md5, err := st.deleteTx(tx, key.Fingerprint)
	if err != nil {
		return "", errors.WithStack(err)
	}
	_, err = st.insertKeyTx(tx, key)
	if err != nil {
		return "", errors.WithStack(err)
	}

	st.Notify(hkpstorage.KeyReplaced{
		OldID:     key.KeyID,
		OldDigest: md5,
		NewID:     key.KeyID,
		NewDigest: key.MD5,
	})
	return md5, nil
}

func (st *storage) Update(key *openpgp.PrimaryKey, lastID string, lastMD5 string) (retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	openpgp.Sort(key)

	now := time.Now().UTC()
	jsonKey := jsonhkp.NewPrimaryKey(key)
	jsonBuf, err := json.Marshal(jsonKey)
	if err != nil {
		return errors.Wrapf(err, "cannot serialize fp=%q", key.Fingerprint)
	}
	keywords, uiddocs := types.KeywordsTSVector(key)
	result, err := tx.Exec("UPDATE keys SET mtime = $1, idxtime = $2, md5 = $3, keywords = $4::TSVECTOR, doc = $5, vfingerprint = $6 "+
		"WHERE md5 = $7",
		&now, &now, &key.MD5, &keywords, jsonBuf, &key.VFingerprint,
		lastMD5)
	if err != nil {
		return errors.WithStack(err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected > 1 {
		return errors.Errorf("unexpected error when updating digest %v fp(%v)", lastMD5, key.Fingerprint)
	} else if rowsAffected == 0 {
		// The md5 disappeared before we could update it. Thread-safety backoff.
		return errTargetMissing
	}
	rfp := types.Reverse(key.Fingerprint)
	for _, subKey := range key.SubKeys {
		rsubfp := types.Reverse(subKey.Fingerprint)
		_, err := tx.Exec("INSERT INTO subkeys (rfingerprint, rsubfp, vsubfp) "+
			"VALUES ( $1::TEXT, $2::TEXT, $3::TEXT ) "+
			"ON CONFLICT (rsubfp) DO UPDATE SET vsubfp = $3::TEXT", // gracefully update existing records
			&rfp, &rsubfp, &subKey.VFingerprint)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	for _, uid := range uiddocs {
		_, err := tx.Exec("INSERT INTO userids (rfingerprint, uidstring, identity, confidence) "+
			"VALUES ( $1::TEXT, $2::TEXT, $3::TEXT, $4::INTEGER ) "+
			"ON CONFLICT (rfingerprint, uidstring) DO UPDATE SET identity = $3::TEXT, confidence = $4::INTEGER", // gracefully update existing records
			&rfp, &uid.UidString, &uid.Identity, &uid.Confidence)
		if err != nil {
			log.Errorf("3 SQL: %q", errors.WithStack(err))
			return errors.WithStack(err)
		}
	}

	st.Notify(hkpstorage.KeyReplaced{
		OldID:     lastID,
		OldDigest: lastMD5,
		NewID:     key.KeyID,
		NewDigest: key.MD5,
	})
	return nil
}
