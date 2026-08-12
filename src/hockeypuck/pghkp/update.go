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

// mergeStoredKey merges the incoming key into an already-stored copy with the
// same fingerprint. It is only called once an insert attempt has found that the
// key already exists. Every storage-mutating path notifies subscribers itself
// (st.Delete and st.Update notify internally; the evaporated branch notifies
// explicitly), so callers MUST NOT re-notify the returned change. The
// KeyNotChanged path mutates nothing and so emits no notification.
//
// errTargetMissing is returned verbatim if the stored copy changed underneath
// us, so that the Upsert back-off loop can detect and retry it.
func (st *storage) mergeStoredKey(pubkey *openpgp.PrimaryKey) (kc hkpstorage.KeyChange, err error) {
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
	lastTrustMD5 := lastRecord.PrimaryKey.TrustMD5
	err = st.preen(lastRecord)
	if err == openpgp.ErrKeyEvaporated {
		// Key on disk is invalid. Delete and insert the incoming key directly.
		// A delete failure is only logged, not fatal: we still try to insert, and
		// the needUpsert check below catches the case where the stale row survives.
		_, delErr := st.Delete(lastRecord.Fingerprint)
		if delErr != nil {
			log.Errorf("could not delete fp=%s: %v", lastRecord.Fingerprint, delErr)
		}
		needUpsert, err := st.insertKey(pubkey)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if needUpsert {
			// The row still exists after the delete+insert, so we could neither
			// merge (preen said the key had evaporated) nor replace it. This most
			// likely means the delete above failed, or a peer concurrently
			// re-inserted the fingerprint.
			return nil, errors.Errorf("evaporated key fp=%v still present after delete+insert (delete error: %v)",
				lastRecord.Fingerprint, delErr)
		}
		// st.Delete above notified the removal, but insertKey does not notify,
		// so announce the replacement with the incoming key explicitly.
		kc := hkpstorage.KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: pubkey.KeyID, NewDigest: pubkey.MD5}
		st.Notify(kc)
		return kc, nil
	} else if err != nil && err != hkpstorage.ErrDigestMismatch {
		return nil, errors.WithStack(err)
	}

	// Merge the incoming key into the stored copy. If the merge changes the key
	// material, st.Update persists it and notifies the KeyReplaced itself.
	err = st.policy.Merge(lastRecord.PrimaryKey, pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// A key is unchanged only if its SKS MD5 *AND* its TrustMD5 are both unchanged.
	// If we don't check both, quiet trust packets will not be reliably propagated. (Issue 456)
	if lastMD5 == lastRecord.PrimaryKey.MD5 && lastTrustMD5 == lastRecord.PrimaryKey.TrustMD5 {
		return hkpstorage.KeyNotChanged{ID: lastID, Digest: lastMD5}, nil
	}
	err = st.Update(lastRecord.PrimaryKey, lastID, lastMD5)
	if err != nil {
		// errTargetMissing is propagated verbatim for the back-off loop.
		return nil, err
	}
	return hkpstorage.KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: lastRecord.KeyID, NewDigest: lastRecord.PrimaryKey.MD5}, nil
}

// Upsert inserts pubkey if it is not already stored, otherwise merges it into
// the stored copy according to the storage's merge policy. It notifies
// subscribers and returns the resulting KeyChange.
func (st *storage) Upsert(pubkey *openpgp.PrimaryKey) (hkpstorage.KeyChange, error) {
	needUpsert, err := st.insertKey(pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !needUpsert {
		// insertKey does not notify, so announce the new key here.
		kc := hkpstorage.KeyAdded{ID: pubkey.KeyID, Digest: pubkey.MD5}
		st.Notify(kc)
		return kc, nil
	}

	// The key already exists; merge the incoming key into it. errTargetMissing
	// is thrown if the stored copy changes underneath us (e.g. concurrent
	// updates); back off a few times before giving up.
	var kc hkpstorage.KeyChange
	for i := 0; i < 3; i++ {
		kc, err = st.mergeStoredKey(pubkey)
		if err != errTargetMissing {
			break
		}
		log.Infof("key fp(%v) is slippery; backing off", pubkey.Fingerprint)
	}
	if err == errTargetMissing {
		return nil, errors.Errorf("key fp(%v) was changing while we were updating it", pubkey.Fingerprint)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return kc, nil
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

			kc, err := st.Upsert(key)
			if err != nil {
				result.Errors = append(result.Errors, err)
				continue
			}
			switch kc.(type) {
			case hkpstorage.KeyAdded:
				n++
			case hkpstorage.KeyReplaced:
				// FIXME: Listener in hockeypuck-load not really prepared for
				// hkpstorage.KeyReplaced notifications but stats are updated...
				u++
			case hkpstorage.KeyNotChanged:
				result.Duplicates = append(result.Duplicates, key)
			}
		}
	}

	if len(result.Duplicates) > 0 || len(result.Errors) > 0 {
		return u, n, result
	}
	return u, n, nil
}

func (st *storage) Replace(key *openpgp.PrimaryKey) (_ hkpstorage.KeyChange, retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			retErr = tx.Commit()
		}
	}()
	// A not-found here just means there was nothing to replace; Replace is
	// documented to add the key in that case, so carry on with an empty prior
	// md5 (which yields a KeyAdded change below).
	md5, err := st.deleteTx(tx, key.Fingerprint)
	if err != nil && !errors.Is(err, hkpstorage.ErrKeyNotFound) {
		return nil, errors.WithStack(err)
	}
	_, err = st.insertKeyTx(tx, key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var kc hkpstorage.KeyChange
	if md5 == "" {
		// Nothing was replaced; the key was newly added.
		kc = hkpstorage.KeyAdded{ID: key.KeyID, Digest: key.MD5}
	} else {
		kc = hkpstorage.KeyReplaced{
			OldID:     key.KeyID,
			OldDigest: md5,
			NewID:     key.KeyID,
			NewDigest: key.MD5,
		}
	}
	st.Notify(kc)
	return kc, nil
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

	// unlike subkeys, where ON CONFLICT updates are sufficient, we have to delete old uiddocs before (re-)adding the current ones
	// this is because (unlike subkeys) uids can be deleted by the merge policy
	// TODO: postgres >=15 supports MERGE which can do this more efficiently
	_, err = tx.Exec("DELETE FROM userids WHERE rfingerprint = $1::TEXT", &rfp)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, uid := range uiddocs {
		// NOTE that the ON CONFLICT clause below should never be triggered (because of the DELETE FROM above),
		// but primary key conflicts have been seen in production if ON CONFLICT is not present.
		// TODO: WTF https://github.com/hockeypuck/hockeypuck/issues/453
		_, err := tx.Exec("INSERT INTO userids (rfingerprint, uidstring, identity, confidence) "+
			"VALUES ( $1::TEXT, $2::TEXT, $3::TEXT, $4::INTEGER ) "+
			"ON CONFLICT (rfingerprint, uidstring) DO UPDATE SET identity = $3::TEXT, confidence = $4::INTEGER", // gracefully update existing records
			&rfp, &uid.UidString, &uid.Identity, &uid.Confidence)
		if err != nil {
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
