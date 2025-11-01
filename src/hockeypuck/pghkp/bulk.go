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
	"encoding/json"
	"fmt"
	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"
	"iter"
	"maps"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//
// Private bulk-update helpers for use by Updater, Reindexer, Reloader etc.
//

// keysInBunch is the maximum number of keys sent in a bunch during bulk insertion.
// Since keys (and subkeys) are sent to the DB in prepared statements with parameters and
// each key requires keysNumColumns parameters, keysInBunch < 65536/keysNumColumns.
// 64k (2-byte parameter count) is the current protocol limit for client communication,
// of prepared statements in PostreSQL v13 (see Bind message in
// https://www.postgresql.org/docs/current/protocol-message-formats.html).
const keysInBunch int = 64000 / keysNumColumns

// subkeysInBunch is the maximum number of subkeys sent in a bunch (for at most
// keysInBunch keys sent in a bunch) during bulk insertion. If each subkey requires 2
// parameters, ~32k subkeys can fit in a bunch (see keysInBunch).
const subkeysInBunch int = 64000 / subkeysNumColumns

// uidsInBunch is the maximum number of userids sent in a bunch (for at most
// keysInBunch keys sent in a bunch) during bulk insertion. If each userid requires 4
// parameters, ~16k userids can fit in a bunch (see keysInBunch).
const uidsInBunch int = 64000 / useridsNumColumns

// minKeys2UseBulk is the minimum number of keys in a call to Insert(..) that
// will trigger a bulk insertion. Otherwise, Insert(..) preceeds one key at a time.
const minKeys2UseBulk int = 3500

func (st *storage) bulkInsertGetStats(result *hkpstorage.InsertError) (maxDups, minDups, keysInserted, subkeysInserted, useridsInserted int) {
	// Get Duplicate stats
	err := st.QueryRow(bulkInsNumMinDups).Scan(&minDups)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update duplicate stats: %v", err)
		minDups = 0
	}
	// In-file duplicates may be duplicates even if we insert a subkey for a key's rfp
	// FIXME: This might be costly and could be removed...
	err = st.QueryRow(bulkInsNumPossibleDups).Scan(&maxDups)
	maxDups += minDups
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update duplicate stats: %v", err)
		maxDups = 0
	}
	// Get keys/subkeys inserted
	err = st.QueryRow(bulkInsertedKeysNum).Scan(&keysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys inserted stats: %v", err)
		keysInserted = 0
	}
	err = st.QueryRow(bulkInsertedSubkeysNum).Scan(&subkeysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys inserted stats: %v", err)
		subkeysInserted = 0
	}
	err = st.QueryRow(bulkInsertedUserIDsNum).Scan(&useridsInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update userids inserted stats: %v", err)
		useridsInserted = 0
	}
	return
}

func (st *storage) bulkUpdateGetStats(result *hkpstorage.InsertError) (keysUpdated, subkeysInserted, useridsInserted, keysDeleted int) {
	// The number of keys copied and the number updated should be the same (TODO: check this!)
	err := st.QueryRow(bulkCopiedKeysNum).Scan(&keysUpdated)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys updated stats: %v", err)
		keysUpdated = 0
	}
	err = st.QueryRow(bulkInsertedSubkeysNum).Scan(&subkeysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys inserted stats: %v", err)
		subkeysInserted = 0
	}
	err = st.QueryRow(bulkInsertedUserIDsNum).Scan(&useridsInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update userids inserted stats: %v", err)
		useridsInserted = 0
	}
	err = st.QueryRow(bulkDeletedKeysNum).Scan(&keysDeleted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys inserted stats: %v", err)
		subkeysInserted = 0
	}
	return
}

func (st *storage) bulkExecSingleTx(bulkJobString, jobDesc []string) (err error) {
	log.Debugf("transaction started: %q", jobDesc)
	t := time.Now()
	// In single transaction
	tx, err := st.Begin()
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			tx.Rollback()
		}
	}()

	for i := 0; i < len(bulkJobString); i++ {
		bulkTxStmt, err := tx.Prepare(bulkJobString[i])
		if err != nil {
			return errors.Wrapf(err, "preparing DB server job %s", jobDesc[i])
		}
		defer bulkTxStmt.Close()
		_, err = bulkTxStmt.Exec()
		if err != nil {
			return errors.Wrapf(err, "issuing DB server job %s", jobDesc[i])
		}
	}
	log.Debugf("transaction finished in %v", time.Since(t))
	return err
}

func (st *storage) bulkInsertCheckSubkeys(result *hkpstorage.InsertError) (numNulls int, ok bool) {
	// NULLs stats
	err := st.QueryRow(bulkInsNumNullSubkeys).Scan(&numNulls)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys with NULL stats: %v", err)
	}

	// (1) Itermediate insert: no NULL fields & no Duplicates (in-file or in DB)
	// (2) Keep only subkeys with Duplicates in subkeys_copyin:
	//     Delete 1st-stage checked subkeys above & those with NULL fields
	// (3) Single-copy of in-file Dups but not in-DB Dups
	txStrs := []string{bulkTxFilterUniqueSubkeys, bulkTxPrepSubkeyStats, bulkTxFilterDupSubkeys}
	msgStrs := []string{"bulkTx-filter-unique-subkeys", "bulkTx-prep-subkeys-stats", "bulkTx-filter-dup-subkeys"}
	err = st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not check subkeys: %v", err)
		return 0, false
	}
	return numNulls, true
}

func (st *storage) bulkInsertCheckUserIDs(result *hkpstorage.InsertError) (numNulls int, ok bool) {
	// NULLs stats
	err := st.QueryRow(bulkInsNumNullUserIDs).Scan(&numNulls)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update userids with NULL stats: %v", err)
	}

	// (1) Itermediate insert: no NULL fields & no Duplicates (in-file or in DB)
	// (2) Keep only userids with Duplicates in userids_copyin:
	//     Delete 1st-stage checked userids above & those with NULL fields
	// (3) Single-copy of in-file Dups but not in-DB Dups
	txStrs := []string{bulkTxFilterUniqueUserIDs, bulkTxPrepUserIDStats, bulkTxFilterDupUserIDs}
	msgStrs := []string{"bulkTx-filter-unique-userids", "bulkTx-prep-userids-stats", "bulkTx-filter-dup-userids"}
	err = st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not check userids: %v", err)
		return 0, false
	}
	return numNulls, true
}

func (st *storage) bulkInsertCheckKeys(result *hkpstorage.InsertError) (numNulls int, ok bool) {
	// NULLs stats
	err := st.QueryRow(bulkInsNumNullKeys).Scan(&numNulls)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys with NULL stats: %v", err)
	}

	// (1) rfingerprint & md5 are also UNIQUE in keys_checked so no duplicates inside this same file allowed
	// (2) Keep only keys with Duplicates in keys_copyin: delete 1st-stage checked keys & tuples with NULL fields
	// (3) Insert single copy of in-file Duplicates, if they have no Duplicate in final keys table (in DB)
	txStrs := []string{bulkTxFilterUniqueKeys, bulkTxPrepKeyStats, bulkTxFilterDupKeys}
	msgStrs := []string{"bulkTx-filter-unique-keys", "bulkTx-prep-key-stats", "bulkTx-filter-dup-keys"}
	err = st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not check keys: %v", err)
		return 0, false
	}
	return numNulls, true
}

func (st *storage) bulkInsertCheckedKeysSubkeys(result *hkpstorage.InsertError) (nullKeys, nullSubkeys, nullUserIDs int, ok bool) {
	keysOK, subkeysOK, useridsOK := true, true, true
	// key batch-processing
	if nullKeys, keysOK = st.bulkInsertCheckKeys(result); !keysOK {
		return 0, 0, 0, false
	}
	// subkey batch-processing
	if nullSubkeys, subkeysOK = st.bulkInsertCheckSubkeys(result); !subkeysOK {
		return 0, 0, 0, false
	}
	// userid batch-processing
	if nullUserIDs, useridsOK = st.bulkInsertCheckUserIDs(result); !useridsOK {
		return 0, 0, 0, false
	}

	// Batch INSERT all checked-for-constraints keys from memory tables (should need no checks!!!!)
	// Final batch-insertion in keys/subkeys tables without any checks: _must not_ give any errors
	txStrs := []string{bulkTxInsertKeys, bulkTxInsertSubkeys, bulkTxInsertUserIDs}
	msgStrs := []string{"bulkTx-insert-keys", "bulkTx-insert-subkeys", "bulkTx-insert-userids"}
	err := st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not insert keys: %v", err)
		return 0, 0, 0, false
	}
	return nullKeys, nullSubkeys, nullUserIDs, true
}

// bulkUpdateKeysSubkeys updates a bunch of keys in-place.
// It is similar to bulkInsertCheckedKeysSubkeys but performs no checks on keys (we assume the DB is already sane)
// We still have to check for duplicate subkeys, as these are not stripped from the json docs.
func (st *storage) bulkUpdateKeysSubkeys(result *hkpstorage.InsertError) (nullSubkeys, nullUserIDs int, ok bool) {
	subkeysOK, useridsOK := true, true
	// subkey batch-processing
	if nullSubkeys, subkeysOK = st.bulkInsertCheckSubkeys(result); !subkeysOK {
		return 0, 0, false
	}
	// userid batch-processing
	if nullUserIDs, useridsOK = st.bulkInsertCheckUserIDs(result); !useridsOK {
		return 0, 0, false
	}

	// Batch UPDATE all keys from memory tables (should need no checks!!!!)
	// Final batch-update in keys/subkeys tables without any checks: _must not_ give any errors
	txStrs := []string{
		bulkTxJournalKeys,
		bulkTxClearDupSubkeys, bulkTxClearOrphanSubkeys, bulkTxClearDupUserIDs, bulkTxClearOrphanUserIDs,
		bulkTxClearKeys, bulkTxUpdateKeys,
		bulkTxInsertSubkeys, bulkTxReindexSubkeys, bulkTxInsertUserIDs, bulkTxReindexUserIDs,
	}
	msgStrs := []string{
		"bulkTx-journal-keys",
		"bulkTx-clear-dup-subkeys", "bulkTx-clear-orphan-subkeys", "bulkTx-clear-dup-userids", "bulkTx-clear-orphan-userids",
		"bulkTx-clear-keys", "bulkTx-update-keys",
		"bulkTx-insert-subkeys", "bulkTx-reindex-subkeys", "bulkTx-insert-userids", "bulkTx-reindex-userids",
	}
	err := st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys: %v", err)
		return 0, 0, false
	}
	return nullSubkeys, nullUserIDs, true
}

func (st *storage) bulkInsertSendBunchTx(keystmt, msgSpec string, keysValueArgs []interface{}) (err error) {
	log.Debugf("transaction started: %q", msgSpec)
	t := time.Now()
	// In single transaction...
	tx, err := st.Begin()
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	stmt, err := tx.Prepare(keystmt)
	if err != nil {
		return errors.Wrapf(err, "failure preparing %s (query='%v')", msgSpec, keystmt)
	}
	defer stmt.Close()
	_, err = stmt.Exec(keysValueArgs...) // All keys in bunch
	if err != nil {
		return errors.Wrapf(err, "cannot simply send a bunch of %s to server (too large bunch?)", msgSpec)
	}
	log.Debugf("transaction finished in %v", time.Since(t))
	return nil
}

// TODO: these are effectively duplicates of KeyDoc, SubKeyDoc, UserIdDoc - can we merge them?
type keyInsertArgs struct {
	RFingerprint *string
	jsonStrDoc   *string
	MD5          *string
	keywords     *string
	VFingerprint *string
}
type subkeyInsertArgs struct {
	keyRFingerprint    *string
	subkeyRFingerprint *string
	subkeyVFingerprint *string
}
type uidInsertArgs struct {
	RFingerprint *string
	UidString    *string
	Identity     *string
	Confidence   *int
}

// Insert keys, subkeys, userids to in-mem tables with no constraints at all: should have no errors!
func (st *storage) bulkInsertDoCopy(keyInsArgs []keyInsertArgs, skeyInsArgs [][]subkeyInsertArgs, uidInsArgs [][]uidInsertArgs, result *hkpstorage.InsertError) (ok bool) {
	lenKIA := len(keyInsArgs)
	for idx, lastIdx := 0, 0; idx < lenKIA; lastIdx = idx {
		totKeyArgs, totSubkeyArgs, totUidArgs := 0, 0, 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]interface{}, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]interface{}, 0, subkeysInBunch*subkeysNumColumns) // *** must be less than 64k arguments ***
		uidsValueStrings := make([]string, 0, uidsInBunch)
		uidsValueArgs := make([]interface{}, 0, uidsInBunch*useridsNumColumns) // *** must be less than 64k arguments ***
		for i, j, k := 0, 0, 0; idx < lenKIA; idx, i = idx+1, i+1 {
			lenSKIA := len(skeyInsArgs[idx])
			lenUIA := len(uidInsArgs[idx])
			totKeyArgs += keysNumColumns
			totSubkeyArgs += subkeysNumColumns * lenSKIA
			totUidArgs += useridsNumColumns * lenUIA
			if (totKeyArgs > keysInBunch*keysNumColumns) || (totSubkeyArgs > subkeysInBunch*subkeysNumColumns) {
				totKeyArgs -= keysNumColumns
				totSubkeyArgs -= subkeysNumColumns * lenSKIA
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, $%d::TSVECTOR, $%d::TEXT)",
					i*keysNumColumns+1, i*keysNumColumns+2, i*keysNumColumns+3, i*keysNumColumns+4, i*keysNumColumns+5, i*keysNumColumns+6, i*keysNumColumns+7, i*keysNumColumns+8))
			insTime := time.Now().UTC()
			keysValueArgs = append(keysValueArgs, *keyInsArgs[idx].RFingerprint, *keyInsArgs[idx].jsonStrDoc,
				insTime, insTime, insTime, *keyInsArgs[idx].MD5, *keyInsArgs[idx].keywords, *keyInsArgs[idx].VFingerprint)

			for sidx := 0; sidx < lenSKIA; sidx, j = sidx+1, j+1 {
				subkeysValueStrings = append(subkeysValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT)", j*subkeysNumColumns+1, j*subkeysNumColumns+2, j*subkeysNumColumns+3))
				subkeysValueArgs = append(subkeysValueArgs,
					*skeyInsArgs[idx][sidx].keyRFingerprint, *skeyInsArgs[idx][sidx].subkeyRFingerprint, *skeyInsArgs[idx][sidx].subkeyVFingerprint)
			}
			for uidx := 0; uidx < lenUIA; uidx, k = uidx+1, k+1 {
				uidsValueStrings = append(uidsValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT, $%d::INTEGER)", k*useridsNumColumns+1, k*useridsNumColumns+2, k*useridsNumColumns+3, k*useridsNumColumns+4))
				uidsValueArgs = append(uidsValueArgs,
					*uidInsArgs[idx][uidx].RFingerprint, *uidInsArgs[idx][uidx].UidString, *uidInsArgs[idx][uidx].Identity, *uidInsArgs[idx][uidx].Confidence)
			}
		}

		log.Debugf("attempting bulk insertion of %d keys, %d subkeys, %d userids", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
		ok := st.bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings, keysValueArgs, subkeysValueArgs, uidsValueArgs, result)
		if !ok {
			return false
		}
		log.Debugf("%d keys, %d subkeys, %d userids sent to DB...", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
	}
	return true
}

// bulkInsertSend copies the constructed database rows to the postgres in-memory tables
func (st *storage) bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings []string, keysValueArgs, subkeysValueArgs, uidsValueArgs []interface{}, result *hkpstorage.InsertError) (ok bool) {
	// Send all keys to in-mem tables to the pg server; *no constraints checked*
	keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint) VALUES %s",
		keys_copyin_temp_table_name, strings.Join(keysValueStrings, ","))
	err := st.bulkInsertSendBunchTx(keystmt, "INSERT INTO "+keys_copyin_temp_table_name, keysValueArgs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not send key bunch: %v", err)
		return false
	}

	// Send all subkeys to in-mem tables to the pg server; *no constraints checked*
	subkeystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, rsubfp, vsubfp) VALUES %s",
		subkeys_copyin_temp_table_name, strings.Join(subkeysValueStrings, ","))
	err = st.bulkInsertSendBunchTx(subkeystmt, "INSERT INTO "+subkeys_copyin_temp_table_name, subkeysValueArgs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not send subkey bunch: %v", err)
		return false
	}

	// Send all userids to in-mem tables to the pg server; *no constraints checked*
	useridstmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, uidstring, identity, confidence) VALUES %s",
		userids_copyin_temp_table_name, strings.Join(uidsValueStrings, ","))
	err = st.bulkInsertSendBunchTx(useridstmt, "INSERT INTO "+userids_copyin_temp_table_name, uidsValueArgs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not send userid bunch: %v", err)
		return false
	}
	return true
}

func (st *storage) bulkInsertCopyOld(oldKeys []string, result *hkpstorage.InsertError) (ok bool) {
	keysValueStrings := make([]string, 0, keysInBunch)
	keysValueArgs := make([]interface{}, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
	for index, fp := range oldKeys {
		keysValueStrings = append(keysValueStrings, fmt.Sprintf("($%d::TEXT)", index+1))
		keysValueArgs = append(keysValueArgs, openpgp.Reverse(fp))
	}

	log.Debugf("uploading %d old fps", len(oldKeys))

	keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint) VALUES %s",
		keys_old_temp_table_name, strings.Join(keysValueStrings, ","))
	err := st.bulkInsertSendBunchTx(keystmt, "keys", keysValueArgs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not send old key bunch: %v", err)
		return false
	}
	return true
}

func (st *storage) bulkInsertCopyKeysToServer(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError) (int, bool) {
	var key *openpgp.PrimaryKey
	keyInsArgs := make([]keyInsertArgs, 0, len(keys))
	skeyInsArgs := make([][]subkeyInsertArgs, 0, len(keys))
	uidInsArgs := make([][]uidInsertArgs, 0, len(keys))
	jsonStrs, theKeywords, uids := make([]string, len(keys)), make([]string, len(keys)), make([][]types.UserIdDoc, len(keys))

	unprocessed, sidx, uidx, i := 0, 0, 0, 0
	for _, key = range keys {
		openpgp.Sort(key)
		jsonKey := jsonhkp.NewPrimaryKey(key)
		jsonBuf, err := json.Marshal(jsonKey)
		if err != nil {
			err = errors.Wrapf(err, "pre-processing cannot serialize rfp=%q", key.RFingerprint)
			result.Errors = append(result.Errors, err)
			log.Warnf("%v", err)
			unprocessed++
			continue
		}
		jsonStrs[i] = string(jsonBuf)
		theKeywords[i], uids[i] = types.KeywordsTSVector(key)
		keyInsArgs = keyInsArgs[:i+1] // re-slice +1
		keyInsArgs[i] = keyInsertArgs{&key.RFingerprint, &jsonStrs[i], &key.MD5, &theKeywords[i], &key.VFingerprint}

		skeyInsArgs = skeyInsArgs[:i+1] // re-slice +1
		skeyInsArgs[i] = make([]subkeyInsertArgs, 0, len(key.SubKeys))
		for sidx = 0; sidx < len(key.SubKeys); sidx++ {
			skeyInsArgs[i] = skeyInsArgs[i][:sidx+1] // re-slice +1
			skeyInsArgs[i][sidx] = subkeyInsertArgs{&key.RFingerprint, &key.SubKeys[sidx].RFingerprint, &key.SubKeys[sidx].VFingerprint}
		}
		uidInsArgs = uidInsArgs[:i+1] // re-slice +1
		uidInsArgs[i] = make([]uidInsertArgs, 0, len(uids[i]))
		for uidx = 0; uidx < len(uids[i]); uidx++ {
			uidInsArgs[i] = uidInsArgs[i][:uidx+1] // re-slice +1
			uidInsArgs[i][uidx] = uidInsertArgs{&key.RFingerprint, &uids[i][uidx].UidString, &uids[i][uidx].Identity, &uids[i][uidx].Confidence}
		}
		i++
	}
	ok := st.bulkInsertDoCopy(keyInsArgs, skeyInsArgs, uidInsArgs, result)
	return unprocessed, ok
}

func (st *storage) bulkDropTempTables() error {
	// Drop the 2 pairs (all) of temporary tables
	err := st.bulkExecSingleTx(drTempTablesSQL, []string{"dr-temp-tables"})
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (st *storage) bulkCreateTempTables() error {
	err := st.bulkExecSingleTx(crTempTablesSQL, []string{"cr-temp-tables"})
	if err != nil {
		return errors.Wrap(err, "cannot create temporary tables")
	}
	return nil
}

// bulkInsert inserts the given keys, and stores any errors in `result`
// If `oldKeys` is a non-empty list of fingerprints, any keys in it but not in `keys` will be deleted.
func (st *storage) bulkInsert(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError, oldKeys []string) (keysInserted, keysDeleted int, ok bool) {
	log.Infof("attempting bulk insertion of keys")
	t := time.Now() // FIXME: Remove this
	// Create 2 sets of _temporary_ (in-mem) tables:
	// (a) keys_copyin, subkeys_copyin, userids_copyin
	// (b) keys_checked, subkeys_checked, userids_checked
	err := st.bulkCreateTempTables()
	if err != nil {
		// This should always be possible (maybe, out-of-memory?)
		result.Errors = append(result.Errors, err)
		log.Warnf("could not create temp tables: %v", err)
		return 0, 0, false
	}
	defer st.bulkDropTempTables()
	var keysWithNulls, subkeysWithNulls, useridsWithNulls, maxDups, minDups, subkeysInserted, useridsInserted int
	// (a): Send *all* keys to in-mem tables on the pg server; *no constraints checked*
	if _, ok = st.bulkInsertCopyKeysToServer(keys, result); !ok {
		return 0, 0, false
	}
	if len(oldKeys) != 0 {
		if !st.bulkInsertCopyOld(oldKeys, result) {
			return 0, 0, false
		}
		// (b): From _copyin tables update existing on-disk records
		//      check subkey constraints only
		if subkeysWithNulls, useridsWithNulls, ok = st.bulkUpdateKeysSubkeys(result); !ok {
			return 0, 0, false
		}
		keysInserted, subkeysInserted, useridsInserted, keysDeleted = st.bulkUpdateGetStats(result)
		err = st.BulkNotify(bulkUpdQueryKeyAdded, bulkUpdQueryKeyRemoved)
		if err != nil {
			result.Errors = append(result.Errors, err)
			log.Warnf("could not bulk notify insertion/deletion: %v", err)
		}
	} else {
		// (b): From _copyin tables (still only to in-mem table) remove duplicates
		//      check *all* constraints & RollBack insertions of key/subkeys that err
		if keysWithNulls, subkeysWithNulls, useridsWithNulls, ok = st.bulkInsertCheckedKeysSubkeys(result); !ok {
			return 0, 0, false
		}
		maxDups, minDups, keysInserted, subkeysInserted, useridsInserted = st.bulkInsertGetStats(result)
		err = st.BulkNotify(bulkInsQueryKeyChange)
		if err != nil {
			result.Errors = append(result.Errors, err)
			log.Warnf("could not bulk notify insertion: %v", err)
		}
	}

	if minDups == maxDups {
		log.Infof("%d keys and %d subkeys bulk-inserted, %d keys deleted, %d duplicates skipped (%d keys, %d subkeys, %d userids with NULLs) in %v",
			keysInserted, subkeysInserted, keysDeleted, minDups, keysWithNulls, subkeysWithNulls, useridsWithNulls, time.Since(t))
	} else {
		log.Infof("%d keys, %d subkeys, %d userids bulk-inserted, %d keys deleted, at least %d (and up to %d possible) duplicates skipped "+
			"(%d keys, %d subkeys, %d userids with NULLs) in %v",
			keysInserted, subkeysInserted, useridsInserted, keysDeleted, minDups, maxDups, keysWithNulls, subkeysWithNulls, useridsWithNulls, time.Since(t))
	}

	err = st.bulkDropTempTables()
	if err != nil {
		// Temporary tables with previous data may lead to errors,
		// when attempting insertion of duplicates, in next file,
		// but may be resolved for the subsequent file(s)
		result.Errors = append(result.Errors, err)
		log.Warnf("could not drop temp tables: %v", err)
	}
	// FIXME: Imitate returning duplicates for reporting. Can be removed.
	result.Duplicates = make([]*openpgp.PrimaryKey, minDups)
	return keysInserted, keysDeleted, true
}

// bulkReindexDoCopy insert keys, subkeys, userids to in-mem tables with no constraints at all: should have no errors!
// TODO: this duplicates a lot of code from bulkInsertDoCopy; find a DRYer way
func (st *storage) bulkReindexDoCopy(keyDocs iter.Seq[*types.KeyDoc], result *hkpstorage.InsertError) bool {
	keyDocsPull, keyDocsPullStop := iter.Pull(keyDocs)
	defer keyDocsPullStop()
	pullOk := true
	var kd *types.KeyDoc
	for idx, lastIdx := 0, 0; pullOk; lastIdx = idx {
		totKeyArgs, totSubkeyArgs, totUidArgs := 0, 0, 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]interface{}, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]interface{}, 0, subkeysInBunch*subkeysNumColumns) // *** must be less than 64k arguments ***
		subkeysDocs := make([][]types.SubKeyDoc, uidsInBunch)
		uidsValueStrings := make([]string, 0, uidsInBunch)
		uidsValueArgs := make([]interface{}, 0, uidsInBunch*useridsNumColumns) // *** must be less than 64k arguments ***
		uidDocs := make([][]types.UserIdDoc, uidsInBunch)
		kd, pullOk = keyDocsPull()
		if !pullOk {
			return true
		}
		for i, j, k := 0, 0, 0; pullOk; idx, i = idx+1, i+1 {
			subkeysDocs[idx], uidDocs[idx], _, _ = kd.Refresh() // ignore errors
			lenSKIA := len(subkeysDocs[idx])
			lenUIA := len(uidDocs[idx])
			totKeyArgs += keysNumColumns
			totSubkeyArgs += subkeysNumColumns * lenSKIA
			totUidArgs += useridsNumColumns * lenUIA
			if (totKeyArgs > keysInBunch*keysNumColumns) || (totSubkeyArgs > subkeysInBunch*subkeysNumColumns) {
				totKeyArgs -= keysNumColumns
				totSubkeyArgs -= subkeysNumColumns * lenSKIA
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, $%d::TSVECTOR, $%d::TEXT)",
					i*keysNumColumns+1, i*keysNumColumns+2, i*keysNumColumns+3, i*keysNumColumns+4, i*keysNumColumns+5, i*keysNumColumns+6, i*keysNumColumns+7, i*keysNumColumns+8))
			insTime := time.Now().UTC()
			keysValueArgs = append(keysValueArgs, kd.RFingerprint, "{}",
				insTime, insTime, insTime, kd.MD5, kd.Keywords, kd.VFingerprint)

			for sidx := 0; sidx < lenSKIA; sidx, j = sidx+1, j+1 {
				subkeysValueStrings = append(subkeysValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT)", j*subkeysNumColumns+1, j*subkeysNumColumns+2, j*subkeysNumColumns+3))
				subkeysValueArgs = append(subkeysValueArgs,
					subkeysDocs[idx][sidx].RFingerprint, subkeysDocs[idx][sidx].RSubKeyFp, subkeysDocs[idx][sidx].VSubKeyFp)
			}
			for uidx := 0; uidx < lenUIA; uidx, k = uidx+1, k+1 {
				uidsValueStrings = append(uidsValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT, $%d::INTEGER)", k*useridsNumColumns+1, k*useridsNumColumns+2, k*useridsNumColumns+3, k*useridsNumColumns+4))
				uidsValueArgs = append(uidsValueArgs,
					uidDocs[idx][uidx].RFingerprint, uidDocs[idx][uidx].UidString, uidDocs[idx][uidx].Identity, uidDocs[idx][uidx].Confidence)
			}
			kd, pullOk = keyDocsPull()
		}

		log.Debugf("attempting bulk insertion of %d keys, %d subkeys, %d userids", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
		ok := st.bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings, keysValueArgs, subkeysValueArgs, uidsValueArgs, result)
		if !ok {
			return false
		}
		log.Debugf("%d keys, %d subkeys, %d userids sent to DB...", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
	}
	return true
}

func (st *storage) bulkReindexGetStats(result *hkpstorage.InsertError) int {
	var keysReindexed int
	err := st.QueryRow(bulkCopiedKeysNum).Scan(&keysReindexed)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update reindex stats: %v", err)
		keysReindexed = 0
	}
	return keysReindexed
}

func (st *storage) bulkReindexKeys(result *hkpstorage.InsertError) bool {
	log.Debugf("attempting bulk update of keys, subkeys, userids")
	subkeysOK, useridsOK := true, true
	// subkey batch-processing
	if _, subkeysOK = st.bulkInsertCheckSubkeys(result); !subkeysOK {
		return false
	}
	// userid batch-processing
	if _, useridsOK = st.bulkInsertCheckUserIDs(result); !useridsOK {
		return false
	}

	// We don't clean up dups/orphans because Reindex doesn't delete keys (unlike Reload)
	if log.GetLevel() >= log.DebugLevel {
		// update each table on disk separately, and fail fast to see which transaction failed
		// write to the keys table last, so that reindex will retry on the next pass
		txStrs := []string{bulkTxInsertSubkeys, bulkTxReindexSubkeys}
		msgStrs := []string{"bulkTx-insert-subkeys", "bulkTx-reindex-subkeys"}
		err := st.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex subkeys: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
		txStrs = []string{bulkTxInsertUserIDs, bulkTxReindexUserIDs}
		msgStrs = []string{"bulkTx-insert-userids", "bulk-Tx-reindex-userids"}
		err = st.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex userids: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
		txStrs = []string{bulkTxReindexKeys}
		msgStrs = []string{"bulkTx-reindex-keys"}
		err = st.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex keys: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
	} else {
		// update all tables on-disk in a single transaction
		txStrs := []string{
			bulkTxClearDupSubkeys, bulkTxInsertSubkeys, bulkTxReindexSubkeys,
			bulkTxClearDupUserIDs, bulkTxInsertUserIDs, bulkTxReindexUserIDs,
			bulkTxReindexKeys,
		}
		msgStrs := []string{
			"bulkTx-insert-subkeys", "bulkTx-reindex-subkeys",
			"bulkTx-insert-userids", "bulk-Tx-reindex-userids",
			"bulkTx-reindex-keys",
		}
		err := st.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
	}
	return true
}

func (st *storage) bulkReindex(keyDocs map[string]*types.KeyDoc, result *hkpstorage.InsertError) (int, bool) {
	log.Infof("attempting bulk reindex of %d keys", len(keyDocs))
	// We only use the `keys_copyin` temp table, but reuse the full complement for simplicity.
	err := st.bulkCreateTempTables()
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	defer st.bulkDropTempTables()
	keysReindexed := 0
	if !st.bulkReindexDoCopy(maps.Values(keyDocs), result) {
		return 0, false
	}
	if !st.bulkReindexKeys(result) {
		return 0, false
	}

	keysReindexed = st.bulkReindexGetStats(result)
	err = st.bulkDropTempTables()
	if err != nil {
		result.Errors = append(result.Errors, err)
	}
	return keysReindexed, true
}
