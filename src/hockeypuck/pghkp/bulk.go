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
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//
// Private bulk-update helpers for use by Updater, Reindexer, Reloader etc.
//

// bulkTxFilterUniqueKeys is a key-filtering query, between temporary tables, used for bulk insertion.
// Among all the keys in a call to Insert(..) (usually the keys in a processed key-dump file), this
// filter gets the unique keys, i.e., those with unique rfingerprint *and* unique md5, but *neither*
// with rfingerprint *nor* with md5 that currently exist in the DB.
const bulkTxFilterUniqueKeys string = `INSERT INTO keys_checked (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords) 
SELECT rfingerprint, doc, ctime, mtime, idxtime, md5, keywords FROM keys_copyin kcpinA WHERE 
rfingerprint IS NOT NULL AND doc IS NOT NULL AND ctime IS NOT NULL AND mtime IS NOT NULL AND idxtime IS NOT NULL AND md5 IS NOT NULL AND 
(SELECT COUNT (*) FROM keys_copyin kcpinB WHERE kcpinB.rfingerprint = kcpinA.rfingerprint OR 
                                                kcpinB.md5          = kcpinA.md5) = 1 AND 
NOT EXISTS (SELECT 1 FROM keys WHERE keys.rfingerprint = kcpinA.rfingerprint OR keys.md5 = kcpinA.md5)
`

// bulkTxPrepKeyStats is a key-processing query on bulk insertion temporary tables that facilitates
// calculation of statistics on keys and subsequent additional filtering. Out of all the keys in a
// call to Insert(..) (usually the keys in a processed key-dump file), this query keeps only duplicates
// by dropping keys previously set aside by bulkTxFilterUniqueKeys query and removing any tuples
// with NULLs.
const bulkTxPrepKeyStats string = `DELETE FROM keys_copyin WHERE 
rfingerprint IS NULL OR doc IS NULL OR ctime IS NULL OR mtime IS NULL OR idxtime IS NULL OR md5 IS NULL OR 
EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = keys_copyin.rfingerprint)
`

// bulkTxFilterDupKeys is the final key-filtering query, between temporary tables, used for bulk
// insertion. Among all the keys in a call to Insert(..) (usually the keys in a processed key-dump
// file), this query sets aside for final DB insertion _a single copy_ of those keys that are
// duplicates in the arguments of Insert(..), but do not yet exist in the DB.
const bulkTxFilterDupKeys string =
// *** ctid field is PostgreSQL-specific; Oracle has ROWID equivalent field ***
// ===> If there are different md5 for same rfp, this query allows them into keys_checked: <===
// ===>  ***  an intentional error of non-unique rfp, to revert to normal insertion!  ***  <===
`INSERT INTO keys_checked (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords) 
SELECT rfingerprint, doc, ctime, mtime, idxtime, md5, keywords FROM keys_copyin WHERE 
( ctid IN 
     (SELECT ctid FROM 
        (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rfingerprint ORDER BY ctid) rfpEnum FROM keys_copyin) AS dupRfpTAB 
        WHERE rfpEnum = 1) OR 
  ctid IN 
     (SELECT ctid FROM 
        (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY md5 ORDER BY ctid) md5Enum FROM keys_copyin) AS dupMd5TAB 
        WHERE md5Enum = 1) ) AND 
NOT EXISTS (SELECT 1 FROM keys WHERE keys.rfingerprint = keys_copyin.rfingerprint OR
                                     keys.md5          = keys_copyin.md5)
`

// bulkTxFilterUniqueSubkeys is a subkey-filtering query, between temporary tables, used for bulk
// insertion. Among all the subkeys of keys in a call to Insert(..) (usually the keys in a processed
// key-dump file), this filter gets the unique subkeys, i.e., those with no NULL fields that are not
// duplicates (unique among subkeys of keys in this call to Insert(..) that do not currently exist in the DB).
const bulkTxFilterUniqueSubkeys string =
// Enforce foreign key constraint by checking both keys_checked and keys_copyin (instead of keys)
// Avoid checking "EXISTS (SELECT 1 FROM keys WHERE keys.rfingerprint = skcpinA.rfingerprint)"
// by checking in keys_copyin (despite no indexing): only duplicates (in-file or _in DB_) are
// still in keys_copyin
`INSERT INTO subkeys_checked (rfingerprint, rsubfp) 
SELECT rfingerprint, rsubfp FROM subkeys_copyin skcpinA WHERE 
skcpinA.rfingerprint IS NOT NULL AND skcpinA.rsubfp IS NOT NULL AND 
(SELECT COUNT(*) FROM subkeys_copyin skcpinB WHERE skcpinB.rsubfp = skcpinA.rsubfp) = 1 AND 
NOT EXISTS (SELECT 1 FROM subkeys WHERE subkeys.rsubfp = skcpinA.rsubfp) AND 
( EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = skcpinA.rfingerprint) OR 
  EXISTS (SELECT 1 FROM keys_copyin  WHERE keys_copyin.rfingerprint  = skcpinA.rfingerprint) )
`

// bulkTxPrepSubkeyStats is a subkey-processing query on bulk insertion temporary tables that
// facilitates calculation of statistics on subkeys and subsequent additional filtering. Out of
// all the subkeys of keys in a call to Insert(..) (usually the keys in a processed key-dump file),
// this query keeps only duplicates by dropping subkeys previously set aside by bulkTxFilterUniqueSubkeys
// query and removing any tuples with NULLs.
const bulkTxPrepSubkeyStats string = `DELETE FROM subkeys_copyin WHERE 
rfingerprint IS NULL OR rsubfp IS NULL OR 
EXISTS (SELECT 1 FROM subkeys_checked WHERE subkeys_checked.rsubfp = subkeys_copyin.rsubfp)
`

// bulkTxFilterDupSubkeys is the final subkey-filtering query, between temporary tables, used for
// bulk insertion. Among all the subkeys of keys in a call to Insert(..) (usually the keys in a processed
// key-dump file), this query sets aside for final DB insertion _a single copy_ of those subkeys that are
// duplicates in the arguments of Insert(..), but do not yet exist in the DB.
const bulkTxFilterDupSubkeys string =
// Enforce foreign key constraint by checking both keys_checked and keys_copyin (instead of keys)
// *** ctid field is PostgreSQL-specific; Oracle has ROWID equivalent field ***
// Avoid checking "EXISTS (SELECT 1 FROM keys WHERE keys.rfingerprint = subkeys_copyin.rfingerprint)"
// by checking in keys_copyin (despite no indexing): only dups (in-file or _in DB_) still in keys_copyin
`INSERT INTO subkeys_checked (rfingerprint, rsubfp) 
SELECT rfingerprint, rsubfp FROM subkeys_copyin WHERE 
ctid IN 
   (SELECT ctid FROM 
      (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rsubfp ORDER BY ctid) rsubfpEnum FROM subkeys_copyin) AS dupRsubfpTAB 
      WHERE rsubfpEnum = 1) AND 
NOT EXISTS (SELECT 1 FROM subkeys WHERE subkeys.rsubfp = subkeys_copyin.rsubfp) AND 
( EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = subkeys_copyin.rfingerprint) OR 
  EXISTS (SELECT 1 FROM keys_copyin  WHERE keys_copyin.rfingerprint  = subkeys_copyin.rfingerprint) )
`

// bulkTxInsertKeys is the query for final bulk key insertion, from a temporary table to the DB.
const bulkTxInsertKeys string = `INSERT INTO keys (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords) 
SELECT rfingerprint, doc, ctime, mtime, idxtime, md5, keywords FROM keys_checked
`

// bulkTxInsertSubkeys is the query for final bulk subkey insertion, from a temporary table to the DB.
const bulkTxInsertSubkeys string = `INSERT INTO subkeys (rfingerprint, rsubfp) 
SELECT rfingerprint, rsubfp FROM subkeys_checked
`

// bulkTxJournalKeys saves the current rows (without json docs) of all the keys about to be updated.
const bulkTxJournalKeys string = `INSERT INTO keys_checked (rfingerprint, doc, md5, ctime, mtime, idxtime)
SELECT rfingerprint, '{}', md5, ctime, mtime, idxtime FROM keys WHERE rfingerprint IN ( SELECT rfingerprint FROM keys_copyin )
`

// bulkTxUpdateKeys is the query for final bulk key update, from a temporary table to the DB.
// Does not update ctime or rfingerprint.
const bulkTxUpdateKeys string = `UPDATE keys SET
doc = c.doc, mtime = c.mtime, idxtime = c.idxtime, md5 = c.md5, keywords = c.keywords
FROM keys_copyin as c
WHERE keys.rfingerprint = c.rfingerprint
`

// bulkTxClearSubkeys is the query to clear existing subkey entries from the subkeys table
// if they are not still present in the subkeys_copyin table after deduplication
// (i.e. they would have been queued for addition if they were not already present in subkeys).
const bulkTxClearSubkeys string = `DELETE FROM subkeys WHERE rfingerprint IN
	( SELECT rfingerprint FROM subkeys_copyin UNION ALL SELECT rfingerprint FROM subkeys_checked )
	AND rsubfp NOT IN (SELECT rsubfp FROM subkeys_copyin)
`

// bulkTxReindexKeys is the query for updating the SQL schema only, from a temporary table to the DB.
// We match on the md5 field only, to prevent race conditions (this is safe since md5 is UNIQUE).
const bulkTxReindexKeys string = `UPDATE keys
SET idxtime = keys_copyin.idxtime, keywords = keys_copyin.keywords FROM keys_copyin
WHERE keys.md5 = keys_copyin.md5
`

// Stats collection queries

const bulkInsNumNullKeys string = `SELECT COUNT (*) FROM keys_copyin WHERE 
rfingerprint IS NULL OR doc IS NULL OR ctime IS NULL OR mtime IS NULL OR idxtime IS NULL OR md5 IS NULL
`
const bulkInsNumNullSubkeys string = `SELECT COUNT (*) FROM subkeys_copyin WHERE 
rfingerprint IS NULL OR rsubfp IS NULL
`
const bulkInsNumMinDups string = `SELECT COUNT (*) FROM keys_copyin WHERE 
( ( NOT EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = keys_copyin.rfingerprint OR
                                                 keys_checked.md5          = keys_copyin.md5) AND 
    ctid IN 
       (SELECT ctid FROM 
          (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rfingerprint ORDER BY ctid) rfpEnum FROM keys_copyin) AS dupRfpTAB 
          WHERE rfpEnum = 1) ) OR 
  ctid IN 
     (SELECT ctid FROM 
        (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rfingerprint) rfpEnum FROM keys_copyin) AS dupRfpTAB 
        WHERE rfpEnum > 1) ) AND 
NOT EXISTS (SELECT 1 FROM subkeys_checked WHERE subkeys_checked.rfingerprint = keys_copyin.rfingerprint)
`
const bulkInsNumPossibleDups string = `SELECT COUNT (*) FROM keys_copyin WHERE 
ctid IN 
   (SELECT ctid FROM 
      (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rfingerprint) rfpEnum FROM keys_copyin) AS dupRfpTAB 
      WHERE rfpEnum > 1) AND 
EXISTS (SELECT 1 FROM subkeys_checked WHERE subkeys_checked.rfingerprint = keys_copyin.rfingerprint)
`
const bulkInsertedKeysNum string = `SELECT COUNT (*) FROM keys_checked
`
const bulkInsertedSubkeysNum string = `SELECT COUNT (*) FROM subkeys_checked
`
const bulkCopiedKeysNum string = `SELECT COUNT (*) FROM keys_copyin
`

const bulkInsQueryKeyChange string = `SELECT md5 FROM keys_checked
`

const bulkUpdQueryKeyAdded string = `SELECT md5 FROM keys_copyin WHERE md5 NOT IN (SELECT md5 from keys_checked)
`
const bulkUpdQueryKeyRemoved string = `SELECT md5 FROM keys_checked WHERE md5 NOT IN (SELECT md5 from keys_copyin)
`

const keys_copyin_temp_table_name string = "keys_copyin"
const subkeys_copyin_temp_table_name string = "subkeys_copyin"

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

// minKeys2UseBulk is the minimum number of keys in a call to Insert(..) that
// will trigger a bulk insertion. Otherwise, Insert(..) preceeds one key at a time.
const minKeys2UseBulk int = 3500

var crTempTablesSQL = []string{
	`CREATE TEMPORARY TABLE IF NOT EXISTS keys_copyin
(
rfingerprint TEXT,
doc jsonb,
ctime TIMESTAMPTZ,
mtime TIMESTAMPTZ,
idxtime TIMESTAMPTZ,
md5 TEXT,
keywords tsvector
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS subkeys_copyin
(
rfingerprint TEXT,
rsubfp TEXT
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS keys_checked
(
rfingerprint TEXT NOT NULL PRIMARY KEY,
doc jsonb NOT NULL,
ctime TIMESTAMPTZ NOT NULL,
mtime TIMESTAMPTZ NOT NULL,
idxtime TIMESTAMPTZ NOT NULL,
md5 TEXT NOT NULL UNIQUE,
keywords tsvector
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS subkeys_checked
(
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL PRIMARY KEY
)
`,
}

var drTempTablesSQL = []string{
	`DROP TABLE IF EXISTS subkeys_copyin CASCADE
`,
	`DROP TABLE IF EXISTS keys_copyin CASCADE
`,
	`DROP TABLE IF EXISTS subkeys_checked CASCADE
`,
	`DROP TABLE IF EXISTS keys_checked CASCADE
`,
}

func (st *storage) bulkInsertGetStats(result *hkpstorage.InsertError) (int, int, int, int) {
	var maxDups, minDups, keysInserted, subkeysInserted int
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
	return maxDups, minDups, keysInserted, subkeysInserted
}

func (st *storage) bulkUpdateGetStats(result *hkpstorage.InsertError) (int, int) {
	var keysUpdated, subkeysInserted int
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
	return keysUpdated, subkeysInserted
}

func (st *storage) bulkExecSingleTx(bulkJobString, jobDesc []string) (err error) {
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
	return err
}

func (st *storage) bulkInsertCheckSubkeys(result *hkpstorage.InsertError) (nullTuples int, ok bool) {
	// NULLs stats
	var numNulls int
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
		return 0, false
	}
	return numNulls, true
}

func (st *storage) bulkInsertCheckKeys(result *hkpstorage.InsertError) (n int, ok bool) {
	// NULLs stats
	var numNulls int
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
		return 0, false
	}
	return numNulls, true
}

func (st *storage) bulkInsertCheckedKeysSubkeys(result *hkpstorage.InsertError) (nullKeys, nullSubkeys int, ok bool) {
	keysOK, subkeysOK := true, true
	// key batch-processing
	if nullKeys, keysOK = st.bulkInsertCheckKeys(result); !keysOK {
		return 0, 0, false
	}
	// subkey batch-processing
	if nullSubkeys, subkeysOK = st.bulkInsertCheckSubkeys(result); !subkeysOK {
		return 0, 0, false
	}

	// Batch INSERT all checked-for-constraints keys from memory tables (should need no checks!!!!)
	// Final batch-insertion in keys/subkeys tables without any checks: _must not_ give any errors
	txStrs := []string{bulkTxInsertKeys, bulkTxInsertSubkeys}
	msgStrs := []string{"bulkTx-insert-keys", "bulkTx-insert-subkeys"}
	err := st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, 0, false
	}
	return nullKeys, nullSubkeys, true
}

// bulkUpdateKeysSubkeys updates a bunch of keys in-place.
// It is similar to bulkInsertCheckedKeysSubkeys but performs no checks on keys (we assume the DB is already sane)
// We still have to check for duplicate subkeys, as these are not stripped from the json docs.
func (st *storage) bulkUpdateKeysSubkeys(result *hkpstorage.InsertError) (nullSubkeys int, ok bool) {
	subkeysOK := true
	// subkey batch-processing
	if nullSubkeys, subkeysOK = st.bulkInsertCheckSubkeys(result); !subkeysOK {
		return 0, false
	}

	// Batch UPDATE all keys from memory tables (should need no checks!!!!)
	// Final batch-update in keys/subkeys tables without any checks: _must not_ give any errors
	txStrs := []string{bulkTxJournalKeys, bulkTxUpdateKeys, bulkTxClearSubkeys, bulkTxInsertSubkeys}
	msgStrs := []string{"bulkTx-journal-keys", "bulkTx-update-keys", "bulkTx-clear-subkeys", "bulkTx-insert-subkeys"}
	err := st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	return nullSubkeys, true
}

func (st *storage) bulkInsertSendBunchTx(keystmt, msgSpec string, keysValueArgs []interface{}) (err error) {
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
		return errors.WithStack(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(keysValueArgs...) // All keys in bunch
	if err != nil {
		return errors.Wrapf(err, "cannot simply send a bunch of %s to server (too large bunch?)", msgSpec)
	}
	return nil
}

type keyInsertArgs struct {
	RFingerprint *string
	jsonStrDoc   *string
	MD5          *string
	keywords     *string
}
type subkeyInsertArgs struct {
	keyRFingerprint    *string
	subkeyRFingerprint *string
}

// Insert keys & subkeys to in-mem tables with no constraints at all: should have no errors!
func (st *storage) bulkInsertDoCopy(keyInsArgs []keyInsertArgs, skeyInsArgs [][]subkeyInsertArgs,
	result *hkpstorage.InsertError) (ok bool) {
	lenKIA := len(keyInsArgs)
	for idx, lastIdx := 0, 0; idx < lenKIA; lastIdx = idx {
		totKeyArgs, totSubkeyArgs := 0, 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]interface{}, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]interface{}, 0, subkeysInBunch*subkeysNumColumns) // *** must be less than 64k arguments ***
		for i, j := 0, 0; idx < lenKIA; idx, i = idx+1, i+1 {
			lenSKIA := len(skeyInsArgs[idx])
			totKeyArgs += keysNumColumns
			totSubkeyArgs += subkeysNumColumns * lenSKIA
			if (totKeyArgs > keysInBunch*keysNumColumns) || (totSubkeyArgs > subkeysInBunch*subkeysNumColumns) {
				totKeyArgs -= keysNumColumns
				totSubkeyArgs -= subkeysNumColumns * lenSKIA
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, $%d::TSVECTOR)",
					i*keysNumColumns+1, i*keysNumColumns+2, i*keysNumColumns+3, i*keysNumColumns+4, i*keysNumColumns+5, i*keysNumColumns+6, i*keysNumColumns+7))
			insTime := time.Now().UTC()
			keysValueArgs = append(keysValueArgs, *keyInsArgs[idx].RFingerprint, *keyInsArgs[idx].jsonStrDoc,
				insTime, insTime, insTime, *keyInsArgs[idx].MD5, *keyInsArgs[idx].keywords)

			for sidx := 0; sidx < lenSKIA; sidx, j = sidx+1, j+1 {
				subkeysValueStrings = append(subkeysValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT)", j*subkeysNumColumns+1, j*subkeysNumColumns+2))
				subkeysValueArgs = append(subkeysValueArgs,
					*skeyInsArgs[idx][sidx].keyRFingerprint, *skeyInsArgs[idx][sidx].subkeyRFingerprint)
			}
		}
		log.Debugf("attempting bulk insertion of %d keys and a total of %d subkeys!", idx-lastIdx, totSubkeyArgs>>1)

		// Send all keys to in-mem tables to the pg server; *no constraints checked*
		keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords) VALUES %s",
			keys_copyin_temp_table_name, strings.Join(keysValueStrings, ","))
		err := st.bulkInsertSendBunchTx(keystmt, "keys", keysValueArgs)
		if err != nil {
			result.Errors = append(result.Errors, err)
			return false
		}

		// Send all subkeys to in-mem tables to the pg server; *no constraints checked*
		subkeystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, rsubfp) VALUES %s",
			subkeys_copyin_temp_table_name, strings.Join(subkeysValueStrings, ","))
		err = st.bulkInsertSendBunchTx(subkeystmt, "subkeys", subkeysValueArgs)
		if err != nil {
			result.Errors = append(result.Errors, err)
			return false
		}

		log.Debugf("%d keys, %d subkeys sent to DB...", idx-lastIdx, totSubkeyArgs>>1)
	}
	return true
}

func (st *storage) bulkInsertCopyKeysToServer(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError) (int, bool) {
	var key *openpgp.PrimaryKey
	keyInsArgs := make([]keyInsertArgs, 0, len(keys))
	skeyInsArgs := make([][]subkeyInsertArgs, 0, len(keys))
	jsonStrs, theKeywords := make([]string, len(keys)), make([]string, len(keys))

	unprocessed, sidx, i := 0, 0, 0
	for _, key = range keys {
		openpgp.Sort(key)
		jsonKey := jsonhkp.NewPrimaryKey(key)
		jsonBuf, err := json.Marshal(jsonKey)
		if err != nil {
			result.Errors = append(result.Errors,
				errors.Wrapf(err, "pre-processing cannot serialize rfp=%q", key.RFingerprint))
			unprocessed++
			continue
		}
		jsonStrs[i], theKeywords[i] = string(jsonBuf), types.KeywordsTSVector(key)
		keyInsArgs = keyInsArgs[:i+1] // re-slice +1
		keyInsArgs[i] = keyInsertArgs{&key.RFingerprint, &jsonStrs[i], &key.MD5, &theKeywords[i]}

		skeyInsArgs = skeyInsArgs[:i+1] // re-slice +1
		skeyInsArgs[i] = make([]subkeyInsertArgs, 0, len(key.SubKeys))
		for sidx = 0; sidx < len(key.SubKeys); sidx++ {
			skeyInsArgs[i] = skeyInsArgs[i][:sidx+1] // re-slice +1
			skeyInsArgs[i][sidx] = subkeyInsertArgs{&key.RFingerprint, &key.SubKeys[sidx].RFingerprint}
		}
		i++
	}
	ok := st.bulkInsertDoCopy(keyInsArgs, skeyInsArgs, result)
	return unprocessed, ok
}

func (st *storage) bulkDropTempTables() error {
	// Drop the 2 pairs (all) of temporary tables
	err := st.bulkExecSingleTx(drTempTablesSQL, sqlDesc(drTempTablesSQL))
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (st *storage) bulkCreateTempTables() error {
	err := st.bulkExecSingleTx(crTempTablesSQL, sqlDesc(crTempTablesSQL))
	if err != nil {
		return errors.Wrap(err, "cannot drop temporary tables")
	}
	return nil
}

func (st *storage) bulkInsert(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError, update bool) (int, bool) {
	log.Infof("attempting bulk insertion of keys")
	t := time.Now() // FIXME: Remove this
	// Create 2 pairs of _temporary_ (in-mem) tables:
	// (a) keys_copyin, subkeys_copyin
	// (b) keys_checked, subkeys_checked
	err := st.bulkCreateTempTables()
	if err != nil {
		// This should always be possible (maybe, out-of-memory?)
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	defer st.bulkDropTempTables()
	keysWithNulls, subkeysWithNulls, ok := 0, 0, true
	maxDups, minDups, keysInserted, subkeysInserted := 0, 0, 0, 0
	// (a): Send *all* keys to in-mem tables on the pg server; *no constraints checked*
	if _, ok = st.bulkInsertCopyKeysToServer(keys, result); !ok {
		return 0, false
	}
	if update {
		// (b): From _copyin tables update existing on-disk records
		//      check subkey constraints only
		if subkeysWithNulls, ok = st.bulkUpdateKeysSubkeys(result); !ok {
			return 0, false
		}
		keysInserted, subkeysInserted = st.bulkUpdateGetStats(result)
		err = st.BulkNotify(bulkUpdQueryKeyAdded, bulkUpdQueryKeyRemoved)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
	} else {
		// (b): From _copyin tables (still only to in-mem table) remove duplicates
		//      check *all* constraints & RollBack insertions of key/subkeys that err
		if keysWithNulls, subkeysWithNulls, ok = st.bulkInsertCheckedKeysSubkeys(result); !ok {
			return 0, false
		}
		maxDups, minDups, keysInserted, subkeysInserted = st.bulkInsertGetStats(result)
		err = st.BulkNotify(bulkInsQueryKeyChange)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
	}

	if minDups == maxDups {
		log.Infof("%d keys and %d subkeys bulk-inserted, %d duplicates skipped (%d keys and %d subkeys with NULLs) in %v",
			keysInserted, subkeysInserted, minDups, keysWithNulls, subkeysWithNulls, time.Since(t))
	} else {
		log.Infof("%d keys and %d subkeys bulk-inserted, at least %d (and up to %d possible) duplicates skipped "+
			"(%d keys and %d subkeys with NULLs) in %v",
			keysInserted, subkeysInserted, minDups, maxDups, keysWithNulls, subkeysWithNulls, time.Since(t))
	}

	err = st.bulkDropTempTables()
	if err != nil {
		// Temporary tables with previous data may lead to errors,
		// when attempting insertion of duplicates, in next file,
		// but may be resolved for the subsequent file(s)
		result.Errors = append(result.Errors, err)
	}
	// FIXME: Imitate returning duplicates for reporting. Can be removed.
	result.Duplicates = make([]*openpgp.PrimaryKey, minDups)
	return keysInserted, true
}
