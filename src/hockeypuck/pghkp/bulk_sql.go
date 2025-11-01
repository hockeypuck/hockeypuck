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

//
// SQL statement constants for use by bulk routines
//

// bulkTxFilterUniqueKeys is a key-filtering query, between temporary tables, used for bulk insertion.
// Among all the keys in a call to Insert(..) (usually the keys in a processed key-dump file), this
// filter gets the unique keys, i.e., those with unique rfingerprint *and* unique md5, but *neither*
// with rfingerprint *nor* with md5 that currently exist in the DB.
const bulkTxFilterUniqueKeys string = `INSERT INTO keys_checked (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint)
SELECT rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint FROM keys_copyin kcpinA WHERE
rfingerprint IS NOT NULL AND doc IS NOT NULL AND ctime IS NOT NULL AND mtime IS NOT NULL AND idxtime IS NOT NULL AND md5 IS NOT NULL AND vfingerprint IS NOT NULL AND
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
`INSERT INTO keys_checked (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint)
SELECT rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint FROM keys_copyin WHERE
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
`INSERT INTO subkeys_checked (rfingerprint, rsubfp, vsubfp)
SELECT rfingerprint, rsubfp, vsubfp FROM subkeys_copyin skcpinA WHERE
skcpinA.rfingerprint IS NOT NULL AND skcpinA.rsubfp IS NOT NULL AND skcpinA.vsubfp IS NOT NULL AND
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
rfingerprint IS NULL OR rsubfp IS NULL OR vsubfp IS NULL OR
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
`INSERT INTO subkeys_checked (rfingerprint, rsubfp, vsubfp)
SELECT rfingerprint, rsubfp, vsubfp FROM subkeys_copyin WHERE
ctid IN
   (SELECT ctid FROM
      (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rsubfp ORDER BY ctid) rsubfpEnum FROM subkeys_copyin) AS dupRsubfpTAB
      WHERE rsubfpEnum = 1) AND
NOT EXISTS (SELECT 1 FROM subkeys WHERE subkeys.rsubfp = subkeys_copyin.rsubfp) AND
( EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = subkeys_copyin.rfingerprint) OR
  EXISTS (SELECT 1 FROM keys_copyin  WHERE keys_copyin.rfingerprint  = subkeys_copyin.rfingerprint) )
`

// bulkTxFilterUniqueUserIDs is a userid-filtering query, between temporary tables, used for bulk
// insertion. Among all the userids of keys in a call to Insert(..) (usually the keys in a processed
// key-dump file), this filter gets the unique userids, i.e., those with no NULL fields that are not
// duplicates (unique among userids of keys in this call to Insert(..) that do not currently exist in the DB).
const bulkTxFilterUniqueUserIDs string =
// Enforce foreign key constraint by checking both keys_checked and keys_copyin (instead of keys)
// Avoid checking "EXISTS (SELECT 1 FROM keys WHERE keys.rfingerprint = uidcpinA.rfingerprint)"
// by checking in keys_copyin (despite no indexing): only duplicates (in-file or _in DB_) are
// still in keys_copyin
`INSERT INTO userids_checked (rfingerprint, uidstring, identity, confidence)
SELECT rfingerprint, uidstring, identity, confidence FROM userids_copyin uidcpinA WHERE
uidcpinA.rfingerprint IS NOT NULL AND uidcpinA.uidstring IS NOT NULL AND uidcpinA.confidence IS NOT NULL AND
(SELECT COUNT(*) FROM userids_copyin uidcpinB WHERE uidcpinB.rfingerprint = uidcpinA.rfingerprint AND uidcpinB.uidstring = uidcpinA.uidstring) = 1 AND
NOT EXISTS (SELECT 1 FROM userids WHERE userids.rfingerprint = uidcpinA.rfingerprint AND userids.uidstring = uidcpinA.uidstring) AND
( EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = uidcpinA.rfingerprint) OR
  EXISTS (SELECT 1 FROM keys_copyin  WHERE keys_copyin.rfingerprint  = uidcpinA.rfingerprint) )
`

// bulkTxPrepUserIDStats is a userid-processing query on bulk insertion temporary tables that
// facilitates calculation of statistics on userids and subsequent additional filtering. Out of
// all the userids of keys in a call to Insert(..) (usually the keys in a processed key-dump file),
// this query keeps only duplicates by dropping userids previously set aside by bulkTxFilterUniqueUserIDs
// query and removing any tuples with NULLs.
const bulkTxPrepUserIDStats string = `DELETE FROM userids_copyin WHERE
rfingerprint IS NULL OR uidstring IS NULL OR confidence IS NULL OR
EXISTS (SELECT 1 FROM userids_checked WHERE userids_checked.rfingerprint = userids_copyin.rfingerprint AND userids_checked.uidstring = userids_copyin.uidstring)
`

// bulkTxFilterDupUserIDs is the final userid-filtering query, between temporary tables, used for
// bulk insertion. Among all the userids of keys in a call to Insert(..) (usually the keys in a processed
// key-dump file), this query sets aside for final DB insertion _a single copy_ of those userids that are
// duplicates in the arguments of Insert(..), but do not yet exist in the DB.
const bulkTxFilterDupUserIDs string =
// Enforce foreign key constraint by checking both keys_checked and keys_copyin (instead of keys)
// *** ctid field is PostgreSQL-specific; Oracle has ROWID equivalent field ***
// Avoid checking "EXISTS (SELECT 1 FROM keys WHERE keys.rfingerprint = userids_copyin.rfingerprint)"
// by checking in keys_copyin (despite no indexing): only dups (in-file or _in DB_) still in keys_copyin
`INSERT INTO userids_checked (rfingerprint, uidstring, identity, confidence)
SELECT rfingerprint, uidstring, identity, confidence FROM userids_copyin WHERE
ctid IN
   (SELECT ctid FROM
      (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY uidstring ORDER BY ctid) uidstringEnum FROM userids_copyin) AS dupRsubfpTAB
      WHERE uidstringEnum = 1) AND
NOT EXISTS (SELECT 1 FROM userids WHERE userids.rfingerprint = userids_copyin.rfingerprint AND userids.uidstring = userids_copyin.uidstring) AND
( EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = userids_copyin.rfingerprint) OR
  EXISTS (SELECT 1 FROM keys_copyin  WHERE keys_copyin.rfingerprint  = userids_copyin.rfingerprint) )
`

// bulkTxInsertKeys is the query for final bulk key insertion, from a temporary table to the DB.
const bulkTxInsertKeys string = `INSERT INTO keys (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint)
SELECT rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint FROM keys_checked
`

// bulkTxInsertSubkeys is the query for final bulk subkey insertion, from a temporary table to the DB.
const bulkTxInsertSubkeys string = `INSERT INTO subkeys (rfingerprint, rsubfp, vsubfp)
SELECT rfingerprint, rsubfp, vsubfp FROM subkeys_checked
`

// bulkTxInsertUserIDs is the query for final bulk userid insertion, from a temporary table to the DB.
const bulkTxInsertUserIDs string = `INSERT INTO userids (rfingerprint, uidstring, identity, confidence)
SELECT rfingerprint, uidstring, identity, confidence FROM userids_checked
`

// bulkTxJournalKeys saves the current rows (without json docs) of all the keys about to be updated.
const bulkTxJournalKeys string = `INSERT INTO keys_checked (rfingerprint, doc, md5, ctime, mtime, idxtime, vfingerprint)
SELECT rfingerprint, '{}', md5, ctime, mtime, idxtime, vfingerprint FROM keys WHERE rfingerprint IN ( SELECT rfingerprint FROM keys_copyin )
`

// bulkTxClearOrphanSubkeys deletes all subkeys of keys that are referenced from the keys_old table but are not in the keys_copyin table.
// It MUST be called before calling bulkTxClearKeys (see below).
const bulkTxClearOrphanSubkeys string = `DELETE FROM subkeys WHERE rfingerprint IN
	( SELECT rfingerprint FROM keys_old WHERE rfingerprint NOT IN ( SELECT rfingerprint from keys_copyin ) )
`

// bulkTxClearOrphanUserIDs deletes all userids of keys that are referenced from the keys_old table but are not in the keys_copyin table.
// It MUST be called before calling bulkTxClearKeys (see below).
const bulkTxClearOrphanUserIDs string = `DELETE FROM userids WHERE rfingerprint IN
	( SELECT rfingerprint FROM keys_old WHERE rfingerprint NOT IN ( SELECT rfingerprint from keys_copyin ) )
`

// bulkTxClearKeys deletes all keys that are referenced from the keys_old table but are not in the keys_copyin table.
// You MUST call bulkTxClearOrphanSubkeys and bulkTxClearOrphanUserIDs first (see above).
const bulkTxClearKeys string = `DELETE FROM keys WHERE rfingerprint IN
	( SELECT rfingerprint FROM keys_old WHERE rfingerprint NOT IN ( SELECT rfingerprint from keys_copyin ) )
`

// bulkTxUpdateKeys is the query for final bulk key update, from a temporary table to the DB.
// Does not update ctime or rfingerprint.
const bulkTxUpdateKeys string = `UPDATE keys SET
doc = c.doc, mtime = c.mtime, idxtime = c.idxtime, md5 = c.md5, keywords = c.keywords, vfingerprint = c.vfingerprint
FROM keys_copyin as c
WHERE keys.rfingerprint = c.rfingerprint
`

// bulkTxClearDupSubkeys is the query to clear existing subkey entries from the subkeys table
// if they are not still present in the subkeys_copyin table after deduplication
// (i.e. they would have been queued for addition if they were not already present in subkeys).
const bulkTxClearDupSubkeys string = `DELETE FROM subkeys WHERE rfingerprint IN
	( SELECT rfingerprint FROM subkeys_copyin UNION ALL SELECT rfingerprint FROM subkeys_checked )
	AND rsubfp NOT IN (SELECT rsubfp FROM subkeys_copyin)
`

// bulkTxClearDupUserIDs is the query to clear existing userid entries from the userids table
// if they are not still present in the userids_copyin table after deduplication
// (i.e. they would have been queued for addition if they were not already present in userids).
const bulkTxClearDupUserIDs string = `DELETE FROM userids WHERE rfingerprint IN
	( SELECT rfingerprint FROM userids_copyin UNION ALL SELECT rfingerprint FROM userids_checked )
	AND uidstring NOT IN (SELECT uidstring FROM userids_copyin)
`

// bulkTxReindexKeys is the query for updating the SQL schema only, from a temporary table to the DB.
// We match on the md5 field only, to prevent race conditions (this is safe since md5 is UNIQUE).
const bulkTxReindexKeys string = `UPDATE keys
SET idxtime = keys_copyin.idxtime, keywords = keys_copyin.keywords, vfingerprint = keys_copyin.vfingerprint FROM keys_copyin
WHERE keys.md5 = keys_copyin.md5
`

// bulkTxReindexSubkeys is the query for updating the subkeys table schema to populate the vsubfp column in existing rows.
const bulkTxReindexSubkeys string = `UPDATE subkeys
SET vsubfp = subkeys_copyin.vsubfp FROM subkeys_copyin
WHERE subkeys.rsubfp = subkeys_copyin.rsubfp
`

// bulkTxReindexUserIDs is the query for updating the userids table schema to (re)populate the identity and confidence columns in existing rows.
const bulkTxReindexUserIDs string = `UPDATE userids
SET identity = userids_copyin.identity, confidence = userids_copyin.confidence FROM userids_copyin
WHERE userids.rfingerprint = userids_copyin.rfingerprint AND userids.uidstring = userids_copyin.uidstring
`

// Stats collection queries

const bulkInsNumNullKeys string = `SELECT COUNT (*) FROM keys_copyin WHERE
rfingerprint IS NULL OR doc IS NULL OR ctime IS NULL OR mtime IS NULL OR idxtime IS NULL OR md5 IS NULL
`
const bulkInsNumNullSubkeys string = `SELECT COUNT (*) FROM subkeys_copyin WHERE
rfingerprint IS NULL OR rsubfp IS NULL
`
const bulkInsNumNullUserIDs string = `SELECT COUNT (*) FROM userids_copyin WHERE
rfingerprint IS NULL OR uidstring IS NULL
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
NOT EXISTS (SELECT 1 FROM subkeys_checked WHERE subkeys_checked.rfingerprint = keys_copyin.rfingerprint) AND
NOT EXISTS (SELECT 1 FROM userids_checked WHERE userids_checked.rfingerprint = keys_copyin.rfingerprint)
`
const bulkInsNumPossibleDups string = `SELECT COUNT (*) FROM keys_copyin WHERE
ctid IN
   (SELECT ctid FROM
      (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rfingerprint) rfpEnum FROM keys_copyin) AS dupRfpTAB
      WHERE rfpEnum > 1) AND
EXISTS (SELECT 1 FROM subkeys_checked WHERE subkeys_checked.rfingerprint = keys_copyin.rfingerprint) AND
EXISTS (SELECT 1 FROM userids_checked WHERE userids_checked.rfingerprint = keys_copyin.rfingerprint)
`
const bulkInsertedKeysNum string = `SELECT COUNT (*) FROM keys_checked
`
const bulkInsertedSubkeysNum string = `SELECT COUNT (*) FROM subkeys_checked
`
const bulkInsertedUserIDsNum string = `SELECT COUNT (*) FROM userids_checked
`
const bulkCopiedKeysNum string = `SELECT COUNT (*) FROM keys_copyin
`
const bulkDeletedKeysNum string = `SELECT COUNT (*) FROM keys_old WHERE rfingerprint NOT IN ( SELECT rfingerprint FROM keys_copyin )
`

const bulkInsQueryKeyChange string = `SELECT md5 FROM keys_checked
`

const bulkUpdQueryKeyAdded string = `SELECT md5 FROM keys_copyin WHERE md5 NOT IN (SELECT md5 from keys_checked)
`
const bulkUpdQueryKeyRemoved string = `SELECT md5 FROM keys_checked WHERE md5 NOT IN (SELECT md5 from keys_copyin)
`

const keys_copyin_temp_table_name string = "keys_copyin"
const subkeys_copyin_temp_table_name string = "subkeys_copyin"
const userids_copyin_temp_table_name string = "userids_copyin"
const keys_old_temp_table_name string = "keys_old"

// the following are declared var, but only because we can't have const slices in go

var crTempTablesSQL = []string{
	`CREATE TEMPORARY TABLE IF NOT EXISTS keys_copyin
(
rfingerprint TEXT,
doc jsonb,
ctime TIMESTAMPTZ,
mtime TIMESTAMPTZ,
idxtime TIMESTAMPTZ,
md5 TEXT,
keywords tsvector,
vfingerprint TEXT
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS subkeys_copyin
(
rfingerprint TEXT,
rsubfp TEXT,
vsubfp TEXT
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS userids_copyin
(
rfingerprint TEXT,
uidstring TEXT,
identity TEXT,
confidence INTEGER
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
keywords tsvector,
vfingerprint TEXT NOT NULL UNIQUE
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS subkeys_checked
(
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL PRIMARY KEY,
vsubfp TEXT NOT NULL UNIQUE
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS userids_checked
(
rfingerprint TEXT NOT NULL,
uidstring TEXT NOT NULL,
identity TEXT,
confidence INTEGER NOT NULL,
PRIMARY KEY (rfingerprint, uidstring)
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS keys_old
(
rfingerprint TEXT NOT NULL PRIMARY KEY
)
`,
}

var drTempTablesSQL = []string{
	`DROP TABLE IF EXISTS subkeys_copyin CASCADE
`,
	`DROP TABLE IF EXISTS userids_copyin CASCADE
`,
	`DROP TABLE IF EXISTS keys_copyin CASCADE
`,
	`DROP TABLE IF EXISTS subkeys_checked CASCADE
`,
	`DROP TABLE IF EXISTS userids_checked CASCADE
`,
	`DROP TABLE IF EXISTS keys_checked CASCADE
`,
	`DROP TABLE IF EXISTS keys_old CASCADE
`,
}
