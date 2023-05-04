/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"

	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	log "hockeypuck/logrus"
	"hockeypuck/openpgp"
)

const (
	maxInsertErrors = 100
)

type storage struct {
	*sql.DB
	dbName  string
	options []openpgp.KeyReaderOption

	mu        sync.Mutex
	listeners []func(hkpstorage.KeyChange) error
}

var _ hkpstorage.Storage = (*storage)(nil)

var crTablesSQL = []string{
	`CREATE TABLE IF NOT EXISTS keys (
rfingerprint TEXT NOT NULL PRIMARY KEY,
doc jsonb NOT NULL,
ctime TIMESTAMP WITH TIME ZONE NOT NULL,
mtime TIMESTAMP WITH TIME ZONE NOT NULL,
md5 TEXT NOT NULL UNIQUE,
keywords tsvector
)`,
	`CREATE TABLE IF NOT EXISTS subkeys (
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL PRIMARY KEY,
FOREIGN KEY (rfingerprint) REFERENCES keys(rfingerprint)
)`,
	`CREATE TABLE IF NOT EXISTS blacklist (
rfingerprint TEXT NOT NULL,
purge BOOLEAN NOT NULL,
comment TEXT,
ctime TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
)`,
}

var crIndexesSQL = []string{
	`CREATE INDEX IF NOT EXISTS keys_rfp ON keys(rfingerprint text_pattern_ops);`,
	`CREATE INDEX IF NOT EXISTS keys_ctime ON keys(ctime);`,
	`CREATE INDEX IF NOT EXISTS keys_mtime ON keys(mtime);`,
	`CREATE INDEX IF NOT EXISTS keys_keywords ON keys USING gin(keywords);`,
	`CREATE INDEX IF NOT EXISTS subkeys_rfp ON subkeys(rsubfp text_pattern_ops);`,
	`CREATE INDEX IF NOT EXISTS blacklist_ctime ON blacklist(ctime);`,
}

// NB: this function is unused, and won't work anyway because it refers to
// obsolete constraint names that hockeypuck no longer creates since @51cc758
var drConstraintsSQL = []string{
	`ALTER TABLE keys DROP CONSTRAINT keys_pk;`,
	`ALTER TABLE keys DROP CONSTRAINT keys_md5;`,
	`DROP INDEX keys_rfp;`,
	`DROP INDEX keys_ctime;`,
	`DROP INDEX keys_mtime;`,
	`DROP INDEX keys_keywords;`,

	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_pk;`,
	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_fk;`,
	`DROP INDEX subkeys_rfp;`,

	`DROP INDEX blacklist_ctime;`,
}

var crTempTablesSQL = []string{
	`CREATE TEMPORARY TABLE IF NOT EXISTS keys_copyin (
rfingerprint TEXT,
doc jsonb,
ctime TIMESTAMP WITH TIME ZONE,
mtime TIMESTAMP WITH TIME ZONE,
md5 TEXT,
keywords tsvector
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS subkeys_copyin (
rfingerprint TEXT,
rsubfp TEXT
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS keys_checked (
rfingerprint TEXT NOT NULL PRIMARY KEY,
doc jsonb NOT NULL,
ctime TIMESTAMP WITH TIME ZONE NOT NULL,
mtime TIMESTAMP WITH TIME ZONE NOT NULL,
md5 TEXT NOT NULL UNIQUE,
keywords tsvector
)
`,
	`CREATE TEMPORARY TABLE IF NOT EXISTS subkeys_checked (
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

// bulkTxFilterUniqueKeys is a key-filtering quyery, between temporary tables, used for bulk insertion.
// Among all the keys in a call to Insert(..) (usually the keys in a processed key-dump file), this
// filter gets the unique keys, i.e., those with unique rfingerprint *and* unique md5, but *neither*
// with rfingerprint *nor* with md5 that currently exist in the DB, *nor* with rfingerprint in the blacklist.
const bulkTxFilterUniqueKeys string = `INSERT INTO keys_checked (rfingerprint, doc, ctime, mtime, md5, keywords) 
SELECT rfingerprint, doc, ctime, mtime, md5, keywords FROM keys_copyin kcpinA WHERE 
rfingerprint IS NOT NULL AND doc IS NOT NULL AND ctime IS NOT NULL AND mtime IS NOT NULL AND md5 IS NOT NULL AND 
(SELECT COUNT (*) FROM keys_copyin kcpinB WHERE kcpinB.rfingerprint = kcpinA.rfingerprint OR 
                                                kcpinB.md5          = kcpinA.md5) = 1 AND 
NOT EXISTS (SELECT 1 FROM      keys WHERE         keys.rfingerprint = kcpinA.rfingerprint OR 
	                                              keys.md5          = kcpinA.md5             ) AND
NOT EXISTS (SELECT 1 FROM blacklist WHERE    blacklist.rfingerprint = kcpinA.rfingerprint)
`

// bulkTxPrepKeyStats is a key-processing query on bulk insertion temporary tables that facilitates
// calculation of statistics on keys and subsequent additional filtering. Out of all the keys in a
// call to Insert(..) (usually the keys in a processed key-dump file), this query keeps only duplicates
// by dropping keys previously set aside by bulkTxFilterUniqueKeys query and removing any tuples
// with NULLs.
const bulkTxPrepKeyStats string = `DELETE FROM keys_copyin WHERE 
rfingerprint IS NULL OR doc IS NULL OR ctime IS NULL OR mtime IS NULL OR md5 IS NULL OR 
EXISTS (SELECT 1 FROM keys_checked WHERE keys_checked.rfingerprint = keys_copyin.rfingerprint)
`

// bulkTxFilterDupKeys is the final key-filtering query, between temporary tables, used for bulk
// insertion. Among all the keys in a call to Insert(..) (usually the keys in a processed key-dump
// file), this query sets aside for final DB insertion _a single copy_ of those keys that are
// duplicates in the arguments of Insert(..), but do not yet exist in the DB or blacklist.
const bulkTxFilterDupKeys string =
// *** ctid field is PostgreSQL-specific; Oracle has ROWID equivalent field ***
// ===> If there are different md5 for same rfp, this query allows them into keys_checked: <===
// ===>  ***  an intentional error of non-unique rfp, to revert to normal insertion!  ***  <===
`INSERT INTO keys_checked (rfingerprint, doc, ctime, mtime, md5, keywords) 
SELECT rfingerprint, doc, ctime, mtime, md5, keywords FROM keys_copyin WHERE 
( ctid IN 
     (SELECT ctid FROM 
        (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY rfingerprint ORDER BY ctid) rfpEnum FROM keys_copyin) AS dupRfpTAB 
        WHERE rfpEnum = 1) OR 
  ctid IN 
     (SELECT ctid FROM 
        (SELECT ctid, ROW_NUMBER() OVER (PARTITION BY md5 ORDER BY ctid) md5Enum FROM keys_copyin) AS dupMd5TAB 
        WHERE md5Enum = 1) ) AND 
NOT EXISTS (SELECT 1 FROM      keys WHERE      keys.rfingerprint = keys_copyin.rfingerprint OR
                                               keys.md5          = keys_copyin.md5             ) AND
NOT EXISTS (SELECT 1 FROM blacklist WHERE blacklist.rfingerprint = keys_copyin.rfingerprint)
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

// bulkTxInsertKeys is the query for final bulk key insertion, from a tmporary table to the DB.
const bulkTxInsertKeys string = `INSERT INTO keys (rfingerprint, doc, ctime, mtime, md5, keywords) 
SELECT rfingerprint, doc, ctime, mtime, md5, keywords FROM keys_checked
`

// bulkTxInsertSubkeys is the query for final bulk subkey insertion, from a tmporary table to the DB.
const bulkTxInsertSubkeys string = `INSERT INTO subkeys (rfingerprint, rsubfp) 
SELECT rfingerprint, rsubfp FROM subkeys_checked
`

// Stats collection queries

const bulkInsNumNullKeys string = `SELECT COUNT (*) FROM keys_copyin WHERE 
rfingerprint IS NULL OR doc IS NULL OR ctime IS NULL OR mtime IS NULL OR md5 IS NULL
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

const bulkInsQueryKeyChange string = `SELECT md5 FROM keys_checked
`

const keys_copyin_temp_table_name string = "keys_copyin"
const subkeys_copyin_temp_table_name string = "subkeys_copyin"

// keysInBunch is the maximum number of keys sent in a bunch during bulk insertion.
// Since keys (and subkeys) are sent to the DB in prepared statements with parameters and
// each key requires 6 parameters, 6 x keysInBunch < 65536 must hold (keysInBunch <= ~10900).
// 64k (2-byte parameter count) is the current protocol limit for client communication,
// of prepared statements in PostreSQL v13 (see Bind message in
// https://www.postgresql.org/docs/current/protocol-message-formats.html).
const keysInBunch int = 5000

// subkeysInBunch is the maximum number of subkeys sent in a bunch (for at most
// keysInBunch keys sent in a bunch) during bulk insertion. Each subkey requires 2
// parameters, so less than 32k subkeys can fit in a bunch (see keysInBunch).
const subkeysInBunch int = 32000

// minKeys2UseBulk is the minimum number of keys in a call to Insert(..) that
// will trigger a bulk insertion. Otherwise, Insert(..) preceeds one key at a time.
const minKeys2UseBulk int = 3500

// Dial returns PostgreSQL storage connected to the given database URL.
func Dial(url string, options []openpgp.KeyReaderOption) (hkpstorage.Storage, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return New(db, options)
}

// New returns a PostgreSQL storage implementation for an HKP service.
func New(db *sql.DB, options []openpgp.KeyReaderOption) (hkpstorage.Storage, error) {
	st := &storage{
		DB:      db,
		options: options,
	}
	err := st.createTables()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create tables")
	}
	err = st.createIndexes()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create indexes")
	}
	return st, nil
}

func (st *storage) createTables() error {
	for _, crTableSQL := range crTablesSQL {
		_, err := st.Exec(crTableSQL)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func (st *storage) createIndexes() error {
	for _, crIndexSQL := range crIndexesSQL {
		_, err := st.Exec(crIndexSQL)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

type keyDoc struct {
	RFingerprint string
	CTime        time.Time
	MTime        time.Time
	MD5          string
	Doc          string
	Keywords     []string
}

func (st *storage) MatchMD5(md5s []string) ([]string, error) {
	var md5In []string
	for _, md5 := range md5s {
		// Must validate to prevent SQL injection since we're appending SQL strings here.
		_, err := hex.DecodeString(md5)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid MD5 %q", md5)
		}
		md5In = append(md5In, "'"+strings.ToLower(md5)+"'")
	}

	sqlStr := fmt.Sprintf("SELECT rfingerprint FROM keys WHERE md5 IN (%s)", strings.Join(md5In, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []string
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err := rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return result, nil
}

// Resolve implements storage.Storage.
//
// Only v4 key IDs are resolved by this backend. v3 short and long key IDs
// currently won't match.
func (st *storage) Resolve(keyids []string) (_ []string, retErr error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM keys WHERE rfingerprint LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	var subKeyIDs []string
	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		var rfp string
		row := stmt.QueryRow(keyid)
		err = row.Scan(&rfp)
		if err == sql.ErrNoRows {
			subKeyIDs = append(subKeyIDs, keyid)
		} else if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}

	if len(subKeyIDs) > 0 {
		subKeyResult, err := st.resolveSubKeys(subKeyIDs)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, subKeyResult...)
	}

	return result, nil
}

func (st *storage) resolveSubKeys(keyids []string) ([]string, error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM subkeys WHERE rsubfp LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		var rfp string
		row := stmt.QueryRow(keyid)
		err = row.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}

	return result, nil
}

func (st *storage) MatchKeyword(search []string) ([]string, error) {
	var result []string
	stmt, err := st.Prepare("SELECT rfingerprint FROM keys WHERE keywords @@ plainto_tsquery($1) LIMIT $2")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	for _, term := range search {
		err = func() error {
			rows, err := stmt.Query(term, 100)
			if err != nil {
				return errors.WithStack(err)
			}
			defer rows.Close()
			for rows.Next() {
				var rfp string
				err = rows.Scan(&rfp)
				if err != nil && err != sql.ErrNoRows {
					return errors.WithStack(err)
				}
				result = append(result, rfp)
			}
			err = rows.Err()
			if err != nil {
				return errors.WithStack(err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (st *storage) ModifiedSince(t time.Time) ([]string, error) {
	var result []string
	rows, err := st.Query("SELECT rfingerprint FROM keys WHERE mtime > $1 ORDER BY mtime DESC LIMIT 100", t.UTC())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err = rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return result, nil
}

func (st *storage) FetchKeys(rfps []string) ([]*openpgp.PrimaryKey, error) {
	if len(rfps) == 0 {
		return nil, nil
	}

	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT doc FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*openpgp.PrimaryKey
	defer rows.Close()
	for rows.Next() {
		var bufStr string
		err = rows.Scan(&bufStr)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := readOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, key)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

func (st *storage) FetchKeyrings(rfps []string) ([]*hkpstorage.Keyring, error) {
	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT ctime, mtime, doc FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*hkpstorage.Keyring
	defer rows.Close()
	for rows.Next() {
		var bufStr string
		var kr hkpstorage.Keyring
		err = rows.Scan(&bufStr, &kr.CTime, &kr.MTime)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := readOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		kr.PrimaryKey = key
		result = append(result, &kr)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

func readOneKey(b []byte, rfingerprint string) (*openpgp.PrimaryKey, error) {
	kr := openpgp.NewKeyReader(bytes.NewBuffer(b))
	keys, err := kr.Read()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(keys) == 0 {
		return nil, nil
	} else if len(keys) > 1 {
		return nil, errors.Errorf("multiple keys in keyring: %v, %v", keys[0].Fingerprint(), keys[1].Fingerprint())
	}
	if keys[0].RFingerprint != rfingerprint {
		return nil, errors.Errorf("RFingerprint mismatch: expected=%q got=%q",
			rfingerprint, keys[0].RFingerprint)
	}
	return keys[0], nil
}

func (st *storage) upsertKeyOnInsert(pubkey *openpgp.PrimaryKey) (kc hkpstorage.KeyChange, err error) {
	var lastKey *openpgp.PrimaryKey
	lastKeys, err := st.FetchKeys([]string{pubkey.RFingerprint})
	if err == nil {
		// match primary fingerprint -- someone might have reused a subkey somewhere
		err = hkpstorage.ErrKeyNotFound
		for _, key := range lastKeys {
			if key.RFingerprint == pubkey.RFingerprint {
				lastKey, err = key, nil
				break
			}
		}
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if pubkey.UUID != lastKey.UUID {
		return nil, errors.Errorf("upsert key %q lookup failed, found mismatch %q", pubkey.UUID, lastKey.UUID)
	}
	lastID := lastKey.KeyID()
	lastMD5 := lastKey.MD5
	err = openpgp.Merge(lastKey, pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if lastMD5 != lastKey.MD5 {
		err = st.Update(lastKey, lastID, lastMD5)
		if err == errTargetMissing {
			// propagate verbatim so it can be handled
			return nil, err
		} else if err != nil {
			return nil, errors.WithStack(err)
		}
		return hkpstorage.KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: lastKey.KeyID(), NewDigest: lastKey.MD5}, nil
	}
	return hkpstorage.KeyNotChanged{ID: lastID, Digest: lastMD5}, nil
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

func (st *storage) insertKeyTx(tx *sql.Tx, key *openpgp.PrimaryKey) (needUpsert bool, retErr error) {
	stmt, err := tx.Prepare("INSERT INTO keys (rfingerprint, ctime, mtime, md5, doc, keywords) " +
		"SELECT $1::TEXT, $2::TIMESTAMP, $3::TIMESTAMP, $4::TEXT, $5::JSONB, to_tsvector($6) " +
		"WHERE NOT EXISTS (SELECT 1 FROM keys WHERE rfingerprint = $1) " +
		"AND NOT EXISTS (SELECT 1 FROM blacklist WHERE rfingerprint = $1)")
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer stmt.Close()

	subStmt, err := tx.Prepare("INSERT INTO subkeys (rfingerprint, rsubfp) " +
		"SELECT $1::TEXT, $2::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)")
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer subStmt.Close()

	openpgp.Sort(key)

	now := time.Now().UTC()
	jsonKey := jsonhkp.NewPrimaryKey(key)
	jsonBuf, err := json.Marshal(jsonKey)
	if err != nil {
		return false, errors.Wrapf(err, "cannot serialize rfp=%q", key.RFingerprint)
	}

	jsonStr := string(jsonBuf)
	keywords := keywordsTSVector(key)
	result, err := stmt.Exec(&key.RFingerprint, &now, &now, &key.MD5, &jsonStr, &keywords)
	if err != nil {
		return false, errors.Wrapf(err, "cannot insert rfp=%q", key.RFingerprint)
	}

	var keysInserted int64
	if keysInserted, err = result.RowsAffected(); err != nil {
		// We arrive here if the DB driver doesn't support
		// RowsAffected, although lib/pq is known to support it.
		// If it doesn't, then something has gone badly awry!
		return false, errors.Wrapf(err, "rows affected not available when inserting rfp=%q", key.RFingerprint)
	}
	if keysInserted == 0 {
		return true, nil
	}

	for _, subKey := range key.SubKeys {
		_, err := subStmt.Exec(&key.RFingerprint, &subKey.RFingerprint)
		if err != nil {
			return false, errors.Wrapf(err, "cannot insert rsubfp=%q", subKey.RFingerprint)
		}
	}
	return false, nil
}

func (st *storage) bulkInsertGetStats(result *hkpstorage.InsertError) (int, int, int, int) {
	var maxDups, minDups, keysInserted, subkeysInserted int
	// Get Duplicate stats
	err := st.QueryRow(bulkInsNumMinDups).Scan(&minDups)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warn("Error querying duplicate keys. Stats may be inaccurate.")
		minDups = 0
	}
	// In-file duplicates may be duplicates even if we insert a subkey for a key's rfp
	// FIXME: This might be costly and could be removed...
	err = st.QueryRow(bulkInsNumPossibleDups).Scan(&maxDups)
	maxDups += minDups
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warn("Error querying duplicate keys. Stats may be inaccurate.")
		maxDups = 0
	}
	// Get keys/subkeys inserted
	err = st.QueryRow(bulkInsertedKeysNum).Scan(&keysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warn("Error querying keys inserted. Stats may be inaccurate.")
		keysInserted = 0
	}
	err = st.QueryRow(bulkInsertedSubkeysNum).Scan(&subkeysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warn("Error querying subkeys inserted. Stats may be inaccurate.")
		subkeysInserted = 0
	}
	return maxDups, minDups, keysInserted, subkeysInserted
}

func (st *storage) bulkInsertSingleTx(bulkJobString, jobDesc []string) (err error) {
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
		_, err = bulkTxStmt.Exec()
		if err != nil {
			return errors.Wrapf(err, "issuing DB server job %s", jobDesc[i])
		}
		err = bulkTxStmt.Close()
		if err != nil {
			return errors.Wrapf(err, "closing DB server job %s", jobDesc[i])
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
		log.Warn("Error querying subkeys with NULLs. Stats may be inaccurate.")
	}

	// (1) Itermediate insert: no NULL fields & no Duplicates (in-file or in DB)
	// (2) Keep only subkeys with Duplicates in subkeys_copyin:
	//     Delete 1st-stage checked subkeys above & those with NULL fields
	// (3) Single-copy of in-file Dups but not in-DB Dups
	txStrs := []string{bulkTxFilterUniqueSubkeys, bulkTxPrepSubkeyStats, bulkTxFilterDupSubkeys}
	msgStrs := []string{"bulkTx-filter-unique-subkeys", "bulkTx-prep-subkeys-stats", "bulkTx-filter-dup-subkeys"}
	err = st.bulkInsertSingleTx(txStrs, msgStrs)
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
		log.Warn("Error querying keys with NULLs. Stats may be inaccurate.")
	}

	// (1) rfingerprint & md5 are also UNIQUE in keys_checked so no duplicates inside this same file allowed
	// (2) Keep only keys with Duplicates in keys_copyin: delete 1st-stage checked keys & tuples with NULL fields
	// (3) Insert single copy of in-file Duplicates, if they have no Duplicate in final keys table (in DB)
	txStrs := []string{bulkTxFilterUniqueKeys, bulkTxPrepKeyStats, bulkTxFilterDupKeys}
	msgStrs := []string{"bulkTx-filter-unique-keys", "bulkTx-prep-key-stats", "bulkTx-filter-dup-keys"}
	err = st.bulkInsertSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	return numNulls, true
}

func (st *storage) bulkInsertCheckedKeysSubkeys(keys []*openpgp.PrimaryKey,
	result *hkpstorage.InsertError) (nullKeys, nullSubkeys int, ok bool) {
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
	err := st.bulkInsertSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, 0, false
	}
	return nullKeys, nullSubkeys, true
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
	_, err = stmt.Exec(keysValueArgs...) // All keys in bunch
	if err != nil {
		return errors.Wrapf(err, "cannot simply send a bunch of %s to server (too large bunch?)", msgSpec)
	}
	err = stmt.Close()
	if err != nil {
		return errors.Wrapf(err, "failed to close xfer sending a bunch of %s to server", msgSpec)
	}

	return nil
}

func (st *storage) bulkInsertSendBunch(keystmt, subkeystmt string, keysValueArgs, subkeysValueArgs []interface{}) (err error) {

	// Send all keys to in-mem tables to the pg server; *no constraints checked*
	err = st.bulkInsertSendBunchTx(keystmt, "keys", keysValueArgs)
	if err != nil {
		return err
	}

	// Send all subkeys to in-mem tables to the pg server; *no constraints checked*
	err = st.bulkInsertSendBunchTx(subkeystmt, "subkeys", subkeysValueArgs)
	if err != nil {
		return err
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
		keysValueArgs := make([]interface{}, 0, keysInBunch*6) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]interface{}, 0, subkeysInBunch*2) // *** must be less than 64k arguments ***
		insTime := make([]time.Time, 0, keysInBunch)                 // stupid but anyway...
		for i, j := 0, 0; idx < lenKIA; idx, i = idx+1, i+1 {
			lenSKIA := len(skeyInsArgs[idx])
			totKeyArgs += 6
			totSubkeyArgs += 2 * lenSKIA
			if (totKeyArgs > keysInBunch*6) || (totSubkeyArgs > subkeysInBunch*2) {
				totKeyArgs -= 6
				totSubkeyArgs -= 2 * lenSKIA
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, to_tsvector($%d))",
					i*6+1, i*6+2, i*6+3, i*6+4, i*6+5, i*6+6))
			insTime = insTime[:i+1] // re-slice +1
			insTime[i] = time.Now().UTC()
			keysValueArgs = append(keysValueArgs, *keyInsArgs[idx].RFingerprint, *keyInsArgs[idx].jsonStrDoc,
				insTime[i], insTime[i], *keyInsArgs[idx].MD5, *keyInsArgs[idx].keywords)

			for sidx := 0; sidx < lenSKIA; sidx, j = sidx+1, j+1 {
				subkeysValueStrings = append(subkeysValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT)", j*2+1, j*2+2))
				subkeysValueArgs = append(subkeysValueArgs,
					*skeyInsArgs[idx][sidx].keyRFingerprint, *skeyInsArgs[idx][sidx].subkeyRFingerprint)
			}
		}
		log.Debugf("Attempting bulk insertion of %d keys and a total of %d subkeys!", idx-lastIdx, totSubkeyArgs>>1)
		keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, doc, ctime, mtime, md5, keywords) VALUES %s",
			keys_copyin_temp_table_name, strings.Join(keysValueStrings, ","))
		subkeystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, rsubfp) VALUES %s",
			subkeys_copyin_temp_table_name, strings.Join(subkeysValueStrings, ","))

		err := st.bulkInsertSendBunch(keystmt, subkeystmt, keysValueArgs, subkeysValueArgs)
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
		jsonStrs[i], theKeywords[i] = string(jsonBuf), keywordsTSVector(key)
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

func (st *storage) bulkInsertCleanUp() (err error) {
	// Drop the 2 pairs (all) of temporary tables
	for _, drTableSQL := range drTempTablesSQL {
		_, err := st.Exec(drTableSQL)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func (st *storage) bulkInsertCreateTempTables() (err error) {
	for _, crTableSQL := range crTempTablesSQL {
		_, err := st.Exec(crTableSQL)
		if err != nil {
			return errors.Wrap(err, "cannot drop temporary tables")
		}
	}
	return nil
}

func (st *storage) BulkInsert(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError) (int, bool) {
	log.Infof("Attempting bulk insertion of keys")
	t := time.Now() // FIXME: Remove this
	// Create 2 pairs of _temporary_ (in-mem) tables:
	// (a) keys_copyin, subkeys_copyin
	// (b) keys_checked, subkeys_checked
	err := st.bulkInsertCreateTempTables()
	if err != nil {
		// This should always be possible (maybe, out-of-memory?)
		result.Errors = append(result.Errors, err)
		st.bulkInsertCleanUp() // Drop temp tables IF EXIST
		return 0, false
	}
	keysWithNulls, subkeysWithNulls, ok := 0, 0, true
	maxDups, minDups, keysInserted, subkeysInserted := 0, 0, 0, 0
	// (a): Send *all* keys to in-mem tables on the pg server; *no constraints checked*
	if _, ok = st.bulkInsertCopyKeysToServer(keys, result); !ok {
		st.bulkInsertCleanUp() // Drop temp tables IF EXIST
		return 0, false
	}
	// (b): From _copyin tables (still only to in-mem table) remove duplicates
	//      check *all* constraints & RollBack insertions of key/subkeys that err
	if keysWithNulls, subkeysWithNulls, ok = st.bulkInsertCheckedKeysSubkeys(keys, result); !ok {
		st.bulkInsertCleanUp() // Drop temp tables IF EXIST
		return 0, false
	}

	maxDups, minDups, keysInserted, subkeysInserted = st.bulkInsertGetStats(result)
	err = st.BulkNotify(bulkInsQueryKeyChange)
	if err != nil {
		result.Errors = append(result.Errors, err)
	}

	if minDups == maxDups {
		log.Infof("%d keys and %d subkeys bulk-inserted, %d duplicates skipped (%d keys and %d subkeys with NULLs) in %v",
			keysInserted, subkeysInserted, minDups, keysWithNulls, subkeysWithNulls, time.Since(t))
	} else {
		log.Infof("%d keys and %d subkeys bulk-inserted, at least %d (and up to %d possible) duplicates skipped "+
			"(%d keys and %d subkeys with NULLs) in %v",
			keysInserted, subkeysInserted, minDups, maxDups, keysWithNulls, subkeysWithNulls, time.Since(t))
	}

	err = st.bulkInsertCleanUp()
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

var errTargetMissing = errors.New("errTargetMissing")

func (st *storage) Insert(keys []*openpgp.PrimaryKey) (u, n int, retErr error) {
	var result hkpstorage.InsertError

	bulkOK, bulkSkip := false, false
	if len(keys) >= minKeys2UseBulk {
		// Attempt bulk insertion
		n, bulkOK = st.BulkInsert(keys, &result)
	} else {
		bulkSkip = true
	}

	if !bulkOK {
		log.Infof("Bulk insertion %s. Reverting to normal insertion.",
			(map[bool]string{true: "skipped (small number of keys)", false: "failed"})[bulkSkip])

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
						log.Infof("Key fp(%v) is slippery; backing off", key.Fingerprint())
						break
					}
				}
				if err == errTargetMissing {
					result.Errors = append(result.Errors,
						errors.Errorf("Key fp(%v) was changing while we were updating it", key.Fingerprint()))
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
					ID:     key.KeyID(),
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
	md5, err := st.deleteTx(tx, key.Fingerprint())
	if err != nil {
		return "", errors.WithStack(err)
	}
	_, err = st.insertKeyTx(tx, key)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return md5, nil
}

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
	return md5, nil
}

func (st *storage) deleteTx(tx *sql.Tx, fp string) (string, error) {
	rfp := openpgp.Reverse(fp)
	_, err := tx.Exec("DELETE FROM subkeys WHERE rfingerprint = $1", rfp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var md5 string
	err = tx.QueryRow("DELETE FROM keys WHERE rfingerprint = $1 RETURNING md5", rfp).Scan(&md5)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(hkpstorage.ErrKeyNotFound)
		}
		return "", errors.WithStack(err)
	}
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
		return errors.Wrapf(err, "cannot serialize rfp=%q", key.RFingerprint)
	}
	keywords := keywordsTSVector(key)
	result, err := tx.Exec("UPDATE keys SET mtime = $1, md5 = $2, keywords = to_tsvector($3), doc = $4 "+
		"WHERE md5 = $5",
		&now, &key.MD5, &keywords, jsonBuf, lastMD5)
	if err != nil {
		return errors.WithStack(err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected > 1 {
		return errors.Errorf("Unexpected error when updating digest %v fp(%v)", lastMD5, key.Fingerprint())
	} else if rowsAffected == 0 {
		// The md5 disappeared before we could update it. Thread-safety backoff.
		return errTargetMissing
	}
	for _, subKey := range key.SubKeys {
		_, err := tx.Exec("INSERT INTO subkeys (rfingerprint, rsubfp) "+
			"SELECT $1::TEXT, $2::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)",
			&key.RFingerprint, &subKey.RFingerprint)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	st.Notify(hkpstorage.KeyReplaced{
		OldID:     lastID,
		OldDigest: lastMD5,
		NewID:     key.KeyID(),
		NewDigest: key.MD5,
	})
	return nil
}

func keywordsTSVector(key *openpgp.PrimaryKey) string {
	keywords := keywordsFromKey(key)
	tsv, err := keywordsToTSVector(keywords)
	if err != nil {
		// In this case we've found a key that generated
		// an invalid tsvector - this is pretty much guaranteed
		// to be a bogus key, since having a valid key with
		// user IDs that exceed limits is highly unlikely.
		// In the future we should catch this earlier and
		// reject it as a bad key, but for now we just skip
		// storing keyword information.
		log.Warningf("keywords for rfp=%q exceeds limit, ignoring: %v", key.RFingerprint, err)
		return ""
	}
	return tsv
}

// keywordsToTSVector converts a slice of keywords to a
// PostgreSQL tsvector. If the resulting tsvector would
// be considered invalid by PostgreSQL an error is
// returned instead.
func keywordsToTSVector(keywords []string) (string, error) {
	const (
		lexemeLimit   = 2048            // 2KB for single lexeme
		tsvectorLimit = 1 * 1024 * 1024 // 1MB for lexemes + positions
	)
	for _, k := range keywords {
		if l := len([]byte(k)); l >= lexemeLimit {
			return "", fmt.Errorf("keyword exceeds limit (%d >= %d)", l, lexemeLimit)
		}
	}
	tsv := strings.Join(keywords, " & ")

	// Allow overhead of 8 bytes for position per keyword.
	if l := len([]byte(tsv)) + len(keywords)*8; l >= tsvectorLimit {
		return "", fmt.Errorf("keywords exceeds limit (%d >= %d)", l, tsvectorLimit)
	}
	return tsv, nil
}

// keywordsFromKey returns a slice of searchable tokens
// extracted from the UserID packets keywords string of
// the given key.
func keywordsFromKey(key *openpgp.PrimaryKey) []string {
	m := make(map[string]bool)
	for _, uid := range key.UserIDs {
		s := strings.ToLower(uid.Keywords)
		lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
		if lbr != -1 && rbr > lbr {
			email := s[lbr+1 : rbr]
			m[email] = true

			parts := strings.SplitN(email, "@", 2)
			if len(parts) > 1 {
				username, domain := parts[0], parts[1]
				m[username] = true
				m[domain] = true
			}
		}
		if lbr != -1 {
			fields := strings.FieldsFunc(s[:lbr], func(r rune) bool {
				if !utf8.ValidRune(r) {
					return true
				}
				if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' {
					return false
				}
				return true
			})
			for _, field := range fields {
				m[field] = true
			}
		}
	}
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}

func subkeys(key *openpgp.PrimaryKey) []string {
	var result []string
	for _, subkey := range key.SubKeys {
		result = append(result, subkey.RFingerprint)
	}
	return result
}

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
		// TODO: log error notifying listener?
		f(change)
	}
	return nil
}

func (st *storage) BulkNotify(sqlStr string) error {
	rows, err := st.Query(sqlStr)
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
	return errors.WithStack(err)
}

func (st *storage) RenotifyAll() error {
	return st.BulkNotify("SELECT md5 FROM keys")
}
