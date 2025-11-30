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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"

	log "github.com/sirupsen/logrus"
)

//
// Queryer implementation
//

// TODO: implement direct lookup by MD5/KeyID/Keyword and deprecate MatchMD5ToFp/ResolveToFp/MatchKeywordToFp (#228)
func (st *storage) MatchMD5ToFp(md5s []string) ([]string, error) {
	var md5In []string
	var md5Values []string
	for _, md5 := range md5s {
		// Must validate to prevent SQL injection since we're appending SQL strings here.
		_, err := hex.DecodeString(md5)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid MD5 %q", md5)
		}
		md5In = append(md5In, "'"+strings.ToLower(md5)+"'")
		md5Values = append(md5Values, "('"+strings.ToLower(md5)+"')")
	}

	sqlStr := fmt.Sprintf("SELECT reverse(rfingerprint) FROM keys WHERE md5 IN (%s)", strings.Join(md5In, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []string
	defer rows.Close()
	for rows.Next() {
		var fp string
		err := rows.Scan(&fp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, fp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// If we receive a hashquery for nonexistent digest(s), assume the ptree is stale and force an update.
	// https://github.com/hockeypuck/hockeypuck/issues/170#issuecomment-1384003238 (note 1)
	sqlStr = fmt.Sprintf("SELECT md5 FROM (values %s) as hashquery(md5) WHERE NOT EXISTS (SELECT FROM keys WHERE md5 = hashquery.md5)", strings.Join(md5Values, ","))
	rows, err = st.Query(sqlStr)
	if err == nil {
		for rows.Next() {
			var md5 string
			err := rows.Scan(&md5)
			if err == nil {
				st.Notify(hkpstorage.KeyRemovedJitter{ID: "??", Digest: md5})
			}
		}
	}

	return result, nil
}

// ResolveToFp implements storage.Storage.
//
// Only v4 key IDs are resolved by this backend. v3 short and long key IDs
// currently won't match.
//
// TODO: implement direct lookup by MD5/KeyID/Keyword and deprecate MatchMD5ToFp/ResolveToFp/MatchKeywordToFp (#228)
func (st *storage) ResolveToFp(keyids []string) (_ []string, retErr error) {
	rkeyids := make([]string, len(keyids))
	for i, keyid := range rkeyids {
		rkeyids[i] = types.Reverse(keyid)
	}
	rfps, retErr := st.resolveRfp(rkeyids)
	result := make([]string, len(rfps))
	for i, rfp := range rfps {
		result[i] = types.Reverse(rfp)
	}
	return result, retErr
}

// resolveRfp is the same as ResolveToFp, but takes rkeyids/rfingerprints and returns rfingerprints.
func (st *storage) resolveRfp(rkeyids []string) (_ []string, retErr error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM keys WHERE rfingerprint LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	var rSubKeyIDs []string
	for _, rkeyid := range rkeyids {
		rkeyid = strings.ToLower(rkeyid)
		var rfp string
		row := stmt.QueryRow(rkeyid)
		err = row.Scan(&rfp)
		if err == sql.ErrNoRows {
			rSubKeyIDs = append(rSubKeyIDs, rkeyid)
		} else if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}

	if len(rSubKeyIDs) > 0 {
		rSubKeyResult, err := st.resolveSubKeysRfp(rSubKeyIDs)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, rSubKeyResult...)
	}

	return result, nil
}

// resolveSubkeysRfp returns a list of key rfingerprints matching the provided subkey rfingerprints
func (st *storage) resolveSubKeysRfp(rkeyids []string) ([]string, error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM subkeys WHERE rsubfp LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	for _, rkeyid := range rkeyids {
		rkeyid = strings.ToLower(rkeyid)
		var rfp string
		row := stmt.QueryRow(rkeyid)
		err = row.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}

	return result, nil
}

// TODO: implement direct lookup by MD5/KeyID/Keyword and deprecate MatchMD5ToFp/ResolveToFp/MatchKeywordToFp (#228)
func (st *storage) MatchKeywordToFp(search []string) ([]string, error) {
	var result []string
	stmt, err := st.Prepare("SELECT reverse(rfingerprint) FROM keys WHERE keywords @@ $1::TSQUERY LIMIT $2")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	for _, term := range search {
		err = func() error {
			query, err := types.KeywordsTSQuery(term)
			if err != nil {
				return errors.WithStack(err)
			}
			rows, err := stmt.Query(query, 100)
			if err != nil {
				return errors.WithStack(err)
			}
			defer rows.Close()
			for rows.Next() {
				var fp string
				err = rows.Scan(&fp)
				if err != nil && err != sql.ErrNoRows {
					return errors.WithStack(err)
				}
				result = append(result, fp)
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

// ModifiedSinceToFp returns the fingerprints of the first 100 keys modified after the reference time.
// To get another 100 keys, pass the mtime of the last key returned to a subsequent invocation.
//
// TODO: Multiple calls do not appear to work as expected, the result windows overlap.
// Are the results sorted correctly by increasing MTime? That may explain the results.
func (st *storage) ModifiedSinceToFp(t time.Time) ([]string, error) {
	rfps, err := st.modifiedSinceRfp(t)
	result := make([]string, len(rfps))
	for i, rfp := range rfps {
		result[i] = types.Reverse(rfp)
	}
	return result, err
}

// modifiedSinceRfp is the same as ModifiedSinceToFp, but for internal pghkp use.
func (st *storage) modifiedSinceRfp(t time.Time) ([]string, error) {
	var result []string
	rows, err := st.Query("SELECT rfingerprint FROM keys WHERE mtime > $1 ORDER BY mtime ASC LIMIT 100", t)
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

// createdSince returns the rfingerprints of the first 100 keys created after the reference time.
// To get another 100 keys, pass the ctime of the last key returned to a subsequent invocation.
//
// TODO: Multiple calls do not appear to work as expected, the result windows overlap.
func (st *storage) createdSince(t time.Time) ([]string, error) {
	var result []string
	rows, err := st.Query("SELECT rfingerprint FROM keys WHERE ctime > $1 ORDER BY ctime ASC LIMIT 100", t)
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

// FetchKeysByFp is now just a compatibility wrapper around FetchRecordsByFp. FetchRecordsByFp should be used instead.
// TODO: purge FetchKeysByFp from the codebase.
func (st *storage) FetchKeysByFp(fps []string, options ...string) ([]*openpgp.PrimaryKey, error) {
	if len(fps) == 0 {
		return nil, nil
	}

	records, err := st.FetchRecordsByFp(fps, options...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*openpgp.PrimaryKey
	for _, record := range records {
		if record.PrimaryKey != nil {
			result = append(result, record.PrimaryKey)
		}
	}
	return result, nil
}

// Fetch the database Records corresponding to the supplied fingerprint slice.
// This will parse the jsonhkp JSONBs into openpgp.PrimaryKey objects.
// If either of the DB or jsonhkp schemas has changed, this MAY cause normalisation, in which case:
// 1. The returned Records MAY contain nil PrimaryKeys; the caller MUST test for them.
// 2. If options contains AutoPreen, any schema changes will be written back to the DB.
func (st *storage) FetchRecordsByFp(fps []string, options ...string) ([]*hkpstorage.Record, error) {
	var rfpIn []string
	for _, fp := range fps {
		_, err := hex.DecodeString(fp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid fingerprint %q", fp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(types.Reverse(fp))+"'")
	}
	records, err := st.fetchRecordsByRfp(rfpIn, options...)
	return records, err
}

// Exactly the same as FetchRecordsByFp, but uses rfingerprints.
// This is used internally by pghkp; other code should use FetchRecordsByFp instead.
func (st *storage) fetchRecordsByRfp(rfpIn []string, options ...string) ([]*hkpstorage.Record, error) {
	autoPreen := slices.Contains(options, hkpstorage.AutoPreen)
	sqlStr := fmt.Sprintf("SELECT reverse(rfingerprint), doc, md5, ctime, mtime FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*hkpstorage.Record
	defer rows.Close()
	for rows.Next() {
		var bufStr, fp string
		record := &hkpstorage.Record{}
		err = rows.Scan(&fp, &bufStr, &record.MD5, &record.CTime, &record.MTime)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		record.Fingerprint = fp
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		// It is possible that the JSON MD5, fingerprint fields do not match the SQL record.
		// This may be a symptom of problems elsewhere, so log it.
		if pk.MD5 != record.MD5 {
			log.Warnf("inconsistent MD5 in database (sql=%s, json=%s)", record.MD5, pk.MD5)
		}
		if record.Fingerprint != pk.Fingerprint {
			log.Warnf("inconsistent fp in database (sql=%s, json=%s)", record.Fingerprint, pk.Fingerprint)
		}

		key, err := types.ReadOneKey(pk.Bytes(), fp)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		record.PrimaryKey = key
		if autoPreen {
			err = st.preen(record)
			if err == hkpstorage.ErrDigestMismatch {
				log.Debugf("Writing back fp=%s", record.Fingerprint)
				err := st.Update(record.PrimaryKey, record.PrimaryKey.KeyID, record.MD5)
				if err != nil {
					log.Errorf("could not writeback fp=%s: %v", record.Fingerprint, err)
				}
			} else if err == openpgp.ErrKeyEvaporated {
				_, err := st.Delete(record.Fingerprint)
				if err != nil {
					log.Errorf("could not delete fp=%s: %v", record.Fingerprint, err)
				}
			} else if err != nil {
				log.Warn(err)
				continue
			}
		}
		result = append(result, record)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

// preen checks for common issues encountered when reading older records from the DB.
// If the record did not parse correctly (no parseable primary key packet or self-signatures),
// it zeros the primary key and returns ErrKeyEvaporated. If the MD5 values in the SQL record
// and the JSONB document are mismatched it throws ErrDigestMismatch.
//
// Note that preen does not validate signatures - if the caller wishes to test for *valid*
// self-signatures, it should call openpgp.ValidSelfSigned.
//
// Also note that preen will explicitly zero the pointer to the primary key object,
// unlike ValidSelfSigned which does not. This is because preen operates on *records* and the
// deleted primary key can still be identified from the other record fields.
func (st *storage) preen(record *hkpstorage.Record) error {
	if len(record.PrimaryKey.SubKeys) == 0 && len(record.PrimaryKey.UserIDs) == 0 && len(record.PrimaryKey.Signatures) == 0 {
		log.Debugf("no valid self-signatures in database (fp=%s); zeroing", record.Fingerprint)
		record.PrimaryKey = nil
		return openpgp.ErrKeyEvaporated
	}
	if record.PrimaryKey == nil {
		log.Debugf("unparseable key material in database (fp=%s)", record.Fingerprint)
		return openpgp.ErrKeyEvaporated
	}
	if record.PrimaryKey.MD5 != record.MD5 {
		log.Debugf("MD5 changed while parsing (old=%s new=%s fp=%s)", record.MD5, record.PrimaryKey.MD5, record.Fingerprint)
		return hkpstorage.ErrDigestMismatch
	}
	return nil
}

// fetchKeyDocsByRfp returns a slice of KeyDocs corresponding to the supplied slice of rfingerprints.
// Note that it returns nil if there are any errors reading the returned SQL records.
func (st *storage) fetchKeyDocsByRfp(rfps []string) ([]*types.KeyDoc, error) {
	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT reverse(rfingerprint), doc, md5, ctime, mtime, idxtime, keywords, vfingerprint FROM keys WHERE rfingerprint IN (%s) ORDER BY idxtime ASC", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*types.KeyDoc
	defer rows.Close()
	for rows.Next() {
		var kd types.KeyDoc
		err = rows.Scan(&kd.Fingerprint, &kd.Doc, &kd.MD5, &kd.CTime, &kd.MTime, &kd.IdxTime, &kd.Keywords, &kd.VFingerprint)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, &kd)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

// fetchSubKeyDocsByRfp returns a slice of SubKeyDocs corresponding to the supplied slice of rfingerprints.
// If the second argument is true, it searches by subkey rfingerprint, otherwise by primary key rfingerprint.
// Note that it returns nil if there are any errors reading the returned SQL records.
func (st *storage) fetchSubKeyDocsByRfp(rfps []string, bysubfp bool) ([]*types.SubKeyDoc, error) {
	var rfpIn []string
	var sqlStr string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	if bysubfp {
		sqlStr = fmt.Sprintf("SELECT reverse(rfingerprint), reverse(rsubfp), vsubfp FROM subkeys WHERE rsubfp IN (%s) ORDER BY vsubfp ASC", strings.Join(rfpIn, ","))
	} else {
		sqlStr = fmt.Sprintf("SELECT reverse(rfingerprint), reverse(rsubfp), vsubfp FROM subkeys WHERE rfingerprint IN (%s) ORDER BY vsubfp ASC", strings.Join(rfpIn, ","))
	}
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*types.SubKeyDoc
	defer rows.Close()
	for rows.Next() {
		var skd types.SubKeyDoc
		err = rows.Scan(&skd.Fingerprint, &skd.SubKeyFp, &skd.VSubKeyFp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, &skd)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

// fetchUserIdDocsByRfp returns a slice of UserIdDocs corresponding to the supplied slice of rfingerprints.
// Note that it returns nil if there are any errors reading the returned SQL records.
func (st *storage) fetchUserIdDocsByRfp(rfps []string) ([]*types.UserIdDoc, error) {
	var rfpIn []string
	var sqlStr string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr = fmt.Sprintf("SELECT reverse(rfingerprint), uidstring, identity, confidence FROM userids WHERE rfingerprint IN (%s) ORDER BY confidence DESC, identity, uidstring ASC", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*types.UserIdDoc
	defer rows.Close()
	for rows.Next() {
		var uidd types.UserIdDoc
		err = rows.Scan(&uidd.Fingerprint, &uidd.UidString, &uidd.Identity, &uidd.Confidence)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, &uidd)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

// oldestIdxTime returns the Time of the oldest value in the idxtime column.
// On error it returns the current time; this prevents excessive calls to StartReindex.
func (st *storage) oldestIdxTime() (t time.Time) {
	sqlStr := "SELECT idxtime FROM keys ORDER BY idxtime ASC LIMIT 1"
	rows, err := st.Query(sqlStr)
	if err != nil {
		return time.Now()
	}

	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&t)
		if err != nil && err != sql.ErrNoRows {
			return time.Now()
		}
	}
	return t
}
