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
	"time"

	_ "github.com/lib/pq"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"
)

//
// Reloader implementation
//

// getReloadBunch fetches a bunch of records from the DB.
// Digest mismatches are NOT handled here, the caller MUST test for them.
//
// TODO: createdSince does not return records in any particular sort order (FIXME!),
// so we explicitly compare timestamps instead of assuming monotonicity.
// BEWARE that `records` MUST be a *pointer* to a slice, because append() re-slices it.
func (st *storage) getReloadBunch(bookmark *time.Time, records *[]*hkpstorage.Record, result *hkpstorage.InsertError) (count int, finished bool) {
	// createdSince uses LIMIT, so this is safe
	rfps, err := st.createdSince(*bookmark)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, true
	}
	if len(rfps) == 0 {
		return 0, true
	}
	newRecords, err := st.fetchRecordsByRfp(rfps)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, true
	}
	count = len(newRecords)
	log.Debugf("reloading %d records", count)
	for _, record := range newRecords {
		// Can't trust CTime to be monotonically increasing, so compare as we go.
		if bookmark.Before(record.CTime) {
			*bookmark = record.CTime
		}
		// Take care, because fetchRecordsByRfp can return nils.
		err = st.preen(record)
		switch err {
		case nil, hkpstorage.ErrDigestMismatch, openpgp.ErrKeyEvaporated:
			*records = append(*records, record)
		}
	}
	log.Infof("found %d records up to %v", len(*records), bookmark)
	return count, false
}

// reloadIncremental updates a bunch of keys one at a time. It SHOULD have the same effect as bulkInsert, just slower.
func (st *storage) reloadIncremental(newRecords []*hkpstorage.Record, result *hkpstorage.InsertError) (n, d int, ok bool) {
	for _, record := range newRecords {
		if count, max := len(result.Errors), maxInsertErrors; count > max {
			log.Errorf("too many reload errors (%d > %d), bailing...", count, max)
			return n, d, false
		}
		if record.PrimaryKey == nil {
			_, err := st.Delete(record.Fingerprint)
			if err != nil {
				result.Errors = append(result.Errors, err)
			}
			d++
			continue
		}
		keyID := record.KeyID
		err := st.Update(record.PrimaryKey, keyID, record.MD5)
		if err != nil {
			result.Errors = append(result.Errors, err)
			continue
		} else {
			if record.MD5 != record.PrimaryKey.MD5 {
				st.Notify(hkpstorage.KeyReplaced{OldID: keyID, OldDigest: record.MD5, NewID: keyID, NewDigest: record.PrimaryKey.MD5})
			} else {
				result.Duplicates = append(result.Duplicates, record.PrimaryKey)
			}
			n++
		}
	}
	return n, d, true
}

// validateRecords takes a slice of records and validates the PrimaryKeys in each.
// It handles nils and ErrKeyEvaporated events, and returns a slice of valid PrimaryKeys,
// and a slice of all the fingerprints, both valid and invalid.
func validateRecords(newRecords []*hkpstorage.Record) (newKeys []*openpgp.PrimaryKey, oldKeys []string) {
	newKeys = make([]*openpgp.PrimaryKey, 0, keysInBunch)
	oldKeys = make([]string, 0, keysInBunch)
	for _, record := range newRecords {
		// Add all fingerprints to the oldKeys list
		oldKeys = append(oldKeys, record.Fingerprint)
		if record.PrimaryKey == nil {
			continue
		}
		err := openpgp.ValidSelfSigned(record.PrimaryKey, false)
		if err != nil {
			record.PrimaryKey = nil
			continue
		}
		newKeys = append(newKeys, record.PrimaryKey)
	}
	return newKeys, oldKeys
}

// Reload is a function that reloads the keydb in-place, oldest-created items first.
// It MUST NOT be called within a goroutine, as it performs no clean shutdown.
//
// Note: it might seem more efficient if getReloadBunch() returned keys rather than records,
// as this would save a redundant pass over the slice in the happy path, but we wouldn't then
// be able to call Update+Notify directly in the fallback case - a previous version of this code
// called upsertKeyOnInsert(), but this added a redundant fetch-preen-merge cycle for each key.
func (st *storage) Reload() (totalUpdated, totalDeleted int, _ error) {
	bookmark := time.Time{}
	newRecords := make([]*hkpstorage.Record, 0, keysInBunch)
	result := hkpstorage.InsertError{}

	bs, err := st.bulkCreateTempTables()
	if err != nil {
		log.Errorf("could not create temp tables: %v", err)
		return 0, 0, err
	}
	defer bs.bulkDropTempTables()

	for {
		t := time.Now()
		_, finished := st.getReloadBunch(&bookmark, &newRecords, &result)
		if (finished && len(newRecords) != 0) || len(newRecords) > keysInBunch-100 {
			// bulkInsert expects keys, not records
			newKeys, oldKeys := validateRecords(newRecords)
			n, d, bulkOK := bs.bulkInsert(newKeys, &result, oldKeys)
			if !bulkOK {
				log.Debugf("bulkInsert not ok: %q", result.Errors)
				log.Infof("bulk reload failed; reverting to normal insertion")
				n, d, bulkOK = st.reloadIncremental(newRecords, &result)
				if !bulkOK {
					return totalUpdated, totalDeleted, result
				}
			}
			totalUpdated += n
			totalDeleted += d
			log.Infof("%d keys reloaded and %d keys deleted in %v (totals %d, %d)", n, d, time.Since(t), totalUpdated, totalDeleted)
			newRecords = make([]*hkpstorage.Record, 0, keysInBunch)
		}
		if finished {
			log.Infof("reload complete")
			return totalUpdated, totalDeleted, nil
		}
	}
}
