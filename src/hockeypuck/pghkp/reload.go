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
	// ModifiedSince uses LIMIT, so this is safe
	rfps, err := st.createdSince(*bookmark)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	if len(rfps) == 0 {
		return 0, true
	}
	newRecords, err := st.FetchRecords(rfps)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	count = len(newRecords)
	log.Debugf("reloading %d records", count)
	for _, record := range newRecords {
		// Can't trust CTime to be monotonically increasing, so compare as we go.
		if bookmark.Before(record.CTime) {
			*bookmark = record.CTime
		}
		// Take care, because FetchRecords can return nils.
		err = st.preen(record)
		switch err {
		case nil, hkpstorage.ErrDigestMismatch:
			*records = append(*records, record)
		case openpgp.ErrKeyEvaporated:
			_, err := st.Delete(record.Fingerprint)
			if err != nil {
				log.Errorf("could not delete fp=%s: %v", record.Fingerprint, err)
			}
		}
	}
	log.Infof("found %d records up to %v", len(*records), bookmark)
	return count, false
}

// Reload is a function that reloads the keydb in-place, oldest items first.
// It MUST NOT be called within a goroutine, as it performs no clean shutdown.
//
// Note: it might seem more efficient if getReloadBunch() returned keys rather than records,
// as this would save a redundant pass over the slice in the happy path, but we wouldn't then
// be able to call Update+Notify directly in the fallback case - a previous version of this code
// called upsertKeyOnInsert(), but this added a redundant fetch-preen-merge cycle for each key.
func (st *storage) Reload() (int, error) {
	bookmark := time.Time{}
	newRecords := make([]*hkpstorage.Record, 0, keysInBunch)
	result := hkpstorage.InsertError{}
	total := 0

	for {
		t := time.Now()
		_, finished := st.getReloadBunch(&bookmark, &newRecords, &result)
		if finished || len(newRecords) > keysInBunch-100 {
			// bulkInsert expects keys, not records
			newKeys := make([]*openpgp.PrimaryKey, 0, keysInBunch)
			for _, record := range newRecords {
				err := openpgp.ValidSelfSigned(record.PrimaryKey, false)
				if err != nil {
					log.Errorf("validation error in database (fp=%s); deleting: %v", record.Fingerprint, err)
					st.Delete(record.Fingerprint)
					continue
				}
				newKeys = append(newKeys, record.PrimaryKey)
			}
			n, bulkOK := st.bulkInsert(newKeys, &result, true)
			if !bulkOK {
				log.Infof("bulk reload failed; reverting to normal insertion")
				log.Debugf("bulkReload not ok: %q", result.Errors)
				for _, record := range newRecords {
					if count, max := len(result.Errors), maxInsertErrors; count > max {
						log.Errorf("too many reload errors (%d > %d), bailing...", count, max)
						return total, result
					}
					keyID := record.KeyID()
					err := st.Update(record.PrimaryKey, keyID, record.MD5)
					if err != nil {
						result.Errors = append(result.Errors, err)
						continue
					} else {
						if record.MD5 != record.PrimaryKey.MD5 {
							st.Notify(hkpstorage.KeyReplaced{OldID: keyID, OldDigest: record.MD5, NewID: keyID, NewDigest: record.PrimaryKey.MD5})
							n++
						} else {
							result.Duplicates = append(result.Duplicates, record.PrimaryKey)
						}
					}
				}
			} else {
				total += n
			}
			log.Infof("%d keys reloaded in %v; total scanned %d", n, time.Since(t), total)
			newRecords = make([]*hkpstorage.Record, 0, keysInBunch)
		}
		if finished {
			log.Infof("reload complete")
			return total, nil
		}
	}
}
