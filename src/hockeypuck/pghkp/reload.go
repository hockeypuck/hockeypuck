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

// getReloadBunch fetches a bunch of keys from the DB.
//
// TODO: createdSince habitually yields the same entries multiple times (FIXME!),
// so we explicitly compare timestamps instead of assuming monotonicity.
// BEWARE that `keys` MUST be a *pointer* to a slice, because append() re-slices it.
func (st *storage) getReloadBunch(bookmark *time.Time, keys *[]*openpgp.PrimaryKey, result *hkpstorage.InsertError) (count int, finished bool) {
	// ModifiedSince uses LIMIT, so this is safe
	rfps, err := st.createdSince(*bookmark)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	if len(rfps) == 0 {
		return 0, true
	}
	records, err := st.FetchRecords(rfps)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	count = len(records)
	log.Debugf("reloading %d records", count)
	for _, record := range records {
		// Can't trust CTime to be monotonically increasing, so compare as we go.
		if bookmark.Before(record.CTime) {
			*bookmark = record.CTime
		}
		// Take care, because FetchRecords can return nils
		err = st.preen(record, false)
		if err == nil {
			*keys = append(*keys, record.PrimaryKey)
		}
	}
	log.Infof("found %d records up to %v", len(*keys), bookmark)
	return count, false
}

// Reload is a function that reloads the keydb in-place, oldest items first.
// It MUST NOT be called within a goroutine, as it performs no clean shutdown.
func (st *storage) Reload() (int, error) {
	bookmark := time.Time{}
	newKeys := make([]*openpgp.PrimaryKey, 0, keysInBunch)
	result := hkpstorage.InsertError{}
	total := 0

	for {
		t := time.Now()
		count, finished := st.getReloadBunch(&bookmark, &newKeys, &result)
		total += count
		if finished || len(newKeys) > keysInBunch-100 {
			n, bulkOK := st.bulkInsert(newKeys, &result, true)
			if !bulkOK {
				log.Debugf("bulkReload not ok, result: %q", result)
				if count, max := len(result.Errors), maxInsertErrors; count > max {
					log.Errorf("too many reload errors (%d > %d), bailing...", count, max)
					return total, nil
				}
			}
			log.Infof("%d keys reloaded in %v; total scanned %d", n, time.Since(t), total)
			newKeys = make([]*openpgp.PrimaryKey, 0, keysInBunch)
		}
		if finished {
			log.Infof("reload complete")
			return total, nil
		}
	}
}
