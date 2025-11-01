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
	"hockeypuck/pghkp/types"

	log "github.com/sirupsen/logrus"
)

//
// Reindexer implementation
//

// refreshBunch fetches a bunch of keyDocs from the DB and returns freshened copies of the ones with stale records.
//
// TODO: ModifiedSince does not return keys in any particular sort order (FIXME!),
// so we use a map (not an array) to deduplicate the returned keyDocs,
// and explicitly compare timestamps instead of assuming monotonicity.
// (reverting these mitigations will almost certainly improve the performance)
func (st *storage) refreshBunch(bookmark *time.Time, newKeyDocs map[string]*types.KeyDoc, result *hkpstorage.InsertError) (count int, finished bool) {
	// ModifiedSince uses LIMIT, so this is safe
	rfps, err := st.ModifiedSince(*bookmark)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	if len(rfps) == 0 {
		return 0, true
	}
	keyDocs, err := st.fetchKeyDocs(rfps)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	count = len(keyDocs)
	log.Debugf("reindexing %d records", count)
	for _, kd := range keyDocs {
		// Can't trust MTime to be monotonically increasing, so compare as we go.
		if bookmark.Before(kd.MTime) {
			*bookmark = kd.MTime
		}
		_, _, changed, err := kd.Refresh()
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if changed {
			newKeyDocs[kd.MD5] = kd
		}
	}
	log.Infof("found %d stale records up to %v", len(newKeyDocs), bookmark)
	return count, false
}

// Reindex is a goroutine that reindexes the keydb in-place, oldest-modified items first.
// It does not update CTime, MTime, MD5 or Doc, and does not call Notify.
// It always returns nil, as reindex failure is not fatal.
func (st *storage) Reindex() error {
	bookmark := time.Time{}
	newKeyDocs := make(map[string]*types.KeyDoc, keysInBunch)
	result := hkpstorage.InsertError{}
	total := 0

	for {
		select {
		case <-st.t.Dying():
			return nil
		default:
		}

		t := time.Now()
		count, finished := st.refreshBunch(&bookmark, newKeyDocs, &result)
		total += count
		if finished || len(newKeyDocs) > keysInBunch-100 {
			n, bulkOK := st.bulkReindex(newKeyDocs, &result)
			if !bulkOK {
				log.Debugf("bulkReindex not ok: %q", result.Errors)
				if count, max := len(result.Errors), maxInsertErrors; count > max {
					log.Errorf("too many reindexing errors (%d > %d), bailing...", count, max)
					return nil
				}
			}
			log.Infof("%d keys reindexed in %v; total scanned %d", n, time.Since(t), total)
			newKeyDocs = make(map[string]*types.KeyDoc, keysInBunch)
		}
		if finished {
			log.Infof("reindexing complete")
			return nil
		}
	}
}

// Start reindexing in the background. This should only be done after server startup, not during load or dump.
func (st *storage) StartReindex(reindexGraceSecs int) {
	if st.oldestIdxTime().Add(time.Second * time.Duration(reindexGraceSecs)).Before(time.Now()) {
		st.t.Go(st.Reindex)
	}
}
