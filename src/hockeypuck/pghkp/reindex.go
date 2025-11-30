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
	"fmt"
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
	rfps, err := st.modifiedSinceRfp(*bookmark)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	if len(rfps) == 0 {
		return 0, true
	}
	keyDocs, err := st.fetchKeyDocsByRfp(rfps)
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
			result.Errors = append(result.Errors, fmt.Errorf("fp=%v: %w", kd.Fingerprint, err))
		} else if changed {
			newKeyDocs[kd.MD5] = kd
		}
	}
	log.Debugf("found %d stale records up to %v", len(newKeyDocs), bookmark)
	return count, false
}

// Reindex scans and reindexes the keydb in-place, oldest-modified items first.
// It does not update CTime, MTime, MD5 or Doc, and does not call Notify.
// It always returns nil, as reindex failure is not fatal.
func (st *storage) Reindex() error {
	bookmark := time.Time{}
	savedBookmark := bookmark
	newKeyDocs := make(map[string]*types.KeyDoc, keysInBunch)
	result := hkpstorage.InsertError{}
	total, subTotal := 0, 0
	try, maxTries := 1, 2
	log.Infof("reindexing scan starting...")

	bs, err := st.bulkCreateTempTables()
	if err != nil {
		log.Warnf("could not create temp tables: %v", err)
		return err
	}
	defer bs.bulkDropTempTables()

	for {
		select {
		case <-st.t.Dying():
			return nil
		default:
		}

		t := time.Now()
		count, finished := st.refreshBunch(&bookmark, newKeyDocs, &result)
		subTotal += count
		if finished && len(newKeyDocs) != 0 || len(newKeyDocs) > keysInBunch-100 {
			n, bulkOK := bs.bulkReindex(newKeyDocs, &result)
			if !bulkOK {
				log.Debugf("bulkReindex not ok: %q", result.Errors)
				if count := len(result.Errors); count > maxInsertErrors {
					log.Errorf("too many reindexing errors (%d > %d), bailing...", count, maxInsertErrors)
					return nil
				}
				if try < maxTries {
					try++
					subTotal = 0
					newKeyDocs = make(map[string]*types.KeyDoc, keysInBunch)
					bookmark = savedBookmark
					log.Debugf("retrying reindex batch... %d tries remaining", maxTries-try)
					continue
				}
			}
			try = 1
			total += subTotal
			subTotal = 0
			newKeyDocs = make(map[string]*types.KeyDoc, keysInBunch)
			savedBookmark = bookmark
			log.Infof("%d keys reindexed in %v on try %d; total scanned %d", n, time.Since(t), try, total)
		}
		if finished {
			log.Infof("reindexing complete")
			return nil
		}
	}
}

// Start reindexing in the background. This should only be done after server startup, not during load or dump.
// reindexStartupDelaySecs is the interval after startup before a freshly-started server will attempt its first reindex.
// This is a safety feature to prevent excessive reindexing when a server restarts multiple times in succession.
// reindexLoadDelaySecs is the interval after database (re)load before a server will attempt to reindex.
// This prevents a wasteful reindex on initial startup.
// reindexIntervalSecs is the interval between *subsequent* reindexing runs; a negative value means to reindex only once per startup.
func (st *storage) StartReindex(reindexStartupDelaySecs, reindexLoadDelaySecs, reindexIntervalSecs int) {
	st.t.Go(func() error {
		reindexInterval := time.Second * time.Duration(reindexIntervalSecs)
		reindexStartupDelay := time.Second * time.Duration(reindexStartupDelaySecs)
		reindexLoadDelay := time.Second * time.Duration(reindexLoadDelaySecs)
		timer := time.NewTimer(reindexStartupDelay)
		for {
			select {
			case <-st.t.Dying():
				return nil
			case <-timer.C:
				// don't reindex if we've only just (re)loaded the database
				if st.oldestIdxTime().Add(reindexLoadDelay).Before(time.Now()) {
					st.Reindex()
				}
				// a negative interval means "run only once"
				if reindexIntervalSecs < 0 {
					return nil
				}
				log.Infof("waiting %s for next reindex attempt", reindexInterval)
				timer.Reset(reindexInterval)
			}
		}
	})
}
