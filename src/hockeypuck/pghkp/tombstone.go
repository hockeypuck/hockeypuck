/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2026 Casey Marshall and the Hockeypuck Contributors

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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
)

// blockVerdict is the outcome of checking a stored or incoming block.
type blockVerdict int

const (
	// blockValid: the signature verifies against a key trusted for its origin.
	blockValid blockVerdict = iota
	// blockUnverifiable: nothing is wrong with the block, but this server
	// cannot judge it - the origin is not configured, or the key that would
	// vouch for it is not in the keyserver.
	blockUnverifiable
	// blockInvalid: the block is malformed, unsigned, or its signature does not
	// verify against the keys trusted for the origin it claims.
	blockInvalid
)

// judgeTombstone decides what this server can say about a block.
func (st *storage) judgeTombstone(key *openpgp.PrimaryKey) (blockVerdict, error) {
	ts, sigs, err := openpgp.TombstoneOf(key)
	if err != nil {
		return blockInvalid, errors.Wrap(err, "malformed tombstone")
	}
	// An unsigned block is a defect in the block itself, not something this
	// server's trust configuration could excuse, so it is judged before trust is
	// consulted at all. Judging it afterwards would leave an unsigned block in
	// place for as long as its origin happened to be unconfigured, which is the
	// case on every server that has not opted into that origin.
	if len(sigs) == 0 {
		return blockInvalid, errors.Errorf(
			"tombstone for 0x%s claiming origin %q carries no signature", ts.Fingerprint, ts.Origin)
	}
	fingerprints := st.policy.TrustedBlocklistKeys(ts.Origin)
	if len(fingerprints) == 0 {
		return blockUnverifiable, errors.Errorf(
			"no keys are trusted for blocklist origin %q", ts.Origin)
	}
	trusted, absent, err := st.trustedBlocklistKeys(fingerprints)
	if err != nil {
		return blockUnverifiable, errors.Wrapf(err,
			"cannot load trusted keys for blocklist origin %q", ts.Origin)
	}
	if len(trusted) == 0 {
		return blockUnverifiable, errors.Errorf(
			"none of the keys trusted for origin %q are in this keyserver (0x%s)",
			ts.Origin, strings.Join(absent, ", 0x"))
	}
	if _, err := openpgp.VerifyTombstone(*ts, sigs, trusted); err != nil {
		// A signature that fails to verify only proves forgery if every key
		// trusted for the origin was there to check it against. A trusted key
		// that is absent - not loaded yet, or rotated into the configuration
		// ahead of its key material - would otherwise make its own blocks look
		// forged, and the sweep would delete them.
		//
		// Matching the signature's issuer against the absent fingerprints would
		// narrow this, but a block is normally signed by a signing subkey, and a
		// subkey's issuer key ID cannot be tied back to a primary fingerprint
		// without holding the key that is missing.
		if errors.Is(err, openpgp.ErrTombstoneUnverifiable) {
			// The keys are here but none of them could be read as a key, so
			// this server cannot judge the block at all.
			return blockUnverifiable, err
		}
		if len(absent) > 0 {
			return blockUnverifiable, errors.Wrapf(err,
				"cannot judge tombstone for 0x%s: %s trusted for origin %q not in this keyserver (0x%s)",
				ts.Fingerprint, plural(len(absent), "key", "keys"), ts.Origin,
				strings.Join(absent, ", 0x"))
		}
		return blockInvalid, err
	}
	return blockValid, nil
}

// trustedBlocklistKeys splits the fingerprints trusted for an origin into the
// keys this server holds and the fingerprints it does not, so that a caller can
// tell "this signature is bad" from "the key that would vouch for it is not
// here yet".
func (st *storage) trustedBlocklistKeys(fingerprints []string) (trusted []*openpgp.PrimaryKey, absent []string, _ error) {
	records, err := st.FetchRecordsByFp(fingerprints)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	present := make(map[string]bool, len(records))
	for _, record := range records {
		if record.PrimaryKey == nil {
			continue
		}
		trusted = append(trusted, record.PrimaryKey)
		present[record.Fingerprint] = true
	}
	for _, fingerprint := range fingerprints {
		if !present[fingerprint] {
			absent = append(absent, fingerprint)
		}
	}
	return trusted, absent, nil
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

// admitTombstone decides whether an incoming blocklist tombstone may be stored.
//
// A tombstone makes this server drop key material, so it is only honoured when
// the operator has said whose blocks to honour: its origin must be configured
// as trusted, and its signature must verify against one of that origin's keys.
// Nothing is trusted by default, so a server that has not been configured for
// blocklists ignores every tombstone offered to it.
//
// This sits in storage rather than at each ingress because every route that
// writes key material converges here, so reconciliation, HKP submission and
// keydump loading are all covered by the one check.
func (st *storage) admitTombstone(key *openpgp.PrimaryKey) error {
	if !openpgp.IsTombstone(key) {
		return nil
	}
	verdict, err := st.judgeTombstone(key)
	if verdict == blockValid {
		log.Debugf("admitted tombstone for 0x%s", key.Fingerprint)
		return nil
	}
	return errors.Wrapf(hkpstorage.ErrBlockRefused, "tombstone for 0x%s: %v", key.Fingerprint, err)
}

// admitTombstones splits a batch into the keys that may be stored and the
// errors for those that may not, so that one refused tombstone does not sink a
// whole keydump.
func (st *storage) admitTombstones(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError) []*openpgp.PrimaryKey {
	admitted := make([]*openpgp.PrimaryKey, 0, len(keys))
	for _, key := range keys {
		if err := st.admitTombstone(key); err != nil {
			log.Warn(err)
			result.Errors = append(result.Errors, err)
			continue
		}
		admitted = append(admitted, key)
	}
	return admitted
}

// blockedInTx reports the digest of the tombstone stored for a fingerprint, or
// the empty string if the fingerprint is not blocked.
//
// It runs inside the caller's transaction and takes a row lock, so that a
// decision made here still holds when the caller acts on it.
func blockedInTx(tx *sql.Tx, fingerprint string) (string, error) {
	var md5, doc string
	err := tx.QueryRow("SELECT md5, doc::TEXT FROM keys WHERE rfingerprint = reverse($1) FOR UPDATE",
		fingerprint).Scan(&md5, &doc)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", errors.WithStack(err)
	}
	var pk jsonhkp.PrimaryKey
	if err := json.Unmarshal([]byte(doc), &pk); err != nil {
		return "", errors.WithStack(err)
	}
	// A tombstone is rooted at a trust packet; ordinary key material is rooted
	// at a public key packet.
	if pk.Packet == nil || pk.Packet.Tag != 12 {
		return "", nil
	}
	return md5, nil
}

// verifyBlocks re-checks the blocks this server is holding, and removes the ones
// it can prove are bad.
//
// hockeypuck-load stores blocks without checking them, because on a keydump
// restore the key that vouches for a block is usually not in the database yet.
// This is where that check is made good, once the whole dump is in.
//
// A block whose signature does not verify is deleted: it is forged or corrupt,
// and the key it names should never have been hidden. A block this server merely
// cannot judge - because the origin is not configured, or the key that would
// vouch for it is absent - is left alone and counted. Deleting those would mean
// a typo in trustedOrigins, or a signing key not yet loaded, silently withdrew
// blocks the operator had asked for.
func (st *storage) verifyBlocks() {
	var checked, removed, unverifiable int
	// Page on the fingerprint, not on mtime: a keydump load stamps every row it
	// writes with the same timestamp, so an mtime bookmark would stop dead after
	// the first bunch and leave the rest of them unchecked.
	bookmark := ""

	for {
		select {
		case <-st.t.Dying():
			return
		default:
		}

		records, err := st.blocksAfter(bookmark, internalQueryLimit)
		if err != nil {
			log.Errorf("could not scan blocklist tombstones: %v", err)
			return
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			bookmark = record.Fingerprint
			if record.PrimaryKey == nil {
				continue
			}
			checked++
			verdict, err := st.judgeTombstone(record.PrimaryKey)
			switch verdict {
			case blockValid:
			case blockUnverifiable:
				unverifiable++
				log.Warnf("cannot verify block on 0x%s, leaving it in place: %v",
					record.Fingerprint, err)
			case blockInvalid:
				log.Errorf("removing bad block on 0x%s: %v", record.Fingerprint, err)
				gone, delErr := st.removeInvalidBlock(record.Fingerprint)
				if delErr != nil {
					log.Errorf("could not remove bad block on 0x%s: %v", record.Fingerprint, delErr)
					continue
				}
				if !gone {
					log.Infof("block on 0x%s changed while the sweep was judging it, leaving it alone",
						record.Fingerprint)
					continue
				}
				removed++
			}
		}
	}

	if checked == 0 {
		return
	}
	log.Infof("checked %d blocklist tombstones: %d removed as invalid, %d could not be verified",
		checked, removed, unverifiable)
}

// ensureTombstoneIndex builds the partial index the sweep pages through.
//
// It is built here rather than in createIndexes, and CONCURRENTLY, because it is
// the one index this series adds to a table that existing servers have already
// filled. A plain CREATE INDEX in createIndexes' single transaction would make
// the first startup after an upgrade evaluate the predicate over every row of
// keys - detoasting each doc to do it - while holding a lock that blocks
// writes. On a keyserver holding millions of keys that is a long, silent stall,
// and "it matches no rows" is no help: PostgreSQL has to read them all to find
// that out.
//
// CONCURRENTLY cannot run inside a transaction, so this runs on the pool and in
// the background. Failure is not fatal: blocksAfter is correct without the
// index, only slower.
func (st *storage) ensureTombstoneIndex() {
	exists, valid, err := st.tombstoneIndexState()
	if err != nil {
		log.Warnf("could not check for the %s index: %v", tombstoneIndexName, err)
		return
	}
	if exists && valid {
		return
	}
	if exists {
		// A previous CONCURRENTLY build was interrupted and left the index
		// behind, unusable. IF NOT EXISTS would keep it, so clear it first.
		log.Warnf("%s was left invalid by an interrupted build; rebuilding it", tombstoneIndexName)
		if _, err := st.Exec("DROP INDEX CONCURRENTLY IF EXISTS " + tombstoneIndexName); err != nil {
			log.Errorf("could not drop the invalid %s index: %v", tombstoneIndexName, err)
			return
		}
	}
	log.Infof("building the %s index in the background; blocklist sweeps scan the keys table until it is ready",
		tombstoneIndexName)
	start := time.Now()
	if _, err := st.Exec(tombstoneIndexSQL); err != nil {
		log.Errorf("could not build the %s index; blocklist sweeps will scan instead: %v",
			tombstoneIndexName, err)
		return
	}
	log.Infof("built the %s index in %v", tombstoneIndexName, time.Since(start))
}

// tombstoneIndexState reports whether the index is there, and whether it is
// usable: an interrupted CONCURRENTLY build leaves one that exists but is not.
func (st *storage) tombstoneIndexState() (exists, valid bool, _ error) {
	err := st.QueryRow(
		"SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname = $1",
		tombstoneIndexName).Scan(&valid)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	if err != nil {
		return false, false, errors.WithStack(err)
	}
	return true, valid, nil
}

// removeInvalidBlock deletes a block, but only if it is still the same bad block
// the sweep judged.
//
// The sweep reads a bunch of blocks, judges them one at a time, and deletes what
// it can prove is bad - so between the judgement and the delete, a valid block
// for that fingerprint can arrive by reconciliation and take the bad one's
// place. Deleting by fingerprint alone would then remove the good one. Nor is
// comparing digests enough to notice the swap: two tombstones for the same
// fingerprint share an SKS digest by design, which is the whole reason
// reconciliation converges on them.
//
// So the block is re-read and re-judged with the fingerprint locked. No writer
// for it can commit while that lock is held, which is what makes the block read
// here the block deleted below.
func (st *storage) removeInvalidBlock(fingerprint string) (removed bool, retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			retErr = tx.Commit()
		}
	}()
	if err := lockFingerprintTx(tx, fingerprint); err != nil {
		return false, err
	}

	records, err := st.FetchRecordsByFp([]string{fingerprint}, hkpstorage.IncludeTombstones)
	if err != nil {
		return false, errors.WithStack(err)
	}
	var current *hkpstorage.Record
	for _, record := range records {
		if record.Fingerprint == fingerprint {
			current = record
			break
		}
	}
	if current == nil || !openpgp.IsTombstone(current.PrimaryKey) {
		// Withdrawn, or displaced by key material, since the sweep looked.
		return false, nil
	}
	if verdict, _ := st.judgeTombstone(current.PrimaryKey); verdict != blockInvalid {
		return false, nil
	}

	md5, err := st.deleteTx(tx, fingerprint)
	if err != nil {
		if errors.Is(err, hkpstorage.ErrKeyNotFound) {
			return false, nil
		}
		return false, errors.WithStack(err)
	}
	st.Notify(hkpstorage.KeyRemoved{ID: fingerprint, Digest: md5})
	return true, nil
}

// blocksAfter returns a bounded bunch of stored tombstones ordered by reversed
// fingerprint, so that the sweep can page through them all. The ordering column
// is the primary key, which is unique; paging on a timestamp would lose rows
// whenever more than a bunch of them shared one.
func (st *storage) blocksAfter(afterFingerprint string, limit int) ([]*hkpstorage.Record, error) {
	// Ordered and paged on the same expression, which is also the one the
	// keys_tombstones index is built over. Paging on a timestamp instead would
	// lose rows whenever more than a bunch of them shared one.
	return st.fetchRecordsByQuery(
		[]string{"WHERE reverse(rfingerprint) > $1 AND doc->'packet'->>'tag' = '12'"},
		"ORDER BY 1 LIMIT $2",
		[]any{afterFingerprint, limit},
		hkpstorage.IncludeTombstones)
}
