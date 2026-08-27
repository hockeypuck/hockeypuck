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
	"bytes"
	"database/sql"
	"time"

	gocrypto "github.com/ProtonMail/go-crypto/openpgp"
	gc "gopkg.in/check.v1"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"
	"hockeypuck/pgtest"
	hktesting "hockeypuck/testing"
)

// TS exercises blocklist tombstones against a real database. It needs its own
// suite rather than reusing S, because the policy has to carry a trusted
// blocklist origin and S builds one without.
type TS struct {
	pgtest.PGSuite
	db      *sql.DB
	storage *storage
	// signer issues blocks for the trusted origin; origin is its public half as
	// the server holds it.
	signer *gocrypto.Entity
	origin *openpgp.PrimaryKey
}

var _ = gc.Suite(&TS{})

const tsOrigin = "keys.example.com"

func (s *TS) SetUpTest(c *gc.C) {
	s.PGSuite.SetUpTest(c)

	var err error
	s.db, err = sql.Open("postgres", s.URL)
	c.Assert(err, gc.IsNil)
	s.db.Exec("DROP DATABASE hkp")

	// Mint the origin's signing key before the policy, so its fingerprint can be
	// the trusted one.
	s.signer, err = gocrypto.NewEntity("Blocklist Origin", "", "origin@example.com", nil)
	c.Assert(err, gc.IsNil)
	var pub bytes.Buffer
	c.Assert(s.signer.Serialize(&pub), gc.IsNil)
	origins, err := openpgp.NewKeyReader(bytes.NewReader(pub.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(origins, gc.HasLen, 1)
	s.origin = origins[0]

	policy, err := openpgp.NewPolicy(
		openpgp.BlocklistOrigin(tsOrigin),
		openpgp.TrustBlocklistOrigin(tsOrigin, []string{s.origin.Fingerprint}),
	)
	c.Assert(err, gc.IsNil)
	st, err := New(s.db, policy, 100)
	c.Assert(err, gc.IsNil)
	s.storage = st.(*storage)
}

func (s *TS) TearDownTest(c *gc.C) {
	if s.db != nil {
		s.db.Exec("DROP DATABASE hkp")
		s.db.Close()
	}
	s.PGSuite.TearDownTest(c)
}

// victim reads the key used as the subject of a block. It is not stored;
// callers that need it present do that themselves.
func (s *TS) victim(c *gc.C) *openpgp.PrimaryKey {
	keys, err := openpgp.ReadArmorKeys(hktesting.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	return keys[0]
}

// trustOrigin stores the origin's public key, without which no block can be
// admitted: verification needs the key to be present in the keyserver.
func (s *TS) trustOrigin(c *gc.C) {
	_, err := s.storage.Upsert(s.origin)
	c.Assert(err, gc.IsNil)
}

func (s *TS) block(c *gc.C, fingerprint string, signed bool) *openpgp.PrimaryKey {
	ts := openpgp.Tombstone{Fingerprint: fingerprint, Origin: tsOrigin, Reason: "abuse"}
	if !signed {
		tombstone, err := openpgp.NewTombstone(ts)
		c.Assert(err, gc.IsNil)
		return tombstone
	}
	sig, err := openpgp.SignTombstone(ts, s.signer)
	c.Assert(err, gc.IsNil)
	tombstone, err := openpgp.NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)
	return tombstone
}

// blockFrom is block for a tombstone that claims some other origin, or that was
// signed by some other key than the one this server trusts.
func (s *TS) blockFrom(c *gc.C, fingerprint, origin string, signer *gocrypto.Entity) *openpgp.PrimaryKey {
	ts := openpgp.Tombstone{Fingerprint: fingerprint, Origin: origin, Reason: "abuse"}
	if signer == nil {
		tombstone, err := openpgp.NewTombstone(ts)
		c.Assert(err, gc.IsNil)
		return tombstone
	}
	sig, err := openpgp.SignTombstone(ts, signer)
	c.Assert(err, gc.IsNil)
	tombstone, err := openpgp.NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)
	return tombstone
}

// newSigner mints a key and stores its public half, returning both halves. Use
// it for a second trusted key, or for one this server should refuse.
func (s *TS) newSigner(c *gc.C, name, email string, store bool) (*gocrypto.Entity, *openpgp.PrimaryKey) {
	entity, err := gocrypto.NewEntity(name, "", email, nil)
	c.Assert(err, gc.IsNil)
	var pub bytes.Buffer
	c.Assert(entity.Serialize(&pub), gc.IsNil)
	keys, err := openpgp.NewKeyReader(bytes.NewReader(pub.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	if store {
		_, err = s.storage.Upsert(keys[0])
		c.Assert(err, gc.IsNil)
	}
	return entity, keys[0]
}

// trustKeys rebuilds the storage policy to trust exactly these fingerprints for
// the test origin.
func (s *TS) trustKeys(c *gc.C, fingerprints ...string) {
	policy, err := openpgp.NewPolicy(
		openpgp.BlocklistOrigin(tsOrigin),
		openpgp.TrustBlocklistOrigin(tsOrigin, fingerprints),
	)
	c.Assert(err, gc.IsNil)
	s.storage.policy = policy
}

func (s *TS) storedTag(c *gc.C, fingerprint string) (isTombstone, present bool) {
	records, err := s.storage.FetchRecordsByFp([]string{fingerprint}, hkpstorage.IncludeTombstones)
	c.Assert(err, gc.IsNil)
	for _, record := range records {
		if record.Fingerprint == fingerprint {
			return openpgp.IsTombstone(record.PrimaryKey), true
		}
	}
	return false, false
}

func (s *TS) componentCounts(c *gc.C, fingerprint string) (subkeys, userids int) {
	rfp := types.Reverse(fingerprint)
	c.Assert(s.db.QueryRow("SELECT count(*) FROM subkeys WHERE rfingerprint = $1", rfp).Scan(&subkeys), gc.IsNil)
	c.Assert(s.db.QueryRow("SELECT count(*) FROM userids WHERE rfingerprint = $1", rfp).Scan(&userids), gc.IsNil)
	return subkeys, userids
}

// TestUnsignedBlockRefused: a block with no signature is never admitted over the
// network paths, however trusted its origin.
func (s *TS) TestUnsignedBlockRefused(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, false))
	c.Assert(err, gc.NotNil)
	c.Check(hkpstorage.IsBlockRefused(err), gc.Equals, true)
	_, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, false)
}

// TestUnknownOriginRefused: an origin the configuration says nothing about is
// refused outright, however well signed the block is.
func (s *TS) TestUnknownOriginRefused(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	ts := openpgp.Tombstone{Fingerprint: victim.Fingerprint, Origin: "someone.else.example", Reason: "abuse"}
	sig, err := openpgp.SignTombstone(ts, s.signer)
	c.Assert(err, gc.IsNil)
	tombstone, err := openpgp.NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)

	_, err = s.storage.Upsert(tombstone)
	c.Assert(err, gc.NotNil)
	c.Check(hkpstorage.IsBlockRefused(err), gc.Equals, true)
	c.Check(err, gc.ErrorMatches, ".*no keys are trusted for blocklist origin.*")
	_, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, false)
}

// TestTrustedOriginWithMissingKeyRefused: the origin is trusted, but the key
// that vouches for it is not in the keyserver, so nothing can be verified.
func (s *TS) TestTrustedOriginWithMissingKeyRefused(c *gc.C) {
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.NotNil)
	c.Check(hkpstorage.IsBlockRefused(err), gc.Equals, true)
	c.Check(err, gc.ErrorMatches, ".*are in this keyserver.*")
}

// TestBlockReplacesKeyMaterial is the core behaviour: a block takes the key's
// place, and the key's components go with it.
func (s *TS) TestBlockReplacesKeyMaterial(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(victim)
	c.Assert(err, gc.IsNil)
	subkeys, userids := s.componentCounts(c, victim.Fingerprint)
	c.Assert(subkeys+userids > 0, gc.Equals, true, gc.Commentf("victim should have components to lose"))

	_, err = s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true)
	subkeys, userids = s.componentCounts(c, victim.Fingerprint)
	c.Check(subkeys, gc.Equals, 0)
	c.Check(userids, gc.Equals, 0, gc.Commentf("a block must not leave the blocked key's user IDs behind"))
}

// TestBlockedKeyRefusedOnReingest: once blocked, the key cannot come back.
func (s *TS) TestBlockedKeyRefusedOnReingest(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	kc, err := s.storage.Upsert(victim)
	c.Assert(err, gc.IsNil)
	_, refused := kc.(hkpstorage.KeyBlocked)
	c.Check(refused, gc.Equals, true)
	c.Check(kc.InsertDigests(), gc.HasLen, 0,
		gc.Commentf("a refused key must not be advertised to partners"))

	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Check(isTombstone, gc.Equals, true)
}

// TestReplaceDoesNotWithdrawABlock: Replace deletes before inserting, so without
// a guard ordinary key material would quietly remove a block and take its place.
// Only an explicit unblock may withdraw one.
func (s *TS) TestReplaceDoesNotWithdrawABlock(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	kc, err := s.storage.Replace(victim)
	c.Assert(err, gc.IsNil)
	_, refused := kc.(hkpstorage.KeyBlocked)
	c.Check(refused, gc.Equals, true)

	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Check(isTombstone, gc.Equals, true, gc.Commentf("the block must survive a Replace"))
}

// TestQueryVisibility: to a caller asking for key material a blocked key is
// simply absent, but reconciliation and dumps must still see it.
func (s *TS) TestQueryVisibility(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	records, err := s.storage.FetchRecordsByFp([]string{victim.Fingerprint})
	c.Assert(err, gc.IsNil)
	c.Check(records, gc.HasLen, 0, gc.Commentf("a block must not answer a key material query"))

	records, err = s.storage.FetchRecordsByFp([]string{victim.Fingerprint}, hkpstorage.IncludeTombstones)
	c.Assert(err, gc.IsNil)
	c.Check(records, gc.HasLen, 1)
}

// TestInsertStoresBlocksUnchecked covers a keydump restore. The key vouching for
// a block is usually in a different shard of the dump, so Insert stores blocks
// without checking them and leaves the verdict to the preening sweep. Nothing
// here trusts the origin, and the block is stored all the same.
func (s *TS) TestInsertStoresBlocksUnchecked(c *gc.C) {
	victim := s.victim(c)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, true)})
	c.Assert(err, gc.IsNil)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true, gc.Commentf("restoring a dump must not drop its blocks"))
	c.Check(isTombstone, gc.Equals, true)
}

// TestInsertStoresEvenAnUnsignedBlock: the load path makes no judgement at all,
// so even a block that could never verify is stored, for the sweep to remove.
func (s *TS) TestInsertStoresEvenAnUnsignedBlock(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, false)})
	c.Assert(err, gc.IsNil)
	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true)
}

// TestInsertDoesNotDoubleCount: a block is not key material, so it is reported
// separately. Folding it into these totals counted a fingerprint whose material
// and block were both in the batch once as inserted and again as updated.
func (s *TS) TestInsertDoesNotDoubleCount(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	u, n, err := s.storage.Insert([]*openpgp.PrimaryKey{
		victim, s.block(c, victim.Fingerprint, true),
	})
	c.Assert(err, gc.IsNil)
	c.Check(u+n, gc.Equals, 1,
		gc.Commentf("one fingerprint went in, so the totals should account for one"))

	// And the block is what survived.
	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true)
}

// TestBulkInsertAppliesBlocks covers the bulk path, which the batches above are
// too small to reach. Bulk insertion skips any fingerprint already in keys, so a
// block has to be applied outside it or it would count as a duplicate and the
// key would survive.
func (s *TS) TestBulkInsertAppliesBlocks(c *gc.C) {
	restore := minKeys2UseBulk
	minKeys2UseBulk = 2
	defer func() { minKeys2UseBulk = restore }()

	s.trustOrigin(c)
	victim := s.victim(c)
	filler, err := openpgp.ReadArmorKeys(hktesting.MustInput("alice_signed.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(filler, gc.HasLen, 1)

	// Key material and its block in one batch, large enough to take the bulk path.
	batch := []*openpgp.PrimaryKey{victim, filler[0], s.block(c, victim.Fingerprint, true)}
	_, _, err = s.storage.Insert(batch)
	c.Assert(err, gc.IsNil)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true,
		gc.Commentf("a block must displace key material even when the batch went through bulk insertion"))
	subkeys, userids := s.componentCounts(c, victim.Fingerprint)
	c.Check(subkeys, gc.Equals, 0)
	c.Check(userids, gc.Equals, 0)

	// The unrelated key in the same batch is unaffected.
	_, present = s.storedTag(c, filler[0].Fingerprint)
	c.Check(present, gc.Equals, true)
}

// TestInsertSurvivesAnErrorHeavyBatch: giving up on a batch full of bad key
// material must not discard the blocks that batch also carried.
func (s *TS) TestInsertSurvivesAnErrorHeavyBatch(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	batch := []*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, true)}
	for i := 0; i < maxInsertErrors+2; i++ {
		// A key with no packet data at all fails to store.
		batch = append(batch, &openpgp.PrimaryKey{})
	}
	s.storage.Insert(batch)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true, gc.Commentf("the block must outlive the failures around it"))
	c.Check(isTombstone, gc.Equals, true)
}

// TestReindexLeavesBlocksAlone: the reindexing pass sweeps the keys table with
// raw SQL, so it sees blocks whether or not other queries hide them. It must
// treat one as a no-op rather than evaporating it or rewriting its keywords.
//
// This also matters for any future deferred verification: that pass is the
// natural place to hang it, and it has to cope with blocks first.
func (s *TS) TestReindexLeavesBlocksAlone(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	before, _ := s.storedTag(c, victim.Fingerprint)
	c.Assert(before, gc.Equals, true)

	c.Assert(s.storage.Reindex(), gc.IsNil)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true, gc.Commentf("reindexing must not remove a block"))
	c.Check(isTombstone, gc.Equals, true)

	// And it is still readable as the block it was.
	records, err := s.storage.FetchRecordsByFp([]string{victim.Fingerprint}, hkpstorage.IncludeTombstones)
	c.Assert(err, gc.IsNil)
	c.Assert(records, gc.HasLen, 1)
	ts, sigs, err := openpgp.TombstoneOf(records[0].PrimaryKey)
	c.Assert(err, gc.IsNil)
	c.Check(ts.Origin, gc.Equals, tsOrigin)
	c.Check(sigs, gc.HasLen, 1, gc.Commentf("the origin signature must survive reindexing"))
}

// TestVerifyBlocksRemovesForgeries: the sweep settles the debt the load path
// leaves. A block that cannot possibly verify is removed, and the key it was
// hiding becomes available again.
func (s *TS) TestVerifyBlocksRemovesForgeries(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	// Stored the way a keydump would store it: unchecked.
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, false)})
	c.Assert(err, gc.IsNil)
	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Assert(isTombstone, gc.Equals, true)

	s.storage.verifyBlocks()

	_, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, false, gc.Commentf("an unsigned block must not survive the sweep"))
}

// TestVerifyBlocksKeepsValidOnes: a block that does verify is left alone, so the
// sweep is not simply deleting everything it looks at.
func (s *TS) TestVerifyBlocksKeepsValidOnes(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, true)})
	c.Assert(err, gc.IsNil)

	s.storage.verifyBlocks()

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true, gc.Commentf("a valid block must survive the sweep"))
	c.Check(isTombstone, gc.Equals, true)
}

// TestVerifyBlocksLeavesUnjudgeableOnes: when this server cannot judge a block -
// the origin is not configured, or the key that would vouch for it is absent -
// it is kept. Removing it would let a typo in trustedOrigins, or a signing key
// not yet loaded, silently withdraw blocks the operator asked for.
func (s *TS) TestVerifyBlocksLeavesUnjudgeableOnes(c *gc.C) {
	victim := s.victim(c)
	// Note: no trustOrigin, so the signing key is not in the keyserver.
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, true)})
	c.Assert(err, gc.IsNil)

	s.storage.verifyBlocks()

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true,
		gc.Commentf("a block we cannot check must be kept, not silently withdrawn"))
	c.Check(isTombstone, gc.Equals, true)
}

// TestVerifyBlocksPagesThroughAll: a keydump load stamps every row it writes
// with the same timestamp, so a sweep that paged on mtime would stop after the
// first bunch. Force a bunch size of one and check every block is still seen.
func (s *TS) TestVerifyBlocksPagesThroughAll(c *gc.C) {
	s.trustOrigin(c)
	// Three unsigned blocks, all written in one Insert so they share an mtime.
	fingerprints := []string{
		"81279eee7ec89fb781702adaf79362da44a2d1db",
		"10fe8cf1b483f7525039aa2a361bc1f023e0dcca",
		"abd00913019d6354ba1d9a132839fe0d796198b1",
	}
	var batch []*openpgp.PrimaryKey
	for _, fp := range fingerprints {
		batch = append(batch, s.block(c, fp, false))
	}
	_, _, err := s.storage.Insert(batch)
	c.Assert(err, gc.IsNil)
	for _, fp := range fingerprints {
		isTombstone, _ := s.storedTag(c, fp)
		c.Assert(isTombstone, gc.Equals, true)
	}

	// One at a time, so paging has to work for all three to be reached.
	seen := map[string]bool{}
	bookmark := ""
	for {
		records, err := s.storage.blocksAfter(bookmark, 1)
		c.Assert(err, gc.IsNil)
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			c.Assert(seen[record.Fingerprint], gc.Equals, false,
				gc.Commentf("paging returned 0x%s twice", record.Fingerprint))
			seen[record.Fingerprint] = true
			bookmark = record.Fingerprint
		}
	}
	c.Check(seen, gc.HasLen, len(fingerprints),
		gc.Commentf("every block must be reachable by paging, not just the first bunch"))

	// And the sweep removes all of them, not just the first.
	s.storage.verifyBlocks()
	for _, fp := range fingerprints {
		_, present := s.storedTag(c, fp)
		c.Check(present, gc.Equals, false, gc.Commentf("0x%s survived the sweep", fp))
	}
}

// TestVerifyBlocksRemovesUnsignedBlocksFromAnyOrigin: an unsigned block is a
// defect in the block itself, so the sweep removes it whether or not this server
// has anything to say about the origin it claims. Judging trust first would keep
// unsigned blocks forever on every server that has not opted into that origin -
// which is every server, for an origin nobody configured.
func (s *TS) TestVerifyBlocksRemovesUnsignedBlocksFromAnyOrigin(c *gc.C) {
	victim := s.victim(c)
	block := s.blockFrom(c, victim.Fingerprint, "nobody-configured.example.com", nil)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{block})
	c.Assert(err, gc.IsNil)
	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Assert(isTombstone, gc.Equals, true)

	s.storage.verifyBlocks()

	_, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, false,
		gc.Commentf("an unsigned block must not survive, whatever origin it claims"))
}

// TestVerifyBlocksKeepsOnesSignedByAnAbsentTrustedKey: with two keys trusted for
// an origin and only one of them in the keyserver, a block signed by the other
// fails to verify - but that failure proves nothing, because the key that would
// vouch for it was never available to check against. Deleting on that would mean
// a trusted key not yet loaded silently withdrew its own blocks, which is exactly
// what a keydump restore looks like part way through.
func (s *TS) TestVerifyBlocksKeepsOnesSignedByAnAbsentTrustedKey(c *gc.C) {
	_, present := s.newSigner(c, "Present Origin", "present@example.com", true)
	// Both are trusted; only the second one is here. The block is signed by
	// s.signer, whose key is not stored.
	s.trustKeys(c, s.origin.Fingerprint, present.Fingerprint)

	victim := s.victim(c)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, true)})
	c.Assert(err, gc.IsNil)

	s.storage.verifyBlocks()

	isTombstone, stored := s.storedTag(c, victim.Fingerprint)
	c.Check(stored, gc.Equals, true,
		gc.Commentf("a block whose trusted signer is absent must be kept, not deleted"))
	c.Check(isTombstone, gc.Equals, true)
}

// TestVerifyBlocksRemovesBlocksSignedByAnUntrustedKey: the converse of the
// above. When every key trusted for the origin is in the keyserver, a signature
// that verifies against none of them really is forged, and the sweep removes it.
// Without this the previous test would be satisfied by a sweep that never
// deletes anything.
func (s *TS) TestVerifyBlocksRemovesBlocksSignedByAnUntrustedKey(c *gc.C) {
	s.trustOrigin(c)
	rogue, _ := s.newSigner(c, "Rogue", "rogue@example.com", false)

	victim := s.victim(c)
	block := s.blockFrom(c, victim.Fingerprint, tsOrigin, rogue)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{block})
	c.Assert(err, gc.IsNil)
	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Assert(isTombstone, gc.Equals, true)

	s.storage.verifyBlocks()

	_, stored := s.storedTag(c, victim.Fingerprint)
	c.Check(stored, gc.Equals, false,
		gc.Commentf("a block signed by an untrusted key must not survive when the trusted key was there to check it"))
}

type replaceResult struct {
	kc  hkpstorage.KeyChange
	err error
}

// TestReplaceWaitsForAConcurrentBlock: the row lock blockedInTx takes covers
// only a row that exists, so on its own it cannot stop a block being committed
// for a fingerprint that is currently empty - and a replacement that had already
// decided the fingerprint was free would then delete that fresh block, or report
// a KeyAdded for material it never stored. Writers of one fingerprint therefore
// take a lock on the name as well.
func (s *TS) TestReplaceWaitsForAConcurrentBlock(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	// A block that has taken the fingerprint but not yet committed.
	tx, err := s.storage.Begin()
	c.Assert(err, gc.IsNil)
	_, err = s.storage.insertKeyTx(tx, s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	done := make(chan replaceResult, 1)
	go func() {
		kc, err := s.storage.Replace(victim)
		done <- replaceResult{kc, err}
	}()

	select {
	case r := <-done:
		tx.Rollback()
		c.Fatalf("Replace decided the fingerprint was free while a block was being written: %v (%v)", r.kc, r.err)
	case <-time.After(500 * time.Millisecond):
	}

	c.Assert(tx.Commit(), gc.IsNil)

	select {
	case r := <-done:
		c.Assert(r.err, gc.IsNil)
		_, refused := r.kc.(hkpstorage.KeyBlocked)
		c.Check(refused, gc.Equals, true,
			gc.Commentf("expected the replacement to be refused, got %#v", r.kc))
	case <-time.After(30 * time.Second):
		c.Fatal("Replace never finished after the block committed")
	}

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true,
		gc.Commentf("the block must still be in place after the replacement was refused"))
}

// TestReblockDoesNotDropTheDigest: two blocks for one fingerprint share an SKS
// digest by design - that is what makes reconciliation converge on them - so
// replacing one with the other changes the stored certificate in a way the
// digest does not see. Emitting an insert and a remove of the same element would
// leave the prefix tree no longer advertising a block the database holds,
// because the peer applies every queued insert before every queued remove.
func (s *TS) TestReblockDoesNotDropTheDigest(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	first := s.block(c, victim.Fingerprint, true)
	_, err := s.storage.Upsert(first)
	c.Assert(err, gc.IsNil)

	// The same fingerprint blocked again, differing only in its annotations.
	ts := openpgp.Tombstone{Fingerprint: victim.Fingerprint, Origin: tsOrigin, Reason: "gdpr"}
	sig, err := openpgp.SignTombstone(ts, s.signer)
	c.Assert(err, gc.IsNil)
	second, err := openpgp.NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)
	c.Assert(second.MD5, gc.Equals, first.MD5,
		gc.Commentf("blocks for one fingerprint are meant to share a digest"))

	kc, err := s.storage.Upsert(second)
	c.Assert(err, gc.IsNil)
	replaced, ok := kc.(hkpstorage.KeyReplaced)
	c.Assert(ok, gc.Equals, true, gc.Commentf("expected a replacement, got %#v", kc))
	c.Check(replaced.InsertDigests(), gc.HasLen, 0)
	c.Check(replaced.RemoveDigests(), gc.HasLen, 0,
		gc.Commentf("a same-digest replacement must not withdraw the element from the prefix tree"))

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true)
}

// TestSweepLeavesABlockThatChangedUnderIt: the sweep judges a block, then
// deletes it - and a valid block for the same fingerprint can arrive in between.
// Deleting by fingerprint alone would remove the good one, and comparing digests
// would not notice, because the two share one.
func (s *TS) TestSweepLeavesABlockThatChangedUnderIt(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)

	// A bad block, stored the way a keydump would store it.
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{
		s.blockFrom(c, victim.Fingerprint, tsOrigin, nil)})
	c.Assert(err, gc.IsNil)

	// Judged the way the sweep judges it.
	records, err := s.storage.blocksAfter("", 10)
	c.Assert(err, gc.IsNil)
	c.Assert(records, gc.HasLen, 1)
	verdict, _ := s.storage.judgeTombstone(records[0].PrimaryKey)
	c.Assert(verdict, gc.Equals, blockInvalid)

	// A good block for the same fingerprint lands before the sweep acts.
	_, err = s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	gone, err := s.storage.removeInvalidBlock(victim.Fingerprint)
	c.Assert(err, gc.IsNil)
	c.Check(gone, gc.Equals, false,
		gc.Commentf("the sweep must not delete a block that became valid under it"))

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true)
}

// TestEnsureTombstoneIndexIsIdempotent: the sweep's index is built outside the
// transaction the other indexes share, and CONCURRENTLY, so that upgrading an
// existing keyserver does not stall behind a scan of every row of keys. It runs
// on every start, so it has to be a no-op once the index is there - and it has
// to replace one an interrupted build left invalid, which IF NOT EXISTS on its
// own would keep.
func (s *TS) TestEnsureTombstoneIndexIsIdempotent(c *gc.C) {
	exists, _, err := s.storage.tombstoneIndexState()
	c.Assert(err, gc.IsNil)
	c.Assert(exists, gc.Equals, false,
		gc.Commentf("the index must not be created with the others, or upgrades stall"))

	s.storage.ensureTombstoneIndex()
	exists, valid, err := s.storage.tombstoneIndexState()
	c.Assert(err, gc.IsNil)
	c.Check(exists, gc.Equals, true)
	c.Check(valid, gc.Equals, true)

	// Again, on a database that already has it.
	s.storage.ensureTombstoneIndex()
	exists, valid, err = s.storage.tombstoneIndexState()
	c.Assert(err, gc.IsNil)
	c.Check(exists, gc.Equals, true)
	c.Check(valid, gc.Equals, true)

	// And once more with the index marked invalid, as an interrupted build
	// would leave it.
	_, err = s.db.Exec("UPDATE pg_index SET indisvalid = false WHERE indexrelid = $1::regclass",
		tombstoneIndexName)
	c.Assert(err, gc.IsNil)
	_, valid, err = s.storage.tombstoneIndexState()
	c.Assert(err, gc.IsNil)
	c.Assert(valid, gc.Equals, false)

	s.storage.ensureTombstoneIndex()
	exists, valid, err = s.storage.tombstoneIndexState()
	c.Assert(err, gc.IsNil)
	c.Check(exists, gc.Equals, true)
	c.Check(valid, gc.Equals, true, gc.Commentf("an invalid index must be rebuilt, not kept"))
}

// TestSweepWorksWithoutTheIndex: the index is a performance aid that may still
// be building, or may have failed to build, so the sweep must not depend on it.
func (s *TS) TestSweepWorksWithoutTheIndex(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, _, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, false)})
	c.Assert(err, gc.IsNil)

	exists, _, err := s.storage.tombstoneIndexState()
	c.Assert(err, gc.IsNil)
	c.Assert(exists, gc.Equals, false)

	s.storage.verifyBlocks()

	_, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, false)
}
