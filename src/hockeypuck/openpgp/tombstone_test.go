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

package openpgp

import (
	"bytes"
	"strings"

	gc "gopkg.in/check.v1"

	"hockeypuck/testing"
)

type TombstoneSuite struct{}

var _ = gc.Suite(&TombstoneSuite{})

const (
	tsFpA = "10fe8cf1b483f7525039aa2a361bc1f023e0dcca"
	tsFpB = "5ad89a35c1284ff043f555b619caa24ebd1ba88d"
)

func mustTombstone(c *gc.C, ts Tombstone) *PrimaryKey {
	pubkey, err := NewTombstone(ts)
	c.Assert(err, gc.IsNil)
	return pubkey
}

// serialize round-trips a certificate through the packet reader, the way key
// material actually reaches storage.
func (s *TombstoneSuite) readBack(c *gc.C, keys ...*PrimaryKey) []*PrimaryKey {
	var buf bytes.Buffer
	for _, key := range keys {
		c.Assert(WritePackets(&buf, key), gc.IsNil)
	}
	out, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	return out
}

func (s *TombstoneSuite) TestRoundTrip(c *gc.C) {
	original := mustTombstone(c, Tombstone{
		Fingerprint: strings.ToUpper(tsFpA),
		Origin:      "pgpkeys.eu",
		Reason:      "abuse",
	})
	c.Check(IsTombstone(original), gc.Equals, true)
	c.Check(original.Fingerprint, gc.Equals, tsFpA, gc.Commentf("fingerprint should be folded to lowercase"))

	keys := s.readBack(c, original)
	c.Assert(keys, gc.HasLen, 1)
	got := keys[0]

	c.Check(IsTombstone(got), gc.Equals, true)
	c.Check(got.Fingerprint, gc.Equals, tsFpA)
	c.Check(got.MD5, gc.Equals, original.MD5)
	c.Check(got.TrustMD5, gc.Equals, original.TrustMD5)

	ts, sigs, err := TombstoneOf(got)
	c.Assert(err, gc.IsNil)
	c.Check(ts.Fingerprint, gc.Equals, tsFpA)
	c.Check(ts.Origin, gc.Equals, "pgpkeys.eu")
	c.Check(ts.Reason, gc.Equals, "abuse")
	c.Check(sigs, gc.HasLen, 0)
}

// TestDigestIsAnnotationIndependent is the property the whole design rests on.
// Two operators blocking the same key must agree on its reconciliation digest
// however much their annotations differ, or every tombstone becomes a permanent
// recon delta instead of converging.
func (s *TombstoneSuite) TestDigestIsAnnotationIndependent(c *gc.C) {
	mine := mustTombstone(c, Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "gdpr"})
	theirs := mustTombstone(c, Tombstone{Fingerprint: tsFpA, Origin: "keys.example.org"})

	c.Check(mine.MD5, gc.Equals, theirs.MD5,
		gc.Commentf("annotations must not affect the SKS digest"))
	c.Check(mine.TrustMD5, gc.Not(gc.Equals), theirs.TrustMD5,
		gc.Commentf("annotations must affect the trust digest, or updates go unnoticed"))

	other := mustTombstone(c, Tombstone{Fingerprint: tsFpB, Origin: "pgpkeys.eu"})
	c.Check(mine.MD5, gc.Not(gc.Equals), other.MD5,
		gc.Commentf("different keys must not collide"))
}

// TestInterleavedWithKeyMaterial checks that a tombstone in the middle of a
// keydump starts its own certificate rather than being absorbed by the key
// before it.
func (s *TombstoneSuite) TestInterleavedWithKeyMaterial(c *gc.C) {
	real1, err := ReadArmorKeys(testing.MustInput("alice_signed.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(real1, gc.HasLen, 1)
	real2, err := ReadArmorKeys(testing.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(real2, gc.HasLen, 1)

	tomb := mustTombstone(c, Tombstone{Fingerprint: tsFpB, Origin: "pgpkeys.eu"})

	keys := s.readBack(c, real1[0], tomb, real2[0])
	c.Assert(keys, gc.HasLen, 3, gc.Commentf("tombstone should not merge into a neighbouring key"))

	c.Check(IsTombstone(keys[0]), gc.Equals, false)
	c.Check(IsTombstone(keys[1]), gc.Equals, true)
	c.Check(IsTombstone(keys[2]), gc.Equals, false)

	c.Check(keys[0].Fingerprint, gc.Equals, real1[0].Fingerprint)
	c.Check(keys[1].Fingerprint, gc.Equals, tsFpB)
	c.Check(keys[2].Fingerprint, gc.Equals, real2[0].Fingerprint)
	// The real keys must come through untouched.
	c.Check(keys[0].MD5, gc.Equals, real1[0].MD5)
	c.Check(keys[2].MD5, gc.Equals, real2[0].MD5)
}

func (s *TombstoneSuite) TestRealKeyIsNotATombstone(c *gc.C) {
	keys, err := ReadArmorKeys(testing.MustInput("alice_signed.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	c.Check(IsTombstone(keys[0]), gc.Equals, false)
	_, _, err = TombstoneOf(keys[0])
	c.Check(err, gc.ErrorMatches, ".*not a blocklist tombstone.*")
}

func (s *TombstoneSuite) TestValidation(c *gc.C) {
	for _, test := range []struct {
		ts    Tombstone
		match string
	}{
		{Tombstone{Fingerprint: "abcd", Origin: "x"}, ".*not a fingerprint.*"},
		{Tombstone{Fingerprint: strings.Repeat("z", 40), Origin: "x"}, ".*not hexadecimal.*"},
		{Tombstone{Fingerprint: tsFpA}, ".*origin is required.*"},
		{Tombstone{Fingerprint: tsFpA, Origin: "a\nb"}, ".*must not contain newlines.*"},
		{Tombstone{Fingerprint: tsFpA, Origin: "x", Reason: "a\nb"}, ".*must not contain newlines.*"},
	} {
		_, err := NewTombstone(test.ts)
		c.Check(err, gc.ErrorMatches, test.match, gc.Commentf("for %+v", test.ts))
	}
}

// TestSigningMessageBindsEveryField guards against a tombstone being re-pointed
// at a different key or origin while keeping a signature made for another.
func (s *TombstoneSuite) TestSigningMessageBindsEveryField(c *gc.C) {
	base := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "gdpr"}
	msg := string(base.SigningMessage())
	c.Check(msg, gc.Equals,
		"blockedFingerprint="+tsFpA+"\nblocklistOrigin=pgpkeys.eu\nblocklistReason=gdpr\n")

	for _, altered := range []Tombstone{
		{Fingerprint: tsFpB, Origin: "pgpkeys.eu", Reason: "gdpr"},
		{Fingerprint: tsFpA, Origin: "evil.example", Reason: "gdpr"},
		{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"},
		{Fingerprint: tsFpA, Origin: "pgpkeys.eu"},
	} {
		c.Check(string(altered.SigningMessage()), gc.Not(gc.Equals), msg,
			gc.Commentf("for %+v", altered))
	}

	// Case folding must not produce a second signable form of the same block.
	upper := Tombstone{Fingerprint: strings.ToUpper(tsFpA), Origin: "pgpkeys.eu", Reason: "gdpr"}
	c.Check(string(upper.SigningMessage()), gc.Equals, msg)
}

// TestTrustDigestCoversFullPacket pins the fix to SksDigest: trustPacketSKSView
// truncates in place, so without a defensive copy the trust digest would cover
// only the SKS-visible prefix and updates to a tombstone would go unnoticed.
func (s *TombstoneSuite) TestTrustDigestCoversFullPacket(c *gc.C) {
	short := mustTombstone(c, Tombstone{Fingerprint: tsFpA, Origin: "a"})
	long := mustTombstone(c, Tombstone{Fingerprint: tsFpA, Origin: strings.Repeat("b", 64)})

	c.Check(short.MD5, gc.Equals, long.MD5)
	c.Check(short.TrustMD5, gc.Not(gc.Equals), long.TrustMD5)
}
