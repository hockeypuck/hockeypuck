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
	"time"

	gocrypto "github.com/ProtonMail/go-crypto/openpgp"
	gocryptoerrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
	gc "gopkg.in/check.v1"
)

type TombstoneVerifySuite struct{}

var _ = gc.Suite(&TombstoneVerifySuite{})

// originKey mints a throwaway key to stand in for an operator's blocklist
// signing key, returning both the private entity and the public form the
// server would hold.
func (s *TombstoneVerifySuite) originKey(c *gc.C) (*gocrypto.Entity, *PrimaryKey) {
	entity, err := gocrypto.NewEntity("Blocklist Origin", "", "origin@example.com", nil)
	c.Assert(err, gc.IsNil)

	var buf bytes.Buffer
	c.Assert(entity.Serialize(&buf), gc.IsNil)
	keys, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	return entity, keys[0]
}

func (s *TombstoneVerifySuite) sign(c *gc.C, entity *gocrypto.Entity, message []byte) *Signature {
	var buf bytes.Buffer
	c.Assert(gocrypto.DetachSign(&buf, entity, bytes.NewReader(message), nil), gc.IsNil)
	op, err := newOpaquePacket(buf.Bytes())
	c.Assert(err, gc.IsNil)
	sig, err := ParseSignature(op, time.Time{}, "", "")
	c.Assert(err, gc.IsNil)
	return sig
}

// TestSignedTombstoneSurvivesTheWire is the whole point of the signature: a
// tombstone that has been serialised, sent and re-read must still verify.
func (s *TombstoneVerifySuite) TestSignedTombstoneSurvivesTheWire(c *gc.C) {
	entity, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}

	tombstone, err := NewTombstone(ts, s.sign(c, entity, ts.SigningMessage()))
	c.Assert(err, gc.IsNil)

	var buf bytes.Buffer
	c.Assert(WritePackets(&buf, tombstone), gc.IsNil)
	received, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(received, gc.HasLen, 1)

	gotTS, gotSigs, err := TombstoneOf(received[0])
	c.Assert(err, gc.IsNil)
	c.Assert(gotSigs, gc.HasLen, 1, gc.Commentf("the signature must survive serialisation"))

	fp, err := VerifyTombstone(*gotTS, gotSigs, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)
	c.Check(fp, gc.Equals, pub.Fingerprint)
}

func (s *TombstoneVerifySuite) TestRejectsUntrustedSigner(c *gc.C) {
	entity, _ := s.originKey(c)
	_, otherPub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}

	sig := s.sign(c, entity, ts.SigningMessage())
	_, err := VerifyTombstone(ts, []*Signature{sig}, []*PrimaryKey{otherPub})
	c.Check(err, gc.ErrorMatches, ".*no trusted signature.*")
}

func (s *TombstoneVerifySuite) TestRejectsUnsigned(c *gc.C) {
	_, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	_, err := VerifyTombstone(ts, nil, []*PrimaryKey{pub})
	c.Check(err, gc.ErrorMatches, ".*carries no signature.*")
}

func (s *TombstoneVerifySuite) TestRejectsWhenNothingIsTrusted(c *gc.C) {
	entity, _ := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	sig := s.sign(c, entity, ts.SigningMessage())
	_, err := VerifyTombstone(ts, []*Signature{sig}, nil)
	c.Check(err, gc.ErrorMatches, ".*no keys are trusted for origin.*")
}

// TestSignatureBindsEveryField is the attack the signature exists to stop:
// taking a validly signed tombstone and re-pointing it at another key, another
// origin, or another reason.
func (s *TombstoneVerifySuite) TestSignatureBindsEveryField(c *gc.C) {
	entity, pub := s.originKey(c)
	signed := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}
	sig := s.sign(c, entity, signed.SigningMessage())

	// Sanity: it verifies as issued.
	_, err := VerifyTombstone(signed, []*Signature{sig}, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)

	for _, altered := range []Tombstone{
		{Fingerprint: tsFpB, Origin: "pgpkeys.eu", Reason: "abuse"},
		{Fingerprint: tsFpA, Origin: "evil.example", Reason: "abuse"},
		{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "gdpr"},
		{Fingerprint: tsFpA, Origin: "pgpkeys.eu"},
	} {
		_, err := VerifyTombstone(altered, []*Signature{sig}, []*PrimaryKey{pub})
		c.Check(err, gc.NotNil, gc.Commentf("re-pointed tombstone %+v must not verify", altered))
	}
}

// TestCaseFoldingDoesNotBreakVerification guards the normalisation seam: a
// tombstone signed with an uppercase fingerprint must still verify once stored
// in the lowercase form everything else uses.
func (s *TombstoneVerifySuite) TestCaseFoldingDoesNotBreakVerification(c *gc.C) {
	entity, pub := s.originKey(c)
	upper := Tombstone{Fingerprint: "10FE8CF1B483F7525039AA2A361BC1F023E0DCCA", Origin: "pgpkeys.eu"}
	sig := s.sign(c, entity, upper.SigningMessage())

	lower := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	_, err := VerifyTombstone(lower, []*Signature{sig}, []*PrimaryKey{pub})
	c.Check(err, gc.IsNil)
}

// TestSignThenVerifyRoundTrip closes the loop: what SignTombstone produces is
// what VerifyTombstone accepts, so the tooling that issues blocks and the
// server that admits them agree.
func (s *TombstoneVerifySuite) TestSignThenVerifyRoundTrip(c *gc.C) {
	entity, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}

	sig, err := SignTombstone(ts, entity)
	c.Assert(err, gc.IsNil)

	tombstone, err := NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)

	var buf bytes.Buffer
	c.Assert(WritePackets(&buf, tombstone), gc.IsNil)
	received, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(received, gc.HasLen, 1)

	gotTS, gotSigs, err := TombstoneOf(received[0])
	c.Assert(err, gc.IsNil)
	fp, err := VerifyTombstone(*gotTS, gotSigs, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)
	c.Check(fp, gc.Equals, pub.Fingerprint)
}

func (s *TombstoneVerifySuite) TestSignRequiresAPrivateKey(c *gc.C) {
	_, err := SignTombstone(Tombstone{Fingerprint: tsFpA, Origin: "x"}, nil)
	c.Check(err, gc.ErrorMatches, ".*requires a private key.*")
}

// signAt is sign with the clock wound back, so that a key which has since
// expired can still be made to produce a signature that was valid when it was
// made.
func (s *TombstoneVerifySuite) signAt(c *gc.C, entity *gocrypto.Entity, message []byte, when time.Time) *Signature {
	config := &packet.Config{Time: func() time.Time { return when }}
	var buf bytes.Buffer
	c.Assert(gocrypto.DetachSign(&buf, entity, bytes.NewReader(message), config), gc.IsNil)
	op, err := newOpaquePacket(buf.Bytes())
	c.Assert(err, gc.IsNil)
	sig, err := ParseSignature(op, time.Time{}, "", "")
	c.Assert(err, gc.IsNil)
	return sig
}

// TestRevokedKeyCannotIssueBlocks: an operator pins a fingerprint, not a key
// for all time. Once that key is revoked it must stop authorising blocks, or a
// compromised signing key would go on removing other people's keys for as long
// as its fingerprint stayed in a peer's configuration.
func (s *TombstoneVerifySuite) TestRevokedKeyCannotIssueBlocks(c *gc.C) {
	entity, _ := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	sig := s.sign(c, entity, ts.SigningMessage())

	c.Assert(entity.RevokeKey(packet.KeyCompromised, "lost", nil), gc.IsNil)
	var buf bytes.Buffer
	c.Assert(entity.Serialize(&buf), gc.IsNil)
	revoked, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(revoked, gc.HasLen, 1)

	_, err = VerifyTombstone(ts, []*Signature{sig}, []*PrimaryKey{revoked[0]})
	c.Assert(err, gc.NotNil, gc.Commentf("a revoked key must not vouch for a block"))
	// Named rather than merely non-nil, so the test cannot pass because the key
	// failed to parse for some unrelated reason.
	c.Check(errors.Is(err, gocryptoerrors.ErrKeyRevoked), gc.Equals, true,
		gc.Commentf("expected a revocation error, got %v", err))
}

// TestExpiredKeyCannotIssueBlocks: the same for a key that simply ran out. The
// signature maths still check out - only the key's own validity says otherwise.
func (s *TombstoneVerifySuite) TestExpiredKeyCannotIssueBlocks(c *gc.C) {
	past := time.Now().AddDate(0, 0, -30)
	config := &packet.Config{
		Time:            func() time.Time { return past },
		KeyLifetimeSecs: 3600,
	}
	entity, err := gocrypto.NewEntity("Expired Origin", "", "expired@example.com", config)
	c.Assert(err, gc.IsNil)
	var buf bytes.Buffer
	c.Assert(entity.Serialize(&buf), gc.IsNil)
	keys, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)

	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	// Signed while the key was still live, so only its expiry can reject it.
	sig := s.signAt(c, entity, ts.SigningMessage(), past)

	_, err = VerifyTombstone(ts, []*Signature{sig}, []*PrimaryKey{keys[0]})
	c.Assert(err, gc.NotNil, gc.Commentf("an expired key must not vouch for a block"))
	c.Check(errors.Is(err, gocryptoerrors.ErrKeyExpired), gc.Equals, true,
		gc.Commentf("expected an expiry error, got %v", err))
}

// TestUnreadableTrustedKeyIsUnverifiable: when the keys trusted for an origin
// are present but none can be read, the block is unjudgeable rather than bad.
// A caller that could not tell those apart would delete blocks over a parsing
// failure in the key that vouches for them.
func (s *TombstoneVerifySuite) TestUnreadableTrustedKeyIsUnverifiable(c *gc.C) {
	entity, _ := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	sig := s.sign(c, entity, ts.SigningMessage())

	// A tombstone is not a key, so it cannot be read as an entity.
	notAKey, err := NewTombstone(Tombstone{Fingerprint: tsFpB, Origin: "pgpkeys.eu"})
	c.Assert(err, gc.IsNil)

	_, err = VerifyTombstone(ts, []*Signature{sig}, []*PrimaryKey{notAKey})
	c.Assert(err, gc.NotNil)
	c.Check(errors.Is(err, ErrTombstoneUnverifiable), gc.Equals, true,
		gc.Commentf("expected an unverifiable verdict, got %v", err))
}

// TestLargeTombstoneSurvivesTheReader: the reader checks a packet's size before
// it knows what the packet is, and a tombstone is a trust packet whose size is
// dominated by the signature inside it. Holding it to the ordinary packet limit
// rather than the signature limit would silently drop exactly the blocks the
// larger limit exists for - those signed with a post-quantum algorithm - before
// anything had a chance to parse them.
func (s *TombstoneVerifySuite) TestLargeTombstoneSurvivesTheReader(c *gc.C) {
	const ordinaryLimit, signatureLimit = 8192, 65536

	entity, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}
	// Stand in for one big signature with several ordinary ones, which is the
	// only way to build an oversized tombstone without a post-quantum key.
	sigs := []*Signature{}
	var tombstone *PrimaryKey
	for len(sigs) < 64 {
		sigs = append(sigs, s.sign(c, entity, ts.SigningMessage()))
		built, err := NewTombstone(ts, sigs...)
		c.Assert(err, gc.IsNil)
		tombstone = built
		if tombstone.Length > ordinaryLimit {
			break
		}
	}
	c.Assert(tombstone.Length, gc.Not(gc.Equals), 0)
	c.Assert(tombstone.Length > ordinaryLimit, gc.Equals, true,
		gc.Commentf("wanted a tombstone over %d bytes, got %d", ordinaryLimit, tombstone.Length))
	c.Assert(tombstone.Length < signatureLimit, gc.Equals, true)

	var buf bytes.Buffer
	c.Assert(WritePackets(&buf, tombstone), gc.IsNil)
	received, err := NewKeyReader(bytes.NewReader(buf.Bytes()),
		MaxPacketLen(ordinaryLimit), MaxSigPacketLen(signatureLimit)).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(received, gc.HasLen, 1,
		gc.Commentf("a %d byte tombstone was dropped by the ordinary packet limit", tombstone.Length))

	gotTS, gotSigs, err := TombstoneOf(received[0])
	c.Assert(err, gc.IsNil)
	c.Check(gotTS.Fingerprint, gc.Equals, tsFpA)
	fp, err := VerifyTombstone(*gotTS, gotSigs, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)
	c.Check(fp, gc.Equals, pub.Fingerprint)
}
