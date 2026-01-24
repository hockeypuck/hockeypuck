/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gc "gopkg.in/check.v1"

	"hockeypuck/testing"
)

type ResolveSuite struct{}

var _ = gc.Suite(&ResolveSuite{})

func (s *ResolveSuite) TestBadSelfSigUid(c *gc.C) {
	f := testing.MustInput("badselfsig.asc")
	_, err := NewKeyReader(f).Read()
	c.Assert(err, gc.NotNil)
}

func (s *ResolveSuite) TestDupSigSksDigest(c *gc.C) {
	f := testing.MustInput("252B8B37.dupsig.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	r := packet.NewOpaqueReader(block.Body)
	var packets []*packet.OpaquePacket
	for {
		if op, err := r.Next(); err != nil {
			break
		} else {
			packets = append(packets, op)
			c.Log("raw:", op)
		}
	}
	sksDigest := sksDigestOpaque(packets, md5.New(), "testing")
	// c.Assert(sksDigest, gc.Equals, "ba693a2769fffc68afd3a22fd5b4bdd6") // This is the value to expect once we fix #283
	c.Assert(sksDigest, gc.Equals, "6d57b48c83d6322076d634059bb3b94b")
}

func patchNow(t time.Time) func() {
	now = func() time.Time {
		return t
	}
	return func() {
		now = time.Now
	}
}

func (s *ResolveSuite) TestUserIDSigInfo(c *gc.C) {
	defer patchNow(time.Date(2014, time.January, 1, 0, 0, 0, 0, time.UTC))()

	key := MustInputAscKey("lp1195901.asc")
	Sort(key)
	// Primary UID
	c.Assert(key.UserIDs[0].Keywords, gc.Equals, "Phil Pennock <phil.pennock@spodhuis.org>")
	for _, uid := range key.UserIDs {
		if uid.Keywords == "pdp@spodhuis.demon.nl" {
			ss, _ := uid.SigInfo(key)
			c.Assert(ss.Revocations, gc.HasLen, 1)
		}
	}

	key = MustInputAscKey("lp1195901_2.asc")
	Sort(key)
	c.Assert(key.UserIDs[0].Keywords, gc.Equals, "Phil Pennock <phil.pennock@globnix.org>")
}

func (s *ResolveSuite) TestSortUserIDs(c *gc.C) {
	defer patchNow(time.Date(2014, time.January, 1, 0, 0, 0, 0, time.UTC))()

	key := MustInputAscKey("lp1195901.asc")
	Sort(key)
	expect := []string{
		"Phil Pennock <phil.pennock@spodhuis.org>",
		"Phil Pennock <phil.pennock@globnix.org>",
		"Phil Pennock <pdp@exim.org>",
		"Phil Pennock <pdp@spodhuis.org>",
		"Phil Pennock <pdp@spodhuis.demon.nl>"}
	for i := range key.UserIDs {
		c.Assert(key.UserIDs[i].Keywords, gc.Equals, expect[i])
	}
}

func (s *ResolveSuite) TestKeyExpiration(c *gc.C) {
	defer patchNow(time.Date(2013, time.January, 1, 0, 0, 0, 0, time.UTC))()

	key := MustInputAscKey("lp1195901.asc")
	Sort(key)

	c.Assert(key.SubKeys, gc.HasLen, 7)
	// Unexpired subkeys sort most recently certified first
	c.Assert(key.SubKeys[0].UUID, gc.Equals, "9cfd8b1a81105d45d33b6e6187e9588908d949c6")
	c.Assert(key.SubKeys[1].UUID, gc.Equals, "3eb6d3e6639b38da338d316935ed4620959e5473")
	// Expired subkeys sort earliest creation date first
	c.Assert(key.SubKeys[2].UUID, gc.Equals, "4dfa4bd9d76d24e5c3355309bd53847773fd5f8d")
	c.Assert(key.SubKeys[3].UUID, gc.Equals, "90179503ff204d6cec9eab1f47863897b85d614b")
	c.Assert(key.SubKeys[4].UUID, gc.Equals, "2a4a12effdec894a18fb43f518318c24c188a8b6")
	c.Assert(key.SubKeys[5].UUID, gc.Equals, "b877339d3748fbf62f64aba393b9fc7e4f54aea2")
	c.Assert(key.SubKeys[6].UUID, gc.Equals, "2b4899add28f2ce9180399f9ec3a1afb21b41f61")
}

func (s *ResolveSuite) TestRedactingSignature(c *gc.C) {
	key := MustInputAscKey("test-key-revoked.asc")
	c.Assert(key.UserIDs, gc.HasLen, 1)
	sig, err := key.RedactingSignature()
	c.Assert(err, gc.IsNil)
	c.Assert(sig.Creation, gc.Equals, time.Unix(1611408186, 0))
}

func (s *ResolveSuite) TestPrimaryUserIDSig(c *gc.C) {
	key := MustInputAscKey("gentoo-l1.asc") // The Gentoo key does not mark its UserID as primary
	c.Assert(key.UserIDs, gc.HasLen, 1)     // ... but it only has one UserID so it is primary by default
	sig, err := key.PrimaryUserIDSig()
	c.Assert(err, gc.IsNil)
	c.Assert(sig.Expiration, gc.Equals, time.Unix(1782907200, 0)) // Check the latest sig directly
	ss, _ := key.SigInfo()
	expiry, _ := ss.ExpiresAt()
	c.Assert(expiry, gc.Equals, time.Unix(1782907200, 0)) // ExpiresAt should give the same result
}

// TestUnsuppIgnored tests parsing key material containing
// packets which are not normally part of an exported public key --
// trust packets, in this case.
func (s *ResolveSuite) TestUnsuppIgnored(c *gc.C) {
	f := testing.MustInput("snowcrash.gpg")
	keys := MustReadKeys(f)
	c.Assert(keys, gc.HasLen, 1)
	key := keys[0]
	c.Assert(key, gc.NotNil)
}

// There is a martian third-party 0x13 signature on the encryption subkey
// This is obviously lost, so it should be dropped
func (s *ResolveSuite) TestMartiansDropped(c *gc.C) {
	key := MustInputAscKey("martian.asc")
	c.Assert(key, gc.NotNil)
	err := ValidSelfSigned(key, false)
	c.Assert(err, gc.IsNil)
	c.Assert(key.SubKeys, gc.HasLen, 1)
	c.Assert(key.SubKeys[0].Signatures, gc.HasLen, 1)
}

func (s *ResolveSuite) TestEvaporatingKey(c *gc.C) {
	key := MustInputAscKey("snowcrash_evaporated.asc")
	c.Assert(key, gc.NotNil)
	err := ValidSelfSigned(key, false)
	c.Assert(err, gc.Equals, ErrKeyEvaporated)
	c.Assert(key.SubKeys, gc.HasLen, 0)
	c.Assert(key.UserIDs, gc.HasLen, 0)
	c.Assert(key.Signatures, gc.HasLen, 0)
}

func (s *ResolveSuite) TestMissingUidFk(c *gc.C) {
	key := MustInputAscKey("d7346e26.asc")
	c.Log(key)
}

func (s *ResolveSuite) TestV3NoUidSig(c *gc.C) {
	key := MustInputAscKey("0xd46b7c827be290fe4d1f9291b1ebc61a.asc")
	c.Assert(key.KeyID, gc.Equals, "0760df64b3d82239")
	f := testing.MustInput("0xd46b7c827be290fe4d1f9291b1ebc61a.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	var oc *OpaqueCert
	for _, ocert := range MustReadOpaqueCerts(block.Body) {
		oc = ocert
	}
	sort.Sort(opaquePacketSlice(oc.Packets))
	h := md5.New()
	for _, opkt := range oc.Packets {
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
	}
	md5 := hex.EncodeToString(h.Sum(nil))
	c.Assert(md5, gc.Equals, "0005127a8b7da8c32998d7e81dc92540")
}

func (s *ResolveSuite) TestMergeAddSig(c *gc.C) {
	unsignedKeys := MustInputAscKeys("alice_unsigned.asc")
	c.Assert(unsignedKeys, gc.HasLen, 1)
	c.Assert(unsignedKeys[0], gc.NotNil)
	signedKeys := MustInputAscKeys("alice_signed.asc")
	c.Assert(signedKeys, gc.HasLen, 1)
	c.Assert(signedKeys[0], gc.NotNil)

	c.Assert(unsignedKeys[0].UserIDs, gc.HasLen, 1)
	c.Assert(signedKeys[0].UserIDs, gc.HasLen, 1)

	c.Assert(unsignedKeys[0].UserIDs[0].Signatures, gc.HasLen, 1)
	c.Assert(signedKeys[0].UserIDs[0].Signatures, gc.HasLen, 2)

	hasExpectedSig := func(key *PrimaryKey) bool {
		for _, node := range key.contents() {
			sig, ok := node.(*Signature)
			if ok {
				c.Logf("sig from %s", sig.IssuerKeyID)
				if sig.IssuerKeyID == "62aea01d67640fb5" {
					return true
				}
			}
		}
		return false
	}
	c.Assert(hasExpectedSig(unsignedKeys[0]), gc.Equals, false)
	c.Assert(hasExpectedSig(signedKeys[0]), gc.Equals, true)
	err := Merge(unsignedKeys[0], signedKeys[0])
	c.Assert(err, gc.IsNil)
	c.Assert(hasExpectedSig(unsignedKeys[0]), gc.Equals, true)
}

func (s *ResolveSuite) TestSelfSignedOnly_BadSigs(c *gc.C) {
	key := MustInputAscKey("badselfsig.asc")
	// Key material contains some uid signatures by a colleague and a forged
	// uid packet with an invalid signature packet.
	c.Assert(key.UserIDs, gc.HasLen, 5)
	c.Assert(key.SubKeys, gc.HasLen, 3)

	c.Assert(ValidSelfSigned(key, true), gc.IsNil)
	c.Assert(key.UserIDs, gc.HasLen, 2)
	for _, uid := range key.UserIDs {
		c.Logf("uid %v", uid.Keywords)
		if strings.Contains(uid.Keywords, "gazzang") {
			c.Assert(uid.Signatures, gc.HasLen, 2)
		} else {
			c.Assert(uid.Signatures, gc.HasLen, 1)
		}
	}
	c.Assert(key.SubKeys, gc.HasLen, 3)
	for _, sub := range key.SubKeys {
		if sub.KeyID == "db769d16cdb9ad53" {
			c.Assert(sub.Signatures, gc.HasLen, 2)
		} else {
			c.Assert(sub.Signatures, gc.HasLen, 1)
		}
	}
}

func (s *ResolveSuite) TestSelfSignedOnly_V3SigDropped(c *gc.C) {
	key := MustInputAscKey("0ff16c87.asc")
	c.Assert(key.UserIDs, gc.HasLen, 9)
	c.Assert(key.SubKeys, gc.HasLen, 1)

	c.Assert(ValidSelfSigned(key, true), gc.IsNil)
	c.Assert(key.UserIDs, gc.HasLen, 9)
	for _, uid := range key.UserIDs {
		c.Assert(uid.Signatures, gc.HasLen, 1)
	}
	// v3 signature on a v4 encryption subkey is NOT dropped
	c.Assert(key.SubKeys, gc.HasLen, 1)
}

func (s *ResolveSuite) TestResolveRootSignatures(c *gc.C) {
	key1 := MustInputAscKey("test-key.asc")
	key2 := MustInputAscKey("test-key-revoked.asc")
	c.Assert(key1.Signatures, gc.HasLen, 0)
	c.Assert(key2.Signatures, gc.HasLen, 1)
	err := ValidSelfSigned(key2, false) // This should drop the UIDs on key2 due to the hard revocation
	c.Assert(err, gc.IsNil)
	c.Assert(key1.MD5, gc.Not(gc.Equals), key2.MD5)
	Merge(key1, key2) // This will drop the UIDs on key1
	c.Assert(key1.MD5, gc.Equals, key2.MD5)
	c.Assert(key1.Signatures, gc.HasLen, 1)
	c.Assert(key2.Signatures, gc.HasLen, 1)
}

func (s *ResolveSuite) TestMergeRevocationSig(c *gc.C) {
	key := MustInputAscKey("test-key.asc")
	armorBlock, err := armor.Decode(testing.MustInput("test-key-revoke.asc"))
	c.Assert(err, gc.IsNil)
	okr, err := NewOpaqueKeyReader(armorBlock.Body)
	c.Assert(err, gc.IsNil)
	keyring, err := okr.Read()
	c.Assert(err, gc.IsNil)
	sig, err := ParseSignature(keyring[0].Packets[0], time.Now(), "", "")
	c.Assert(err, gc.IsNil)
	MergeRevocationSig(key, sig)
	c.Assert(key.Signatures, gc.HasLen, 1)
	c.Assert(key.UserIDs, gc.HasLen, 0) // The UID should be dropped due to the hard revocation
}

func (s *ResolveSuite) TestMergeWrongRevocationSig(c *gc.C) {
	key := MustInputAscKey("test-key.asc")
	armorBlock, err := armor.Decode(testing.MustInput("test-rtbf-revoke.asc"))
	c.Assert(err, gc.IsNil)
	okr, err := NewOpaqueKeyReader(armorBlock.Body)
	c.Assert(err, gc.IsNil)
	keyring, err := okr.Read()
	c.Assert(err, gc.IsNil)
	c.Assert(key.Signatures, gc.HasLen, 0)
	sig, err := ParseSignature(keyring[0].Packets[0], time.Now(), "", "")
	c.Assert(err, gc.IsNil)
	MergeRevocationSig(key, sig)
	c.Assert(key.Signatures, gc.HasLen, 0) // martian revocation sig should be dropped
	c.Assert(key.UserIDs, gc.HasLen, 1)
}

// TODO: since default revocation sigs are hard, this test is redundant.
// Replace it with a SOFT revocation test that does not delete UIDs
func (s *ResolveSuite) TestMergeHardRevocationSig(c *gc.C) {
	key := MustInputAscKey("test-rtbf.asc")
	armorBlock, err := armor.Decode(testing.MustInput("test-rtbf-revoke.asc"))
	c.Assert(err, gc.IsNil)
	okr, err := NewOpaqueKeyReader(armorBlock.Body)
	c.Assert(err, gc.IsNil)
	keyring, err := okr.Read()
	c.Assert(err, gc.IsNil)
	c.Assert(key.Signatures, gc.HasLen, 0)
	sig, err := ParseSignature(keyring[0].Packets[0], time.Now(), "", "")
	c.Assert(err, gc.IsNil)
	c.Assert(*sig.RevocationReason, gc.Equals, packet.KeyCompromised)
	MergeRevocationSig(key, sig)
	c.Assert(key.Signatures, gc.HasLen, 1)
	c.Assert(key.UserIDs, gc.HasLen, 0)
}
