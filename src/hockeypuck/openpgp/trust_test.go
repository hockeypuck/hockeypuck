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
	"crypto/md5"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gc "gopkg.in/check.v1"

	"hockeypuck/testing"
)

type TrustDigestSuite struct{}

var _ = gc.Suite(&TrustDigestSuite{})

// noisyTrust builds a trust packet in the noisy SKS app context. Only its first
// subpacket is visible to the SKS digest; everything after it should be covered
// by the trust digest alone.
func (s *TrustDigestSuite) noisyTrust(c *gc.C, tail string) *Trust {
	trust := &Trust{
		AppContext:    trustAppContextNoisySKS,
		PacketContext: 6,
		Notations: []*packet.Notation{
			{Name: "parentMD5", Value: []byte("0123456789abcdef0123456789abcdef")},
			{Name: "unhashedDetail", Value: []byte(tail)},
		},
	}
	c.Assert(trust.UpdatePacket(), gc.IsNil)
	return trust
}

func (s *TrustDigestSuite) keyWithTrust(c *gc.C, tail string) *PrimaryKey {
	keys, err := ReadArmorKeys(testing.MustInput("alice_signed.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	key := keys[0]
	key.Trusts = append(key.Trusts, s.noisyTrust(c, tail))
	return key
}

// TestTrustDigestCoversUnhashedSubpackets is a regression test for
// trustPacketSKSView truncating the packet that SksDigest has already stored in
// tpackets. With that aliasing in place the trust digest silently covers only
// the SKS-visible prefix, so a change confined to the unhashed subpackets moves
// neither digest and Upsert reports the key as unchanged.
func (s *TrustDigestSuite) TestTrustDigestCoversUnhashedSubpackets(c *gc.C) {
	before := s.keyWithTrust(c, "original")
	beforeMD5, beforeTrustMD5, err := SksDigest(before, md5.New(), md5.New())
	c.Assert(err, gc.IsNil)

	after := s.keyWithTrust(c, "amended, and materially longer than the original")
	afterMD5, afterTrustMD5, err := SksDigest(after, md5.New(), md5.New())
	c.Assert(err, gc.IsNil)

	c.Check(afterMD5, gc.Equals, beforeMD5,
		gc.Commentf("unhashed subpackets must not move the SKS digest"))
	c.Check(afterTrustMD5, gc.Not(gc.Equals), beforeTrustMD5,
		gc.Commentf("unhashed subpackets MUST move the trust digest, else Upsert sees no change"))
}

// TestTrustPacketSKSViewDoesNotMutateArgument pins the underlying cause.
func (s *TrustDigestSuite) TestTrustPacketSKSViewDoesNotMutateArgument(c *gc.C) {
	trust := s.noisyTrust(c, "some trailing detail")
	op, err := newOpaquePacket(trust.Data)
	c.Assert(err, gc.IsNil)

	before := len(op.Contents)
	view := trustPacketSKSView(op)
	c.Assert(view, gc.NotNil)

	c.Check(view.Contents, gc.Not(gc.HasLen), before,
		gc.Commentf("the SKS view should be a truncation"))
	c.Check(op.Contents, gc.HasLen, before,
		gc.Commentf("trustPacketSKSView must not truncate its argument in place"))
}
