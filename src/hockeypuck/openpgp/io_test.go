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
	"bytes"
	"crypto/md5"
	"io"
	"sort"
	"strings"
	stdtesting "testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gc "gopkg.in/check.v1"

	"hockeypuck/testing"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type SamplePacketSuite struct{}

var _ = gc.Suite(&SamplePacketSuite{})

func (s *SamplePacketSuite) TestVerifyUserAttributeSig(c *gc.C) {
	key := MustInputAscKey("uat.asc")
	c.Assert(key.UserAttributes, gc.HasLen, 1)
	DropDuplicates(key)
	c.Assert(key.UserAttributes, gc.HasLen, 1)
	uat := key.UserAttributes[0]
	c.Assert(uat.Images, gc.HasLen, 1)
	// TODO: check contents
}

func (s *SamplePacketSuite) TestSksDigest(c *gc.C) {
	key := MustInputAscKey("sksdigest.asc")
	md5, err := SksDigest(key, md5.New())
	c.Assert(err, gc.IsNil)
	c.Assert(key.ShortID(), gc.Equals, "ce353cf4")
	c.Assert(md5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa")
}

func (s *SamplePacketSuite) TestSksContextualDup(c *gc.C) {
	f := testing.MustInput("sks_fail.asc")

	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	buf, err := io.ReadAll(block.Body)
	c.Assert(err, gc.IsNil)
	err = f.Close()
	c.Assert(err, gc.IsNil)

	var kr *OpaqueKeyring
	for _, opkr := range MustReadOpaqueKeys(bytes.NewBuffer(buf)) {
		c.Assert(kr, gc.IsNil)
		kr = opkr
	}

	var refBuf bytes.Buffer
	for _, op := range kr.Packets {
		err = op.Serialize(&refBuf)
		c.Assert(err, gc.IsNil)
	}
	c.Assert(buf, gc.DeepEquals, refBuf.Bytes())

	pk, err := kr.Parse()
	c.Assert(err, gc.IsNil)
	digest1, err := SksDigest(pk, md5.New())
	c.Assert(err, gc.IsNil)

	err = DropDuplicates(pk)
	c.Assert(err, gc.IsNil)
	digest2, err := SksDigest(pk, md5.New())
	c.Assert(err, gc.IsNil)

	c.Check(digest1, gc.Equals, digest2)

	for _, op := range kr.Packets {
		c.Logf("%d %d %s", op.Tag, len(op.Contents), hexmd5(op.Contents))
	}

	c.Log("parse primary key")
	key := MustInputAscKey("sks_fail.asc")
	dupDigest, err := SksDigest(key, md5.New())
	c.Assert(err, gc.IsNil)
	var packetsDup opaquePacketSlice
	for _, node := range key.contents() {
		op, err := node.packet().opaquePacket()
		c.Assert(err, gc.IsNil)
		packetsDup = append(packetsDup, op)
	}
	sort.Sort(packetsDup)
	for _, op := range packetsDup {
		c.Logf("%d %d %s", op.Tag, len(op.Contents), hexmd5(op.Contents))
	}

	c.Log("deduped primary key")
	key = MustInputAscKey("sks_fail.asc")
	DropDuplicates(key)
	dedupDigest, err := SksDigest(key, md5.New())
	c.Assert(err, gc.IsNil)
	var packetsDedup opaquePacketSlice
	for _, node := range key.contents() {
		op, err := node.packet().opaquePacket()
		c.Assert(err, gc.IsNil)
		packetsDedup = append(packetsDedup, op)
	}
	sort.Sort(packetsDedup)
	for _, op := range packetsDedup {
		c.Logf("%d %d %s", op.Tag, len(op.Contents), hexmd5(op.Contents))
	}

	c.Assert(dupDigest, gc.Equals, dedupDigest)
}

func (s *SamplePacketSuite) TestUatRtt(c *gc.C) {
	f := testing.MustInput("uat.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	var p packet.Packet
	for {
		p, err = packet.Read(block.Body)
		if err != nil {
			c.Assert(err, gc.Equals, io.EOF)
			break
		}

		uat, ok := p.(*packet.UserAttribute)
		if ok {
			var buf bytes.Buffer
			uat.Serialize(&buf)
			or := packet.NewOpaqueReader(bytes.NewBuffer(buf.Bytes()))
			op, _ := or.Next()
			c.Assert(buf.Bytes()[3:], gc.DeepEquals, op.Contents)
		}
	}
}

func (s *SamplePacketSuite) TestPacketCounts(c *gc.C) {
	testCases := []struct {
		name                                         string
		nUserID, nUserAttribute, nSubKey, nSignature int
	}{{
		"0ff16c87.asc", 9, 0, 1, 0,
	}, {
		"alice_signed.asc", 1, 0, 1, 0,
	}, {
		"uat.asc", 2, 1, 3, 0,
	}, {
		"252B8B37.dupsig.asc", 3, 0, 2, 1,
	}}
	for i, testCase := range testCases {
		c.Logf("test#%d: %s", i, testCase.name)
		f := testing.MustInput(testCase.name)
		defer f.Close()
		block, err := armor.Decode(f)
		c.Assert(err, gc.IsNil)
		for _, key := range MustReadKeys(block.Body) {
			c.Assert(key, gc.NotNil)
			c.Assert(key.UserIDs, gc.HasLen, testCase.nUserID)
			c.Assert(key.UserAttributes, gc.HasLen, testCase.nUserAttribute)
			c.Assert(key.SubKeys, gc.HasLen, testCase.nSubKey)
			c.Assert(key.Signatures, gc.HasLen, testCase.nSignature)
		}
	}
}

func (s *SamplePacketSuite) TestDeduplicate(c *gc.C) {
	f := testing.MustInput("d7346e26.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		c.Fatal(err)
	}

	// Parse keyring, duplicate all packet types except primary pubkey.
	kr := &OpaqueKeyring{}
	for _, opkr := range MustReadOpaqueKeys(block.Body) {
		c.Assert(opkr.Error, gc.IsNil)
		for _, op := range opkr.Packets {
			kr.Packets = append(kr.Packets, op)
			switch op.Tag {
			case 2:
				kr.Packets = append(kr.Packets, op)
				fallthrough
			case 13, 14, 17:
				kr.Packets = append(kr.Packets, op)
			}
		}
	}
	key, err := kr.Parse()
	c.Assert(err, gc.IsNil)

	n := 0
	for _, node := range key.contents() {
		c.Logf("%s", node.uuid())
		n++
	}

	c.Log()
	err = CollectDuplicates(key)
	c.Assert(err, gc.IsNil)

	n2 := 0
	for _, node := range key.contents() {
		c.Logf("%s %d", node.uuid(), node.packet().Count)
		n2++
		switch node.packet().Tag {
		case 2:
			c.Check(node.packet().Count, gc.Equals, 2)
		case 13, 14, 17:
			c.Check(node.packet().Count, gc.Equals, 1)
		case 6:
			c.Check(node.packet().Count, gc.Equals, 0)
		default:
			c.Fatal("should not happen")
		}
	}
	c.Assert(n2 < n, gc.Equals, true)
}

func (s *SamplePacketSuite) TestMerge(c *gc.C) {
	key1 := MustInputAscKey("lp1195901.asc")
	key2 := MustInputAscKey("lp1195901_globnix.asc")
	err := Merge(key2, key1)
	c.Assert(err, gc.IsNil)
	var matchUID *UserID
	for _, uid := range key2.UserIDs {
		if uid.Keywords == "Phil Pennock <pdp@spodhuis.org>" {
			matchUID = uid
		}
	}
	c.Assert(matchUID, gc.NotNil)
}

func (s *SamplePacketSuite) TestRevocationCert(c *gc.C) {
	keys, err := ReadArmorKeys(testing.MustInput("revok_cert.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 0)
}

func (s *SamplePacketSuite) TestMalformedSignatures(c *gc.C) {
	key := MustInputAscKey("a7400f5a_nobadsigs.asc")
	c.Assert(len(key.Others), gc.Equals, 0)

	key = MustInputAscKey("a7400f5a_badsigs.asc")
	c.Assert(len(key.Others), gc.Equals, 3)
	for _, other := range key.Others {
		c.Assert(other.Malformed, gc.Equals, true)
	}
}

func (s *SamplePacketSuite) TestECCSelfSigs(c *gc.C) {
	keys := MustInputAscKeys("ecc_keys.asc")
	c.Assert(keys, gc.HasLen, 6)
	for i, key := range keys {
		ss, _ := key.SigInfo()
		c.Assert(ss.Errors, gc.HasLen, 0, gc.Commentf("errors in key #%d: %+v", i, ss.Errors))
		c.Assert(ss.Valid(), gc.Equals, true, gc.Commentf("invalid key #%d", i))
		c.Assert(key.UserIDs, gc.HasLen, 1)
		ss, _ = key.UserIDs[0].SigInfo(key)
		c.Assert(ss.Errors, gc.HasLen, 0, gc.Commentf("errors in key #%d: %+v", i, ss.Errors))
		c.Assert(ss.Valid(), gc.Equals, true, gc.Commentf("invalid key #%d", i))
	}
}

func (s *SamplePacketSuite) TestMaxKeyLen(c *gc.C) {
	keys, err := ReadArmorKeys(testing.MustInput("e68e311d.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	keys, err = ReadArmorKeys(testing.MustInput("e68e311d.asc"), MaxKeyLen(10))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 0)
}

func (s *SamplePacketSuite) TestMaxPacketLen(c *gc.C) {
	keys, err := ReadArmorKeys(testing.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].UserAttributes, gc.HasLen, 1)
	// UAT packet is > 3k bytes long
	keys, err = ReadArmorKeys(testing.MustInput("uat.asc"), MaxPacketLen(2048))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].UserAttributes, gc.HasLen, 0)
}

func (s *SamplePacketSuite) TestMaxKeyLenConcat(c *gc.C) {
	block1, err := armor.Decode(testing.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	block2, err := armor.Decode(testing.MustInput("e68e311d.asc"))
	c.Assert(err, gc.IsNil)
	key1, err := io.ReadAll(block1.Body)
	c.Assert(err, gc.IsNil)
	key2, err := io.ReadAll(block2.Body)
	c.Assert(err, gc.IsNil)

	keys := MustReadKeys(io.MultiReader(bytes.NewBuffer(key1), bytes.NewBuffer(key2)))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 2)

	keys = MustReadKeys(io.MultiReader(bytes.NewBuffer(key1), bytes.NewBuffer(key2)), MaxKeyLen(2048))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "e68e311d")

	keys = MustReadKeys(io.MultiReader(bytes.NewBuffer(key2), bytes.NewBuffer(key1)), MaxKeyLen(2048))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "e68e311d")
}

func (s *SamplePacketSuite) TestBlacklist(c *gc.C) {
	keys, err := ReadArmorKeys(testing.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	keys, err = ReadArmorKeys(testing.MustInput("uat.asc"), Blacklist([]string{"81279eee7ec89fb781702adaf79362da44a2d1db"}))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 0)
}

func (s *SamplePacketSuite) TestKeyLength(c *gc.C) {
	keys, err := ReadArmorKeys(testing.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].Length, gc.Equals, 8429)
}

func (s *SamplePacketSuite) TestWriteArmorHeaders(c *gc.C) {
	var opts []KeyWriterOption
	b := new(bytes.Buffer)

	opts = append(opts, ArmorHeaderComment("HKP"))
	opts = append(opts, ArmorHeaderVersion("Hockeypuck 2.1.0"))
	keys, err := ReadArmorKeys(testing.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	err = WriteArmoredPackets(b, keys, opts...)
	c.Assert(err, gc.IsNil)
	c.Logf("%s", b.String())
	c.Assert(strings.Contains(b.String(), "Comment: HKP\n"), gc.Equals, true)
	c.Assert(strings.Contains(b.String(), "Version: Hockeypuck 2.1.0\n"), gc.Equals, true)
}
