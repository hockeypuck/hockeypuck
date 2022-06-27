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
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	gc "gopkg.in/check.v1"

	"hockeypuck/testing"
)

type CompatSuite struct{}

var _ = gc.Suite(&CompatSuite{})

func (s *ResolveSuite) TestSerializeOldHeader(c *gc.C) {
	tag := uint8(6) // packetTypePublicKey
	lengths := []int{0, 1, 2, 64, 192, 193, 8000, 8384, 8385, 10000}

	for _, length := range lengths {
		buf := bytes.NewBuffer(nil)
		err := serializeOldHeader(buf, tag, length)
		c.Assert(err, gc.IsNil)
		tag2, length2, _, err := readHeader(buf)
		c.Assert(err, gc.IsNil)
		c.Assert(tag2, gc.Equals, packetTypePublicKey) // Serialize[Old]Header expects tag~int8, but readHeader emits tag~packetType.
		c.Assert(length2, gc.Equals, int64(length))    // Serialize[Old]Header expects length~int, but readHeader emits length~int64.
	}
}

func (s *CompatSuite) TestCompatRoundtrip(c *gc.C) {
	f := testing.MustInput("test-key.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	or := packet.NewOpaqueReader(block.Body)
	buf := bytes.NewBuffer(nil)
	for {
		packet, err := or.Next()
		if err != nil {
			break
		}
		SerializeCompat(buf, packet)
	}

	f.Seek(0, io.SeekStart)
	block2, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	buf2, err := ioutil.ReadAll(block2.Body)
	c.Assert(err, gc.IsNil)
	c.Assert(buf.Bytes(), gc.DeepEquals, buf2)
}
