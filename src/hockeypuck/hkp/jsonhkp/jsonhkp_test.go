/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  Casey Marshall and the Hockeypuck Contributors

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

package jsonhkp

import (
	"bytes"
	"crypto/md5"
	"hockeypuck/openpgp"
	"hockeypuck/testing"
	stdtesting "testing"

	gc "gopkg.in/check.v1"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type JsonHkpSuite struct {
}

var _ = gc.Suite(&JsonHkpSuite{})

func (s *JsonHkpSuite) TestRoundtrip(c *gc.C) {
	keys := openpgp.MustReadArmorKeys(testing.MustInput("sksdigest.asc"))
	c.Assert(keys, gc.HasLen, 1)
	md5, err := openpgp.SksDigest(keys[0], md5.New())
	c.Assert(err, gc.IsNil)
	c.Assert(keys[0].KeyID, gc.Equals, "cc5112bdce353cf4")
	c.Assert(md5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa")
	jsonKeys := NewPrimaryKeys(keys)
	c.Assert(jsonKeys, gc.HasLen, 1)
	buf := jsonKeys[0].Bytes()
	c.Assert(err, gc.IsNil)
	newKeys := openpgp.MustReadKeys(bytes.NewReader(buf))
	c.Assert(newKeys, gc.HasLen, 1)
	c.Assert(newKeys, gc.DeepEquals, keys)
}
