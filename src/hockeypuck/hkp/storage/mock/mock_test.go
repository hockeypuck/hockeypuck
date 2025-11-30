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

package mock_test

import (
	"testing"

	gc "gopkg.in/check.v1"

	"hockeypuck/hkp/storage"
	"hockeypuck/hkp/storage/mock"
)

func Test(t *testing.T) { gc.TestingT(t) }

type MockSuite struct{}

var _ = gc.Suite(&MockSuite{})

var _ storage.Storage = (*mock.Storage)(nil)

// TODO: implement direct lookup by MD5/KeyID/Keyword and deprecate MatchMD5ToFp/ResolveToFp/MatchKeywordToFp (#228)
func (*MockSuite) TestMatchMD5(c *gc.C) {
	m := mock.NewStorage(mock.MatchMD5ToFp(func([]string) ([]string, error) { return []string{"foo", "bar"}, nil }))
	ids, err := m.MatchMD5ToFp(nil)
	c.Assert(ids, gc.DeepEquals, []string{"foo", "bar"})
	c.Assert(err, gc.IsNil)
	c.Assert(m.Calls, gc.HasLen, 1)
}
