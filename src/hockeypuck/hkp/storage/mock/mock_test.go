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

func (*MockSuite) TestFetchMD5(c *gc.C) {
	record := &storage.Record{MD5: "abc"}
	m := mock.NewStorage(mock.FetchRecordsByMD5(func([]string, ...string) ([]*storage.Record, error) { return []*storage.Record{record}, nil }))
	ids, err := m.FetchRecordsByMD5(nil)
	c.Assert(ids, gc.DeepEquals, []*storage.Record{record})
	c.Assert(err, gc.IsNil)
	c.Assert(m.Calls, gc.HasLen, 1)
}
