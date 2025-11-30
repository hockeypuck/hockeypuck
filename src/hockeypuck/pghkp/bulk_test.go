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

package pghkp

import (
	"net/http"

	"hockeypuck/pghkp/types"
	"hockeypuck/testing"

	gc "gopkg.in/check.v1"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
)

func (s *S) TestBulkInsert(c *gc.C) {
	f := testing.MustInput("examples.pgp")
	kr := openpgp.NewKeyReader(f, []openpgp.KeyReaderOption{}...)
	keys, err := kr.Read()
	c.Assert(err, gc.IsNil)
	var result hkpstorage.InsertError
	bs, err := s.storage.bulkCreateTempTables()
	c.Assert(err, gc.IsNil)
	defer bs.bulkDropTempTables()
	n, _, ok := bs.bulkInsert(keys, &result, []string{})
	c.Assert(ok, gc.Equals, true)
	c.Assert(n, gc.Equals, 2592)

	newkeydocs, err := s.storage.fetchKeyDocsByRfp([]string{types.Reverse("00bc6161d88d85e9ef87c55826707ffc4fb750d8")})
	comment := gc.Commentf("fetch 00BC6161D88D85E9EF87C55826707FFC4FB750D8")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newkeydocs, gc.HasLen, 1, comment)
	c.Assert(newkeydocs[0].Keywords, gc.Equals, "'example-10101010' 'example-10101010@example.com' 'example.com' 'testing' 'testing <example-10101010@example.com>'", comment)
	c.Assert(newkeydocs[0].VFingerprint, gc.Equals, "0400bc6161d88d85e9ef87c55826707ffc4fb750d8", comment)

	newsubkeydocs, err := s.storage.fetchSubKeyDocsByRfp([]string{types.Reverse("00bc6161d88d85e9ef87c55826707ffc4fb750d8")}, false)
	comment = gc.Commentf("fetch subkeys 00BC6161D88D85E9EF87C55826707FFC4FB750D8")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newsubkeydocs, gc.HasLen, 1, comment)
	c.Assert(newsubkeydocs[0].Fingerprint, gc.Equals, "00bc6161d88d85e9ef87c55826707ffc4fb750d8", comment)
	c.Assert(newsubkeydocs[0].VSubKeyFp, gc.Equals, "043cf221f8cecc8ef558f52146b7d1a07afdf07c46", comment)

	newuseriddocs, err := s.storage.fetchUserIdDocsByRfp([]string{types.Reverse("00bc6161d88d85e9ef87c55826707ffc4fb750d8")})
	comment = gc.Commentf("fetch userids 00BC6161D88D85E9EF87C55826707FFC4FB750D8")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newuseriddocs, gc.HasLen, 1, comment)
	c.Assert(newuseriddocs[0].Fingerprint, gc.Equals, "00bc6161d88d85e9ef87c55826707ffc4fb750d8", comment)
	c.Assert(newuseriddocs[0].UidString, gc.Equals, "Testing <example-10101010@example.com>", comment)
	c.Assert(newuseriddocs[0].Identity, gc.Equals, "example-10101010@example.com", comment)

	// Check that the key is indexed
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=example-10101010@example.com")
	comment = gc.Commentf("search=example-10101010@example.com")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)
}
