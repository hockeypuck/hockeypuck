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
	"hockeypuck/openpgp"
	"net/http"

	gc "gopkg.in/check.v1"
)

func (s *S) TestReindex(c *gc.C) {
	s.addKey(c, "e68e311d.asc")

	// Now reset the reindexable columns of the test key's DB record
	_, err := s.storage.Exec(`UPDATE keys SET keywords = '', vfingerprint = '' WHERE rfingerprint = $1`, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"))
	c.Assert(err, gc.IsNil, gc.Commentf("mangle casey's key"))
	_, err = s.storage.Exec(`UPDATE subkeys SET vsubfp = '' WHERE rsubfp = $1`, openpgp.Reverse("636e5e7c575d2e971318b663ca7e517d2a42ac0a"))
	c.Assert(err, gc.IsNil, gc.Commentf("mangle casey's subkey"))
	_, err = s.storage.Exec(`DELETE FROM subkeys WHERE rsubfp = $1`, openpgp.Reverse("6f6d93d0811d1f8b7a34944b782e33de1a96e4c8"))
	c.Assert(err, gc.IsNil, gc.Commentf("delete casey's subkey"))
	_, err = s.storage.Exec(`UPDATE userids SET identity = '' WHERE identity = 'cmars@cmarstech.com'`)
	c.Assert(err, gc.IsNil, gc.Commentf("mangle casey's userid"))
	_, err = s.storage.Exec(`DELETE FROM userids WHERE identity = 'casey.marshall@canonical.com'`)
	c.Assert(err, gc.IsNil, gc.Commentf("delete casey's userid"))

	oldkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment := gc.Commentf("fetch 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(oldkeydocs, gc.HasLen, 1, comment)
	c.Assert(oldkeydocs[0].Keywords, gc.Equals, "", comment)
	c.Assert(oldkeydocs[0].VFingerprint, gc.Equals, "", comment)

	// Check that Casey's key is no longer indexed by name
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=casey+marshall")
	comment = gc.Commentf("search=casey+marshall")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)

	err = s.storage.Reindex()
	c.Assert(err, gc.IsNil, gc.Commentf("reindex"))

	// Check that reindexing only changed the desired fields
	newkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment = gc.Commentf("fetch 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newkeydocs, gc.HasLen, 1, comment)
	c.Assert(newkeydocs[0].Keywords, gc.Equals, "'canonical.com' 'casey' 'casey marshall <casey.marshall@canonical.com>' 'casey marshall <cmars@cmarstech.com>' 'casey.marshall' 'casey.marshall@canonical.com' 'cmars' 'cmars@cmarstech.com' 'cmarstech.com' 'marshall'", comment)
	c.Assert(newkeydocs[0].CTime.Equal(oldkeydocs[0].CTime), gc.Equals, true, comment)
	c.Assert(newkeydocs[0].MTime.Equal(oldkeydocs[0].MTime), gc.Equals, true, comment)
	c.Assert(newkeydocs[0].IdxTime.Equal(oldkeydocs[0].IdxTime), gc.Equals, false, comment)
	c.Assert(newkeydocs[0].VFingerprint, gc.Equals, "048d7c6b1a49166a46ff293af2d4236eabe68e311d", comment)

	newsubkeydocs, err := s.storage.fetchSubKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")}, false)
	comment = gc.Commentf("fetch subkeys 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newsubkeydocs, gc.HasLen, 2, comment)
	c.Assert(newsubkeydocs[0].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(newsubkeydocs[1].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(newsubkeydocs[0].VSubKeyFp, gc.Equals, "04636e5e7c575d2e971318b663ca7e517d2a42ac0a", comment)
	c.Assert(newsubkeydocs[1].VSubKeyFp, gc.Equals, "046f6d93d0811d1f8b7a34944b782e33de1a96e4c8", comment)

	newuseriddocs, err := s.storage.fetchUserIdDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment = gc.Commentf("fetch userids 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newuseriddocs, gc.HasLen, 2, comment)
	c.Assert(newuseriddocs[0].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(newuseriddocs[1].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(newuseriddocs[0].UidString, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>", comment)
	c.Assert(newuseriddocs[0].Identity, gc.Equals, "casey.marshall@canonical.com", comment)
	c.Assert(newuseriddocs[1].UidString, gc.Equals, "Casey Marshall <cmars@cmarstech.com>", comment)
	c.Assert(newuseriddocs[1].Identity, gc.Equals, "cmars@cmarstech.com", comment)

	// Check that Casey's key is indexed again
	res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=casey+marshall")
	comment = gc.Commentf("search=casey+marshall")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	// Check that reindexing is idempotent
	err = s.storage.Reindex()
	c.Assert(err, gc.IsNil, gc.Commentf("reindex idempotency"))
	idemkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	c.Assert(err, gc.IsNil, comment)
	c.Assert(idemkeydocs, gc.DeepEquals, newkeydocs, comment)
}
