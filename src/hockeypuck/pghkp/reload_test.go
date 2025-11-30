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
	"bytes"
	"io"
	"net/http"
	"time"

	"hockeypuck/pghkp/types"
	"hockeypuck/testing"

	log "github.com/sirupsen/logrus"
	gc "gopkg.in/check.v1"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
)

// factorise out setupReload and checkReload because we use them in multiple testss

// setupReload loads the test keys
func (s *S) setupReload(c *gc.C) (oldkeydocs []*types.KeyDoc) {
	s.addKey(c, "e68e311d.asc")
	s.addKey(c, "alice_signed.asc")

	// insert a bad key directly into database (bypassing validation)
	// this should evaporate on reload
	keys := openpgp.MustReadArmorKeys(testing.MustInput("snowcrash_evaporated.asc"))
	comment := gc.Commentf("load snowcrash_evaporated.asc")
	c.Assert(keys, gc.HasLen, 1, comment)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1, comment)
	_, _, err := s.storage.Insert(keys)
	c.Assert(err, gc.IsNil, comment)

	// Check that there are three records in the database
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 3, gc.Commentf("Check that there are three records in the database"))

	oldkeydocs, err = s.storage.fetchKeyDocsByRfp([]string{types.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment = gc.Commentf("fetch 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(oldkeydocs, gc.HasLen, 1, comment)

	// Now mangle Casey's key and write back
	newdoc := `{"nonsense": "nonsense", ` + oldkeydocs[0].Doc[1:]
	_, err = s.storage.Exec(`UPDATE keys SET keywords = '', vfingerprint = '', doc = $2 WHERE rfingerprint = reverse($1)`,
		"8d7c6b1a49166a46ff293af2d4236eabe68e311d", newdoc)
	c.Assert(err, gc.IsNil, gc.Commentf("mangle casey's key"))
	_, err = s.storage.Exec(`UPDATE subkeys SET vsubfp = '' WHERE rsubfp = reverse($1)`, "636e5e7c575d2e971318b663ca7e517d2a42ac0a")
	c.Assert(err, gc.IsNil, gc.Commentf("mangle casey's subkey"))
	_, err = s.storage.Exec(`DELETE FROM subkeys WHERE rsubfp = reverse($1)`, "6f6d93d0811d1f8b7a34944b782e33de1a96e4c8")
	c.Assert(err, gc.IsNil, gc.Commentf("delete casey's subkey"))
	_, err = s.storage.Exec(`UPDATE userids SET identity = '' WHERE identity = 'cmars@cmarstech.com'`)
	c.Assert(err, gc.IsNil, gc.Commentf("mangle casey's userid"))
	_, err = s.storage.Exec(`DELETE FROM userids WHERE identity = 'casey.marshall@canonical.com'`)
	c.Assert(err, gc.IsNil, gc.Commentf("delete casey's userid"))

	log.Infof("setupReload ready...")
	return oldkeydocs
}

// checkReload confirms that the (surviving) test keys are intact
func (s *S) checkReload(c *gc.C, oldkeydocs []*types.KeyDoc) {
	// Check that reloading put Casey back to normal, apart from the timestamps
	newkeydocs, err := s.storage.fetchKeyDocsByRfp([]string{types.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment := gc.Commentf("fetch 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newkeydocs, gc.HasLen, 1, comment)
	c.Assert(newkeydocs[0].Keywords, gc.Equals, "'canonical.com' 'casey' 'casey marshall <casey.marshall@canonical.com>' 'casey marshall <cmars@cmarstech.com>' 'casey.marshall' 'casey.marshall@canonical.com' 'cmars' 'cmars@cmarstech.com' 'cmarstech.com' 'marshall'", comment)
	c.Assert(newkeydocs[0].CTime.Equal(oldkeydocs[0].CTime), gc.Equals, true, comment)
	c.Assert(newkeydocs[0].MTime.Equal(oldkeydocs[0].MTime), gc.Equals, false, comment)
	c.Assert(newkeydocs[0].IdxTime.Equal(oldkeydocs[0].IdxTime), gc.Equals, false, comment)
	c.Assert(len(newkeydocs[0].Doc), gc.Equals, len(oldkeydocs[0].Doc), comment)

	newsubkeydocs, err := s.storage.fetchSubKeyDocsByRfp([]string{types.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")}, false)
	comment = gc.Commentf("fetch subkeys 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newsubkeydocs, gc.HasLen, 2, comment)
	c.Assert(newsubkeydocs[0].Fingerprint, gc.Equals, "8d7c6b1a49166a46ff293af2d4236eabe68e311d", comment)
	c.Assert(newsubkeydocs[1].Fingerprint, gc.Equals, "8d7c6b1a49166a46ff293af2d4236eabe68e311d", comment)
	c.Assert(newsubkeydocs[0].VSubKeyFp, gc.Equals, "04636e5e7c575d2e971318b663ca7e517d2a42ac0a", comment)
	c.Assert(newsubkeydocs[1].VSubKeyFp, gc.Equals, "046f6d93d0811d1f8b7a34944b782e33de1a96e4c8", comment)

	newuseriddocs, err := s.storage.fetchUserIdDocsByRfp([]string{types.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment = gc.Commentf("fetch userids 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(newuseriddocs, gc.HasLen, 2, comment)
	c.Assert(newuseriddocs[0].Fingerprint, gc.Equals, "8d7c6b1a49166a46ff293af2d4236eabe68e311d", comment)
	c.Assert(newuseriddocs[1].Fingerprint, gc.Equals, "8d7c6b1a49166a46ff293af2d4236eabe68e311d", comment)
	c.Assert(newuseriddocs[0].UidString, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>", comment)
	c.Assert(newuseriddocs[0].Identity, gc.Equals, "casey.marshall@canonical.com", comment)
	c.Assert(newuseriddocs[1].UidString, gc.Equals, "Casey Marshall <cmars@cmarstech.com>", comment)
	c.Assert(newuseriddocs[1].Identity, gc.Equals, "cmars@cmarstech.com", comment)

	// Check that Alice's key is still searchable by her encryption subkey fingerprint
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x6A5B700BF3D13863")
	comment = gc.Commentf("search=0x6A5B700BF3D13863")
	c.Assert(err, gc.IsNil, comment)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1, comment)
	c.Assert(keys[0].KeyID, gc.Equals, "361bc1f023e0dcca", comment)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1, comment)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 2, comment)

	// Check that there are only two records in the database
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 2, gc.Commentf("Check that there are only two records in the database"))
}

func (s *S) TestReload(c *gc.C) {
	log.Infof("starting TestReload")
	oldkeydocs := s.setupReload(c)

	n, d, err := s.storage.Reload()
	comment := gc.Commentf("reload")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(n, gc.Equals, 2, comment)
	c.Assert(d, gc.Equals, 1, comment) // the evaporating key should have been deleted

	s.checkReload(c, oldkeydocs)
}

// Same as above, but calling the bulk reload method directly.
// All the test keys fit in the one bunch, so we don't need an outer loop.
func (s *S) TestReloadBulk(c *gc.C) {
	log.Infof("starting TestReloadBulk")
	oldkeydocs := s.setupReload(c)

	bookmark := time.Time{}
	newRecords := make([]*hkpstorage.Record, 0, keysInBunch)
	result := hkpstorage.InsertError{}
	count, finished := s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	comment := gc.Commentf("getReloadBunch (bulk)")
	c.Assert(count, gc.Equals, 3, comment)
	c.Assert(finished, gc.Equals, false, comment)
	newKeys, oldKeys := validateRecords(newRecords)
	bs, err := s.storage.bulkCreateTempTables()
	c.Assert(err, gc.IsNil)
	defer bs.bulkDropTempTables()
	n, d, ok := bs.bulkInsert(newKeys, &result, oldKeys)
	comment = gc.Commentf("bulkInsert")
	c.Assert(result.Errors, gc.HasLen, 0, comment)
	c.Assert(ok, gc.Equals, true, comment)
	c.Assert(n, gc.Equals, 2, comment)
	c.Assert(d, gc.Equals, 1, comment) // the evaporating key should have been deleted

	// check that there are no more keys
	count, finished = s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	comment = gc.Commentf("getReloadBunch second time (bulk)")
	c.Assert(count, gc.Equals, 0, comment)
	c.Assert(finished, gc.Equals, true, comment)

	s.checkReload(c, oldkeydocs)
}

// Same as above, but calling the fallback reload method directly.
// All the test keys fit in the one bunch, so we don't need an outer loop.
func (s *S) TestReloadIncremental(c *gc.C) {
	log.Infof("starting TestReloadIncremental")
	oldkeydocs := s.setupReload(c)

	bookmark := time.Time{}
	newRecords := make([]*hkpstorage.Record, 0, keysInBunch)
	result := hkpstorage.InsertError{}
	count, finished := s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	comment := gc.Commentf("getReloadBunch (incremental)")
	c.Assert(count, gc.Equals, 3, comment)
	c.Assert(finished, gc.Equals, false, comment)
	_, _ = validateRecords(newRecords)
	n, d, ok := s.storage.reloadIncremental(newRecords, &result)
	comment = gc.Commentf("reloadIncremental")
	c.Assert(ok, gc.Equals, true, comment)
	c.Assert(result.Errors, gc.HasLen, 0, comment)
	c.Assert(n, gc.Equals, 2, comment)
	c.Assert(d, gc.Equals, 1, comment) // the evaporating key should have been deleted

	// check that there are no more keys
	count, finished = s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	comment = gc.Commentf("getReloadBunch second time (incremental)")
	c.Assert(count, gc.Equals, 0, comment)
	c.Assert(finished, gc.Equals, true, comment)

	s.checkReload(c, oldkeydocs)
}
