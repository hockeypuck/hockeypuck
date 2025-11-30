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
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	stdtesting "testing"
	"time"

	"hockeypuck/pgtest"
	"hockeypuck/testing"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"hockeypuck/hkp"
	"hockeypuck/hkp/jsonhkp"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"

	log "github.com/sirupsen/logrus"
)

func Test(t *stdtesting.T) {
	if os.Getenv("POSTGRES_TESTS") == "" {
		t.Skip("skipping postgresql integration test, specify -postgresql-integration to run")
	}
	gc.TestingT(t)
}

type S struct {
	pgtest.PGSuite
	storage *storage
	db      *sql.DB
	srv     *httptest.Server
}

var _ = gc.Suite(&S{})

func (s *S) SetUpTest(c *gc.C) {
	s.PGSuite.SetUpTest(c)

	c.Log(s.URL)
	var err error
	s.db, err = sql.Open("postgres", s.URL)
	c.Assert(err, gc.IsNil)

	s.db.Exec("DROP DATABASE hkp")

	st, err := New(s.db, nil)
	c.Assert(err, gc.IsNil)
	s.storage = st.(*storage)

	testAdminKeys := hkp.AdminKeys([]string{"0x5B74AE43F908323506BD2DFD31EDE6D1DF9E2BAF"})
	r := httprouter.New()
	handler, err := hkp.NewHandler(s.storage, testAdminKeys)
	c.Assert(err, gc.IsNil)
	handler.Register(r)
	s.srv = httptest.NewServer(r)

	log.SetLevel(log.DebugLevel)
}

func (s *S) TearDownTest(c *gc.C) {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.db != nil {
		s.db.Exec("DROP DATABASE hkp")
		s.db.Close()
	}
	s.PGSuite.TearDownTest(c)
}

func (s *S) addKey(c *gc.C, keyname string) []byte {
	keytext, err := io.ReadAll(testing.MustInput(keyname))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)
	return data
}

func (s *S) queryAllKeys(c *gc.C) []*types.KeyDoc {
	rows, err := s.db.Query("SELECT rfingerprint, ctime, mtime, idxtime, md5, doc, keywords FROM keys")
	c.Assert(err, gc.IsNil)
	defer rows.Close()
	var result []*types.KeyDoc
	for rows.Next() {
		var doc types.KeyDoc
		err = rows.Scan(&doc.RFingerprint, &doc.CTime, &doc.MTime, &doc.IdxTime, &doc.MD5, &doc.Doc, &doc.Keywords)
		c.Assert(err, gc.IsNil)
		result = append(result, &doc)
	}
	c.Assert(rows.Err(), gc.IsNil)
	return result
}

func assertParse(d *types.KeyDoc, c *gc.C) *jsonhkp.PrimaryKey {
	var pk jsonhkp.PrimaryKey
	err := json.Unmarshal([]byte(d.Doc), &pk)
	c.Assert(err, gc.IsNil)
	return &pk
}

func (s *S) TestMD5(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "sksdigest.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(keyDocs[0].MD5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa")
	jsonDoc := assertParse(keyDocs[0], c)
	c.Assert(jsonDoc.MD5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa")

	res, err = http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, "cc5112bdce353cf4")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Jenny Ondioline <jennyo@transient.net>")
}

func (s *S) TestTableSchemas(c *gc.C) {
	s.addKey(c, "e68e311d.asc")

	keydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment := gc.Commentf("fetch 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(keydocs, gc.HasLen, 1, comment)
	c.Assert(keydocs[0].Keywords, gc.Equals, "'canonical.com' 'casey' 'casey marshall <casey.marshall@canonical.com>' 'casey marshall <cmars@cmarstech.com>' 'casey.marshall' 'casey.marshall@canonical.com' 'cmars' 'cmars@cmarstech.com' 'cmarstech.com' 'marshall'", comment)
	c.Assert(keydocs[0].CTime.Equal(time.Time{}), gc.Equals, false, comment)
	c.Assert(keydocs[0].MTime.Equal(keydocs[0].CTime), gc.Equals, true, comment)
	c.Assert(keydocs[0].IdxTime.Equal(keydocs[0].CTime), gc.Equals, true, comment)
	c.Assert(keydocs[0].VFingerprint, gc.Equals, "048d7c6b1a49166a46ff293af2d4236eabe68e311d", comment)

	subkeydocs, err := s.storage.fetchSubKeyDocs([]string{"a0ca24a2d715e7ac366b813179e2d575c7e5e636"}, true)
	comment = gc.Commentf("fetch subkey a0ca24a2d715e7ac366b813179e2d575c7e5e636")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(subkeydocs, gc.HasLen, 1, comment)
	c.Assert(subkeydocs[0].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(subkeydocs[0].VSubKeyFp, gc.Equals, "04636e5e7c575d2e971318b663ca7e517d2a42ac0a", comment)

	uiddocs, err := s.storage.fetchUserIdDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	comment = gc.Commentf("fetch userids 8d7c6b1a49166a46ff293af2d4236eabe68e311d")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(uiddocs, gc.HasLen, 2, comment)
	c.Assert(uiddocs[0].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(uiddocs[0].UidString, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>", comment)
	c.Assert(uiddocs[0].Identity, gc.Equals, "casey.marshall@canonical.com", comment)
	c.Assert(uiddocs[0].Confidence, gc.Equals, 0, comment)
	c.Assert(uiddocs[1].RFingerprint, gc.Equals, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), comment)
	c.Assert(uiddocs[1].UidString, gc.Equals, "Casey Marshall <cmars@cmarstech.com>", comment)
	c.Assert(uiddocs[1].Identity, gc.Equals, "cmars@cmarstech.com", comment)
	c.Assert(uiddocs[1].Confidence, gc.Equals, 0, comment)
}

// Test round-trip of TSVector through PostgreSQL
func (s *S) TestTSVector(c *gc.C) {
	s.addKey(c, "sksdigest.asc")
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(keyDocs[0].Keywords, gc.Equals, "'jenny' 'jenny ondioline <jennyo@transient.net>' 'jennyo' 'jennyo@transient.net' 'ondioline' 'transient.net'")
}

func (s *S) TestAddDuplicates(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	for i := 0; i < 10; i++ {
		s.addKey(c, "sksdigest.asc")
	}

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(keyDocs[0].MD5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa")
}

func (s *S) TestResolve(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0xf79362da44a2d1db")
	comment := gc.Commentf("search=0xf79362da44a2d1db")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)

	s.addKey(c, "uat.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(assertParse(keyDocs[0], c).LongKeyID, gc.Equals, "f79362da44a2d1db")

	// Should match
	for _, search := range []string{
		// key ID and fingerprint match
		"0xf79362da44a2d1db", "0x81279eee7ec89fb781702adaf79362da44a2d1db",

		// subkeys
		"0xdb769d16cdb9ad53", "0xe9ebaf4195c1826c", "0x6cdc23d76cba8ca9",

		// full fingerprint subkeys
		"0xb62a1252f26aebafee124e1fdb769d16cdb9ad53",
		"0x5b28eca0cc5033df4f00038be9ebaf4195c1826c",
		"0x313988d090243bb576b88b4f6cdc23d76cba8ca9",

		// contiguous words, usernames, domains and email addresses match
		"casey", "marshall", "casey+marshall", "cAseY+MArSHaLL",
		"casey.marshall@gmail.com", "casey.marshall@gazzang.com",
		"casey.marshall", "gmail.com",

		// stop words should not affect the match
		"is+casey", "the+marshall", "your+casey+marshall",

		// full textual IDs that include characters special to tsquery match
		"Casey+Marshall+<casey.marshall@gmail.com>"} {
		comment := gc.Commentf("search=%s", search)
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil, comment)
		armor, err := io.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil, comment)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].KeyID, gc.Equals, "f79362da44a2d1db")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@gazzang.com>")
	}

	// Shouldn't match any of these
	for _, search := range []string{
		"0xdeadbeef", "0xce353cf4", "0xd1db", "44a2d1db", "0xadaf79362da44a2d1db",
		"alice@example.com", "bob@example.com", "com"} {
		comment := gc.Commentf("search=%s", search)
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil, comment)
		res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)
	}
}

func (s *S) TestResolveWithHyphen(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x3287f5a32632c2c3")
	comment := gc.Commentf("search=0x3287f5a32632c2c3")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)

	s.addKey(c, "steven-12345.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(assertParse(keyDocs[0], c).LongKeyID, gc.Equals, "3287f5a32632c2c3")
	c.Assert(keyDocs[0].Keywords, gc.Equals, "'12345' 'encryption' 'example.com' 'steven' 'steven-12345' 'steven-12345 (test encryption) <steven-test@example.com>' 'steven-test' 'steven-test@example.com' 'test'")

	// Should match
	for _, search := range []string{
		// key ID and fingerprint match
		"0x3287f5a32632c2c3", "0x68d1b3d8b76c50f7c97038393287f5a32632c2c3",

		// contiguous words, usernames, domains and email addresses match
		"steven", "steven-12345", "Test", "Encryption", "Test+Encryption", "TeSt+EnCrYpTiOn",
		"steven-test@example.com", "steven-test", "example.com",

		// full textual IDs that include characters special to tsquery match
		"steven-12345+(Test+Encryption)+<steven-test@example.com>"} {
		comment := gc.Commentf("search=%s", search)
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil, comment)
		armor, err := io.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil, comment)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].KeyID, gc.Equals, "3287f5a32632c2c3")
		c.Assert(keys[0].UserIDs, gc.HasLen, 1)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "steven-12345 (Test Encryption) <steven-test@example.com>")
	}

	// Shouldn't match any of these
	for _, search := range []string{
		"0xdeadbeef", "0xce353cf4", "0xc2c3", "2632c2c3", "0x8393287f5a32632c2c3",
		"alice@example.com", "bob@example.com", "com"} {
		comment := gc.Commentf("search=%s", search)
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil, comment)
		res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)
	}
}

func (s *S) TestResolveBareEmail(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0xa4eb82d2573f7c77")
	comment := gc.Commentf("search=0xa4eb82d2573f7c77")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)

	s.addKey(c, "bare-email-posteo.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(assertParse(keyDocs[0], c).LongKeyID, gc.Equals, "a4eb82d2573f7c77")
	c.Assert(keyDocs[0].Keywords, gc.Equals, "'posteo.de' 'support' 'support@posteo.de'")

	// Should match
	for _, search := range []string{
		// key ID and fingerprint match
		"0xa4eb82d2573f7c77", "0x9671c8185c6519abb4e8ad9fa4eb82d2573f7c77",

		// subkeys
		"0x21b4ba25958075da",

		// full fingerprint subkeys
		"0x72059de4c577b5da81de9a0521b4ba25958075da",

		// contiguous words, usernames, domains and email addresses match
		"support@posteo.de", "support", "posteo.de",

		// full textual IDs that include characters special to tsquery match
		"<support@posteo.de>"} {
		comment := gc.Commentf("search=%s", search)
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil, comment)
		armor, err := io.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil, comment)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].KeyID, gc.Equals, "a4eb82d2573f7c77")
		c.Assert(keys[0].UserIDs, gc.HasLen, 1)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "support@posteo.de")
	}

	// Shouldn't match any of these
	for _, search := range []string{
		"0xdeadbeef", "0xce353cf4", "0x7c77", "573f7c77", "0xd9fa4eb82d2573f7c77",
		"alice@example.com", "bob@example.com", "posteo"} {
		comment := gc.Commentf("search=%s", search)
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil, comment)
		res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)
	}
}

func (s *S) TestMerge(c *gc.C) {
	s.addKey(c, "alice_unsigned.asc")
	s.addKey(c, "alice_signed.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=alice@example.com")
	comment := gc.Commentf("search=alice@example.com")
	c.Assert(err, gc.IsNil, comment)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, "361bc1f023e0dcca")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 2)
}

func (s *S) TestPolicyURI(c *gc.C) {
	s.addKey(c, "gentoo-l2-infra.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=openpgp-auth%2Bl2-infra@gentoo.org")
	comment := gc.Commentf("%s", "search=openpgp-auth%2Bl2-infra@gentoo.org") // beware '%' in search string
	c.Assert(err, gc.IsNil, comment)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, "422c9066e21f705a")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	// this shouldn't actually care WHICH signature the policy URI is at in the same way.
	c.Assert(keys[0].UserIDs[0].Signatures[2].IssuerKeyID(), gc.Equals, "2839fe0d796198b1")
	c.Assert(keys[0].UserIDs[0].Signatures[2].PolicyURI, gc.Equals, "https://www.gentoo.org/glep/glep-0079.html")
}

func (s *S) TestEd25519(c *gc.C) {
	s.addKey(c, "e68e311d.asc")

	for _, search := range []string{
		// long key ID and fingerprint match
		"0xd4236eabe68e311d", "0x8d7c6b1a49166a46ff293af2d4236eabe68e311d",
		// contiguous words and email addresses match
		"casey", "marshall", "casey+marshall", "cAseY+MArSHaLL",
		"cmars@cmarstech.com", "casey.marshall@canonical.com"} {
		res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		comment := gc.Commentf("search=%s", search)
		c.Assert(err, gc.IsNil, comment)
		armor, err := io.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil, comment)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].KeyID, gc.Equals, "d4236eabe68e311d")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>")
	}
}

func (s *S) TestDropNullUserIDs(c *gc.C) {
	// This key has one userID that contains a null byte, which is forbidden.
	// It contains other valid selfsigs, so does not evaporate.
	s.addKey(c, "270f682dc391d7d9.asc")
	s.assertKey(c, "0xd943ebb8639c530e99f70ca0270f682dc391d7d9", "", false)
}

func (s *S) assertKeyNotFound(c *gc.C, fp string) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + fp)
	comment := gc.Commentf("search=%s", fp)
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)
}

// assertKey checks if a userID exists (or not) on the key with a given fingerprint.
// If the userID is the empty string, it checks if *any* userIDs exist (or not).
func (s *S) assertKey(c *gc.C, fp, uid string, exist bool) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + fp)
	comment := gc.Commentf("search=%s", fp)
	c.Assert(err, gc.IsNil, comment)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	for ki := range keys {
		for ui := range keys[ki].UserIDs {
			if uid == "" || keys[ki].UserIDs[ui].Keywords == uid {
				c.Assert(exist, gc.Equals, true)
				return
			}
		}
	}
	c.Assert(exist, gc.Equals, false)
}

func (s *S) TestReplaceNoSig(c *gc.C) {
	// Original key has uids "somename" and "forgetme"
	s.addKey(c, "replace_orig.asc")
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", true)

	// Replace without signature gets ignored
	keytext, err := io.ReadAll(testing.MustInput("replace.asc"))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/replace", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	defer res.Body.Close()
	c.Assert(res.StatusCode, gc.Equals, http.StatusBadRequest)

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", true)
}

func (s *S) TestAddDoesntReplace(c *gc.C) {
	// Original key has uids "somename" and "forgetme"
	s.addKey(c, "replace_orig.asc")
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", true)

	// Signature without replace directive gets ignored
	keytext, err := io.ReadAll(testing.MustInput("replace.asc"))
	c.Assert(err, gc.IsNil)
	keysig, err := io.ReadAll(testing.MustInput("replace.asc.asc"))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
		"keysig":  []string{string(keysig)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	_, err = io.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", true)
}

func (s *S) TestReplaceWithAdminSig(c *gc.C) {
	// Original key has uids "somename" and "forgetme"
	// Admin key has uid "admin"
	s.addKey(c, "replace_orig.asc")
	s.addKey(c, "admin.asc")
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 2)

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", true)
	s.assertKey(c, "0x5B74AE43F908323506BD2DFD31EDE6D1DF9E2BAF", "admin", true)

	keytext, err := io.ReadAll(testing.MustInput("replace.asc"))
	c.Assert(err, gc.IsNil)
	keysig, err := io.ReadAll(testing.MustInput("replace.asc.asc"))
	c.Assert(err, gc.IsNil)

	values := url.Values{
		"keytext": []string{string(keytext)},
		"keysig":  []string{string(keysig)},
	}
	res, err := http.PostForm(s.srv.URL+"/pks/replace", values)
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", false)
	s.assertKey(c, "0x5B74AE43F908323506BD2DFD31EDE6D1DF9E2BAF", "admin", true)
}

func (s *S) TestDeleteWithAdminSig(c *gc.C) {
	// Original key has uids "somename" and "forgetme"
	// Admin key has uid "admin"
	s.addKey(c, "replace_orig.asc")
	s.addKey(c, "admin.asc")
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 2)

	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "somename", true)
	s.assertKey(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC", "forgetme", true)
	s.assertKey(c, "0x5B74AE43F908323506BD2DFD31EDE6D1DF9E2BAF", "admin", true)

	keytext, err := io.ReadAll(testing.MustInput("delete.asc"))
	c.Assert(err, gc.IsNil)
	keysig, err := io.ReadAll(testing.MustInput("delete.asc.asc"))
	c.Assert(err, gc.IsNil)

	values := url.Values{
		"keytext": []string{string(keytext)},
		"keysig":  []string{string(keysig)},
	}
	res, err := http.PostForm(s.srv.URL+"/pks/delete", values)
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()

	s.assertKeyNotFound(c, "0xB3836BA47C8CFE0CEBD000CBF30F9BABFDD1F1EC")
	s.assertKey(c, "0x5B74AE43F908323506BD2DFD31EDE6D1DF9E2BAF", "admin", true)
}

func (s *S) TestAddBareRevocation(c *gc.C) {
	s.addKey(c, "test-key.asc")
	doc := s.addKey(c, "test-key-revoke.asc")
	var addRes hkp.AddResponse
	err := json.Unmarshal(doc, &addRes)
	c.Assert(err, gc.IsNil)
	c.Assert(addRes.Inserted, gc.HasLen, 0)
	c.Assert(addRes.Updated, gc.HasLen, 1)
}

func (s *S) TestOldestIdxTime(c *gc.C) {
	s.addKey(c, "e68e311d.asc")
	now := time.Now()
	t := s.storage.oldestIdxTime() // returns time.Now() on error, which will be later than the time.Now() above, so the line below should fail
	c.Assert(t.Before(now), gc.Equals, true)
	c.Assert(t.Add(time.Minute).Before(now), gc.Equals, false)
}
