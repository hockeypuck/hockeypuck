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
	"github.com/pkg/errors"
	gc "gopkg.in/check.v1"

	"hockeypuck/hkp"
	"hockeypuck/hkp/jsonhkp"
	pksstorage "hockeypuck/hkp/pks/storage"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"
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
	c.Assert(keys[0].KeyID(), gc.Equals, "cc5112bdce353cf4")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Jenny Ondioline <jennyo@transient.net>")
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
		c.Assert(keys[0].KeyID(), gc.Equals, "f79362da44a2d1db")
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
		c.Assert(keys[0].KeyID(), gc.Equals, "3287f5a32632c2c3")
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
		c.Assert(keys[0].KeyID(), gc.Equals, "a4eb82d2573f7c77")
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
	c.Assert(keys[0].KeyID(), gc.Equals, "361bc1f023e0dcca")
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
	c.Assert(keys[0].KeyID(), gc.Equals, "422c9066e21f705a")
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
		c.Assert(keys[0].KeyID(), gc.Equals, "d4236eabe68e311d")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>")
	}
}

func (s *S) assertKeyNotFound(c *gc.C, fp string) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + fp)
	comment := gc.Commentf("search=%s", fp)
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)
}

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
			if keys[ki].UserIDs[ui].Keywords == uid {
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

func (s *S) TestReindex(c *gc.C) {
	s.addKey(c, "e68e311d.asc")

	// Now reset the keywords column of the test key's DB record
	_, err := s.storage.Exec(`UPDATE keys SET keywords = '' WHERE rfingerprint = $1`, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"))
	c.Assert(err, gc.IsNil)

	oldkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	c.Assert(err, gc.IsNil)
	c.Assert(oldkeydocs, gc.HasLen, 1)
	c.Assert(oldkeydocs[0].Keywords, gc.Equals, "")

	// Check that Casey's key is no longer indexed by name
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=casey+marshall")
	comment := gc.Commentf("search=casey+marshall")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound, comment)

	err = s.storage.Reindex()
	c.Assert(err, gc.IsNil)

	// Check that reindexing only changed the desired fields
	newkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	c.Assert(err, gc.IsNil)
	c.Assert(newkeydocs, gc.HasLen, 1)
	c.Assert(newkeydocs[0].Keywords, gc.Equals, "'canonical.com' 'casey' 'casey marshall <casey.marshall@canonical.com>' 'casey marshall <cmars@cmarstech.com>' 'casey.marshall' 'casey.marshall@canonical.com' 'cmars' 'cmars@cmarstech.com' 'cmarstech.com' 'marshall'")
	c.Assert(newkeydocs[0].CTime, gc.Equals, oldkeydocs[0].CTime)
	c.Assert(newkeydocs[0].MTime, gc.Equals, oldkeydocs[0].MTime)
	c.Assert(newkeydocs[0].IdxTime, gc.Not(gc.Equals), oldkeydocs[0].IdxTime)

	// Check that Casey's key is indexed again
	res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=casey+marshall")
	c.Assert(err, gc.IsNil, comment)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	// Check that reindexing is idempotent
	err = s.storage.Reindex()
	c.Assert(err, gc.IsNil)
	idemkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	c.Assert(err, gc.IsNil)
	c.Assert(idemkeydocs, gc.DeepEquals, newkeydocs)
}

// factorise out setupReload and checkReload because we use them in multiple testss

// setupReload loads the test keys
func (s *S) setupReload(c *gc.C) (oldkeydocs []*types.KeyDoc) {
	s.addKey(c, "e68e311d.asc")
	s.addKey(c, "alice_signed.asc")

	// insert a bad key directly into database (bypassing validation)
	// this should evaporate on reload
	keys := openpgp.MustReadArmorKeys(testing.MustInput("snowcrash_evaporated.asc"))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	_, _, err := s.storage.Insert(keys)
	c.Assert(err, gc.IsNil)

	// Check that there are three records in the database
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 3)

	oldkeydocs, err = s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	c.Assert(err, gc.IsNil)
	c.Assert(oldkeydocs, gc.HasLen, 1)

	// Now mangle Casey's key and write back
	newdoc := `{"nonsense": "nonsense", ` + oldkeydocs[0].Doc[1:]
	_, err = s.storage.Exec(`UPDATE keys SET keywords = '', doc = $2 WHERE rfingerprint = $1`, openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d"), newdoc)
	c.Assert(err, gc.IsNil)
	return oldkeydocs
}

// checkReload confirms that the (surviving) test keys are intact
func (s *S) checkReload(c *gc.C, oldkeydocs []*types.KeyDoc) {
	// Check that reloading put Casey back to normal, apart from the timestamps
	newkeydocs, err := s.storage.fetchKeyDocs([]string{openpgp.Reverse("8d7c6b1a49166a46ff293af2d4236eabe68e311d")})
	c.Assert(err, gc.IsNil)
	c.Assert(newkeydocs, gc.HasLen, 1)
	c.Assert(newkeydocs[0].Keywords, gc.Equals, "'canonical.com' 'casey' 'casey marshall <casey.marshall@canonical.com>' 'casey marshall <cmars@cmarstech.com>' 'casey.marshall' 'casey.marshall@canonical.com' 'cmars' 'cmars@cmarstech.com' 'cmarstech.com' 'marshall'")
	c.Assert(newkeydocs[0].CTime, gc.Equals, oldkeydocs[0].CTime)
	c.Assert(newkeydocs[0].MTime, gc.Not(gc.Equals), oldkeydocs[0].MTime)
	c.Assert(newkeydocs[0].IdxTime, gc.Not(gc.Equals), oldkeydocs[0].IdxTime)
	c.Assert(len(newkeydocs[0].Doc), gc.Equals, len(oldkeydocs[0].Doc))

	// Check that Alice's key is still searchable by her encryption subkey fingerprint
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x6A5B700BF3D13863")
	comment := gc.Commentf("search=0x6A5B700BF3D13863")
	c.Assert(err, gc.IsNil, comment)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil, comment)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK, comment)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID(), gc.Equals, "361bc1f023e0dcca")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 2)

	// Check that there are only two records in the database
	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 2)
}

func (s *S) TestReload(c *gc.C) {
	oldkeydocs := s.setupReload(c)

	n, d, err := s.storage.Reload()
	c.Assert(err, gc.IsNil)
	c.Assert(n, gc.Equals, 2)
	c.Assert(d, gc.Equals, 1) // the evaporating key should have been deleted

	s.checkReload(c, oldkeydocs)
}

// Same as above, but calling the bulk reload method directly.
// All the test keys fit in the one bunch, so we don't need an outer loop.
func (s *S) TestReloadBulk(c *gc.C) {
	oldkeydocs := s.setupReload(c)

	bookmark := time.Time{}
	newRecords := make([]*hkpstorage.Record, 0, keysInBunch)
	result := hkpstorage.InsertError{}
	count, finished := s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	c.Assert(count, gc.Equals, 3)
	c.Assert(finished, gc.Equals, false)
	newKeys, oldKeys := validateRecords(newRecords)
	n, d, ok := s.storage.bulkInsert(newKeys, &result, oldKeys)
	c.Assert(ok, gc.Equals, true)
	c.Assert(result.Errors, gc.HasLen, 0)
	c.Assert(n, gc.Equals, 2)
	c.Assert(d, gc.Equals, 1) // the evaporating key should have been deleted

	// check that there are no more keys
	count, finished = s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	c.Assert(count, gc.Equals, 0)
	c.Assert(finished, gc.Equals, true)

	s.checkReload(c, oldkeydocs)
}

// Same as above, but calling the fallback reload method directly.
// All the test keys fit in the one bunch, so we don't need an outer loop.
func (s *S) TestReloadIncremental(c *gc.C) {
	oldkeydocs := s.setupReload(c)

	bookmark := time.Time{}
	newRecords := make([]*hkpstorage.Record, 0, keysInBunch)
	result := hkpstorage.InsertError{}
	count, finished := s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	c.Assert(count, gc.Equals, 3)
	c.Assert(finished, gc.Equals, false)
	_, _ = validateRecords(newRecords)
	n, d, ok := s.storage.reloadIncremental(newRecords, &result)
	c.Assert(ok, gc.Equals, true)
	c.Assert(result.Errors, gc.HasLen, 0)
	c.Assert(n, gc.Equals, 2)
	c.Assert(d, gc.Equals, 1) // the evaporating key should have been deleted

	// check that there are no more keys
	count, finished = s.storage.getReloadBunch(&bookmark, &newRecords, &result)
	c.Assert(count, gc.Equals, 0)
	c.Assert(finished, gc.Equals, true)

	s.checkReload(c, oldkeydocs)
}

func (s *S) TestPKS(c *gc.C) {
	testAddr := "mailto:test@example.com"
	now := time.Now()
	testError := errors.Errorf("unknown error")
	testStatus := pksstorage.Status{Addr: testAddr, LastSync: now, LastError: testError}

	err := s.storage.PKSInit(testAddr, now)
	c.Assert(err, gc.IsNil)
	statuses, err := s.storage.PKSAll()
	c.Assert(err, gc.IsNil)
	c.Assert(statuses, gc.HasLen, 1)
	status := statuses[0]
	c.Assert(status.Addr, gc.Equals, testAddr)
	c.Assert(status.LastSync.UTC(), gc.Equals, now.UTC().Round(time.Microsecond))
	c.Assert(status.LastError, gc.IsNil)

	// PKSUpdate should populate LastError
	err = s.storage.PKSUpdate(&testStatus)
	c.Assert(err, gc.IsNil)
	status, err = s.storage.PKSGet(testAddr)
	c.Assert(err, gc.IsNil)
	c.Assert(status.LastError, gc.NotNil)
	c.Assert(status.LastError.Error(), gc.Equals, testError.Error())

	// PKSInit should not update
	next := now.Add(time.Second)
	err = s.storage.PKSInit(testAddr, next)
	c.Assert(err, gc.IsNil)
	status, err = s.storage.PKSGet(testAddr)
	c.Assert(err, gc.IsNil)
	c.Assert(status.LastSync.UTC(), gc.Equals, now.UTC().Round(time.Microsecond))
	c.Assert(status.LastError, gc.NotNil)
	c.Assert(status.LastError.Error(), gc.Equals, testError.Error())

	testStatus2 := pksstorage.Status{Addr: testAddr, LastSync: next, LastError: nil}
	err = s.storage.PKSUpdate(&testStatus2)
	c.Assert(err, gc.IsNil)
	status, err = s.storage.PKSGet(testAddr)
	c.Assert(err, gc.IsNil)
	c.Assert(status.Addr, gc.Equals, testAddr)
	c.Assert(status.LastSync.UTC(), gc.Equals, next.UTC().Round(time.Microsecond))
	c.Assert(status.LastError, gc.IsNil)

	err = s.storage.PKSRemove(testAddr)
	c.Assert(err, gc.IsNil)
	statuses, err = s.storage.PKSAll()
	c.Assert(err, gc.IsNil)
	c.Assert(statuses, gc.HasLen, 0)
}
