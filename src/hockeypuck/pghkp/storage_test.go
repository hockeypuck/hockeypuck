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

	"hockeypuck/pgtest"
	"hockeypuck/testing"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"hockeypuck/hkp"
	"hockeypuck/hkp/jsonhkp"
	"hockeypuck/openpgp"
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

func (s *S) addKey(c *gc.C, keyname string) {
	keytext, err := io.ReadAll(testing.MustInput(keyname))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	_, err = io.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)
}

func (s *S) queryAllKeys(c *gc.C) []*keyDoc {
	rows, err := s.db.Query("SELECT rfingerprint, ctime, mtime, md5, doc FROM keys")
	c.Assert(err, gc.IsNil)
	defer rows.Close()
	var result []*keyDoc
	for rows.Next() {
		var doc keyDoc
		err = rows.Scan(&doc.RFingerprint, &doc.CTime, &doc.MTime, &doc.MD5, &doc.Doc)
		c.Assert(err, gc.IsNil)
		result = append(result, &doc)
	}
	c.Assert(rows.Err(), gc.IsNil)
	return result
}

func (d *keyDoc) assertParse(c *gc.C) *jsonhkp.PrimaryKey {
	var pk jsonhkp.PrimaryKey
	err := json.Unmarshal([]byte(d.Doc), &pk)
	c.Assert(err, gc.IsNil)
	return &pk
}

func (s *S) TestMD5(c *gc.C) {
	// res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa") // this digest includes unhashed subpackets
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=6697e3e34853841a2f9c5010e5a40439")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "sksdigest.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	// c.Assert(keyDocs[0].MD5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa") // this digest includes unhashed subpackets
	c.Assert(keyDocs[0].MD5, gc.Equals, "6697e3e34853841a2f9c5010e5a40439")
	jsonDoc := keyDocs[0].assertParse(c)
	// c.Assert(jsonDoc.MD5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa") // this digest includes unhashed subpackets
	c.Assert(jsonDoc.MD5, gc.Equals, "6697e3e34853841a2f9c5010e5a40439")

	// res, err = http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa") // this digest includes unhashed subpackets
	res, err = http.Get(s.srv.URL + "/pks/lookup?op=hget&search=6697e3e34853841a2f9c5010e5a40439")
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "ce353cf4")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Jenny Ondioline <jennyo@transient.net>")
}

func (s *S) TestAddDuplicates(c *gc.C) {
	// res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa") // this digest includes unhashed subpackets
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=6697e3e34853841a2f9c5010e5a40439")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	for i := 0; i < 10; i++ {
		s.addKey(c, "sksdigest.asc")
	}

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	// c.Assert(keyDocs[0].MD5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa") // this digest includes unhashed subpackets
	c.Assert(keyDocs[0].MD5, gc.Equals, "6697e3e34853841a2f9c5010e5a40439")
}

func (s *S) TestResolve(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x44a2d1db")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "uat.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(keyDocs[0].assertParse(c).ShortKeyID, gc.Equals, "44a2d1db")

	// Should match
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0x44a2d1db", "0xf79362da44a2d1db", "0x81279eee7ec89fb781702adaf79362da44a2d1db",

		// subkeys
		"0xdb769d16cdb9ad53", "0xe9ebaf4195c1826c", "0x6cdc23d76cba8ca9",

		// full fingerprint subkeys
		"0xb62a1252f26aebafee124e1fdb769d16cdb9ad53",
		"0x5b28eca0cc5033df4f00038be9ebaf4195c1826c",
		"0x313988d090243bb576b88b4f6cdc23d76cba8ca9",

		// contiguous words, usernames, domains and email addresses match
		"casey", "marshall", "marshal", "casey+marshall", "cAseY+MArSHaLL",
		"casey.marshall@gmail.com", "casey.marshall@gazzang.com",
		"casey.marshall", "gmail.com",

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
		c.Assert(keys[0].ShortID(), gc.Equals, "44a2d1db")
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
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x2632c2c3")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "steven-12345.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(keyDocs[0].assertParse(c).ShortKeyID, gc.Equals, "2632c2c3")

	// Should match
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0x2632c2c3", "0x3287f5a32632c2c3", "0x68d1b3d8b76c50f7c97038393287f5a32632c2c3",

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
		c.Assert(keys[0].ShortID(), gc.Equals, "2632c2c3")
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
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x573f7c77")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "bare-email-posteo.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)
	c.Assert(keyDocs[0].assertParse(c).ShortKeyID, gc.Equals, "573f7c77")

	// Should match
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0x573f7c77", "0xa4eb82d2573f7c77", "0x9671c8185c6519abb4e8ad9fa4eb82d2573f7c77",

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
		c.Assert(keys[0].ShortID(), gc.Equals, "573f7c77")
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
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "23e0dcca")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 2)
}

func (s *S) TestPolicyURI(c *gc.C) {
	s.addKey(c, "gentoo-l2-infra.asc")

	keyDocs := s.queryAllKeys(c)
	c.Assert(keyDocs, gc.HasLen, 1)

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=openpgp-auth+l2-infra@gentoo.org")
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "e21f705a")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	// this shouldn't actually care WHICH signature the policy URI is at in the same way.
	c.Assert(keys[0].UserIDs[0].Signatures[2].IssuerKeyID(), gc.Equals, "2839fe0d796198b1")
	c.Assert(keys[0].UserIDs[0].Signatures[2].PolicyURI, gc.Equals, "https://www.gentoo.org/glep/glep-0079.html")
}

func (s *S) TestEd25519(c *gc.C) {
	s.addKey(c, "e68e311d.asc")

	// Should match, even if we don't fully support eddsa yet.
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0xe68e311d", "0x8d7c6b1a49166a46ff293af2d4236eabe68e311d",
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
		c.Assert(keys[0].ShortID(), gc.Equals, "e68e311d")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>")
	}
}

func (s *S) assertKeyNotFound(c *gc.C, fp string) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + fp)
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)
}

func (s *S) assertKey(c *gc.C, fp, uid string, exist bool) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + fp)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

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
	keytext, err := io.ReadAll(testing.MustInput("test-key.asc"))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	doc, err := io.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)

	var addRes hkp.AddResponse
	err = json.Unmarshal(doc, &addRes)
	c.Assert(err, gc.IsNil)
	c.Assert(addRes.Inserted, gc.HasLen, 1)

	keytext, err = io.ReadAll(testing.MustInput("test-key-revoke.asc"))
	c.Assert(err, gc.IsNil)

	res2, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res2.Body.Close()
	doc, err = io.ReadAll(res2.Body)
	c.Assert(err, gc.IsNil)
	err = json.Unmarshal(doc, &addRes)
	c.Assert(err, gc.IsNil)
	c.Assert(addRes.Inserted, gc.HasLen, 0)
	c.Assert(addRes.Updated, gc.HasLen, 1)
}
