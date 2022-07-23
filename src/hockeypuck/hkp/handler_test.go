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

package hkp

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	stdtesting "testing"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"hockeypuck/conflux/recon"
	"hockeypuck/openpgp"
	"hockeypuck/testing"

	"hockeypuck/hkp/storage/mock"
)

type testKey struct {
	fp   string
	rfp  string
	sid  string
	file string
}

var (
	testKeyDefault = &testKey{
		fp:   "10fe8cf1b483f7525039aa2a361bc1f023e0dcca",
		rfp:  "accd0e320f1cb163a2aa9305257f384b1fc8ef01",
		sid:  "23e0dcca",
		file: "alice_signed.asc",
	}
	testKeyBadSigs = &testKey{
		fp:   "a7400f5a48fb42b8cee8638b5759f35001aa4a64",
		rfp:  "46a4aa10053f9575b8368eec8b24bf84a5f0047a",
		sid:  "01aa4a64",
		file: "a7400f5a_badsigs.asc",
	}

	testKeys = map[string]*testKey{
		testKeyDefault.fp: testKeyDefault,
		testKeyBadSigs.fp: testKeyBadSigs,
	}
	testKeysRFP = map[string]*testKey{
		testKeyDefault.rfp: testKeyDefault,
		testKeyBadSigs.rfp: testKeyBadSigs,
	}
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type HandlerSuite struct {
	storage *mock.Storage
	srv     *httptest.Server
	handler *Handler
	digests int
}

var _ = gc.Suite(&HandlerSuite{})

func (s *HandlerSuite) SetUpTest(c *gc.C) {
	s.storage = mock.NewStorage(
		mock.Resolve(func(keys []string) ([]string, error) {
			tk := testKeyDefault
			if len(keys) == 1 && testKeysRFP[keys[0]] != nil {
				tk = testKeysRFP[keys[0]]
			}
			return []string{tk.fp}, nil
		}),
		mock.FetchKeys(func(keys []string) ([]*openpgp.PrimaryKey, error) {
			tk := testKeyDefault
			if len(keys) == 1 && testKeys[keys[0]] != nil {
				tk = testKeys[keys[0]]
			}
			return openpgp.MustReadArmorKeys(testing.MustInput(tk.file)), nil
		}),
	)

	r := httprouter.New()
	handler, err := NewHandler(s.storage)
	c.Assert(err, gc.IsNil)
	s.handler = handler
	s.handler.Register(r)
	s.srv = httptest.NewServer(r)
	s.digests = 50
}

func (s *HandlerSuite) TearDownTest(c *gc.C) {
	s.srv.Close()
}

func (s *HandlerSuite) TestGetKeyID(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x" + tk.sid)
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, tk.sid)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "alice <alice@example.com>")

	c.Assert(s.storage.MethodCount("MatchMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("Resolve"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("MatchKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchKeys"), gc.Equals, 1)
}

func (s *HandlerSuite) TestGetKeyword(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=alice")
	c.Assert(err, gc.IsNil)
	defer res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(s.storage.MethodCount("MatchMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("Resolve"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("MatchKeyword"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchKeys"), gc.Equals, 1)
}

func (s *HandlerSuite) TestGetMD5(c *gc.C) {
	// fake MD5, this is a mock
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=f49fba8f60c4957725dd97faa4b94647")
	c.Assert(err, gc.IsNil)
	defer res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(s.storage.MethodCount("MatchMD5"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("Resolve"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("MatchKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchKeys"), gc.Equals, 1)
}

func (s *HandlerSuite) TestIndexAlice(c *gc.C) {
	tk := testKeyDefault

	for _, op := range []string{"index", "vindex"} {
		res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=%s&search=0x"+tk.sid, s.srv.URL, op))
		c.Assert(err, gc.IsNil)
		doc, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

		var result []map[string]interface{}
		err = json.Unmarshal(doc, &result)
		c.Assert(err, gc.IsNil)

		c.Assert(result, gc.HasLen, 1)
		c.Assert(fmt.Sprintf("%v", result[0]["bitLength"]), gc.Equals, "2048")
	}

	c.Assert(s.storage.MethodCount("MatchMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("MatchKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("Resolve"), gc.Equals, 2)
	c.Assert(s.storage.MethodCount("FetchKeys"), gc.Equals, 2)
}

func (s *HandlerSuite) TestIndexAliceMR(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=0x"+tk.sid, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `info:1:1
pub:10FE8CF1B483F7525039AA2A361BC1F023E0DCCA:1:2048:1345589945::
uid:alice <alice@example.com>:1345589945::
`)
}

func (s *HandlerSuite) TestBadOp(c *gc.C) {
	for _, op := range []string{"", "?op=explode"} {
		res, err := http.Get(s.srv.URL + "/pks/lookup" + op)
		c.Assert(err, gc.IsNil)
		defer res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusBadRequest)
	}
}

func (s *HandlerSuite) TestMissingSearch(c *gc.C) {
	for _, op := range []string{"get", "index", "vindex", "index&options=mr", "vindex&options=mr"} {
		res, err := http.Get(s.srv.URL + "/pks/lookup?op=" + op)
		c.Assert(err, gc.IsNil)
		defer res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusBadRequest)
	}
}

func (s *HandlerSuite) TestAdd(c *gc.C) {
	keytext, err := ioutil.ReadAll(testing.MustInput("alice_unsigned.asc"))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	doc, err := ioutil.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)

	var addRes AddResponse
	err = json.Unmarshal(doc, &addRes)
	c.Assert(err, gc.IsNil)
	c.Assert(addRes.Ignored, gc.HasLen, 1)
}

func (s *HandlerSuite) TestFetchWithBadSigs(c *gc.C) {
	tk := testKeyBadSigs

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x" + tk.fp)
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, tk.sid)
	c.Assert(len(keys[0].Others), gc.Equals, 0)
}

func (s *HandlerSuite) SetupHashQueryTest(c *gc.C, unique bool, digests ...int) (*httptest.ResponseRecorder, *http.Request) {
	// Determine reference digest to compare with
	h := md5.New()
	refDigest := h.Sum(nil)
	url, err := url.Parse("/pks/hashquery")
	c.Assert(err, gc.IsNil)
	var buf bytes.Buffer
	c.Assert(err, gc.IsNil)
	if digests != nil {
		s.digests = digests[0]
	}
	err = recon.WriteInt(&buf, s.digests)
	c.Assert(err, gc.IsNil)
	for i := 0; i < s.digests; i++ {
		// Generate different digests
		if unique {
			b := make([]byte, 8)
			rand.Read(b)
			refDigest = h.Sum(b)
		}
		err = recon.WriteInt(&buf, len(refDigest))
		c.Assert(err, gc.IsNil)
		_, err = buf.Write(refDigest)
		c.Assert(err, gc.IsNil)
	}
	// Create an HTTP request
	req := &http.Request{
		Method: "POST",
		URL:    url,
		Body:   ioutil.NopCloser(bytes.NewBuffer(buf.Bytes())),
	}
	w := httptest.NewRecorder()

	return w, req
}

func getNumberOfkeys(body *bytes.Buffer) (nk int, err error) {
	buf, err := ioutil.ReadAll(body)
	if err != nil {
		return
	}
	r := bytes.NewBuffer(buf)
	nk, err = recon.ReadInt(r)
	if err != nil {
		return
	}
	return
}

func (s *HandlerSuite) TestHashQueryUnlimitedReponse(c *gc.C) {
	w, req := s.SetupHashQueryTest(c, true)
	// When NewHandler is initialized without options maxResponseLen should be 0
	c.Assert(s.handler.maxResponseLen, gc.Equals, 0)
	s.handler.HashQuery(w, req, nil)
	nk, err := getNumberOfkeys(w.Body)
	c.Assert(err, gc.IsNil)

	// The number of keys should be the same as the number of digests
	c.Assert(nk, gc.Equals, s.digests)
}

// Test HashQuery when the response maxResponseLen is set and the limit is reached
func (s *HandlerSuite) TestHashQueryResponseTooLong(c *gc.C) {
	var err error
	w, req := s.SetupHashQueryTest(c, true)

	// Test HashQuery when the response is too long
	// Reduce the response max length for testing purposes
	s.handler.maxResponseLen = 14460
	c.Assert(err, gc.IsNil)
	s.handler.HashQuery(w, req, nil)
	nk, err := getNumberOfkeys(w.Body)
	c.Assert(err, gc.IsNil)

	// The number of keys has to be less than the number of digests as the response
	// is being limited
	if nk >= s.digests {
		c.Errorf("The number of keys has to be less than the number of digests "+
			"as the response is being limited - keys: %d, digests: %d ", nk, s.digests)
	}
}

// Test HashQuery when the response maxResponseLen is set but the limit is not reached
func (s *HandlerSuite) TestHashQueryResponseUnderLimit(c *gc.C) {
	var err error
	w, req := s.SetupHashQueryTest(c, true)

	// Reduce the response max length for testing purposes
	s.handler.maxResponseLen = 72300
	c.Assert(err, gc.IsNil)
	s.handler.HashQuery(w, req, nil)
	nk, err := getNumberOfkeys(w.Body)
	c.Assert(err, gc.IsNil)

	// The number of keys should be the same as the number of digests
	c.Assert(s.storage.MethodCount("MatchMD5"), gc.Equals, s.digests)
	c.Assert(s.storage.MethodCount("FetchKeys"), gc.Equals, s.digests)
	c.Assert(nk, gc.Equals, s.digests)
}

// Test HashQuery with duplicate digests
func (s *HandlerSuite) TestHashQueryDuplicateDigests(c *gc.C) {
	var err error
	w, req := s.SetupHashQueryTest(c, false, 500)
	c.Assert(err, gc.IsNil)
	s.handler.HashQuery(w, req, nil)
	nk, err := getNumberOfkeys(w.Body)
	c.Assert(err, gc.IsNil)

	// It should return only one key as all the digests are identical
	c.Assert(s.storage.MethodCount("MatchMD5"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchKeys"), gc.Equals, 1)
	c.Assert(nk, gc.Equals, 1)
}
