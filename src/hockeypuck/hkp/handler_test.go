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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	stdtesting "testing"
	"time"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/testing"

	"hockeypuck/hkp/storage/mock"
)

type testKey struct {
	fp   string
	kv   string
	kid  string
	id   string
	file string
}

var (
	testKeyDefault = &testKey{
		fp:   "10fe8cf1b483f7525039aa2a361bc1f023e0dcca",
		kv:   "04",
		kid:  "361bc1f023e0dcca",
		id:   "alice@example.com",
		file: "alice_signed.asc",
	}
	testKeyBadSigs = &testKey{
		fp:   "a7400f5a48fb42b8cee8638b5759f35001aa4a64",
		kv:   "04",
		kid:  "5759f35001aa4a64",
		id:   "<unknown>",
		file: "a7400f5a_badsigs.asc",
	}
	testKeyGentoo = &testKey{
		fp:   "abd00913019d6354ba1d9a132839fe0d796198b1",
		kv:   "04",
		kid:  "2839fe0d796198b1",
		id:   "openpgp-auth+l1@gentoo.org",
		file: "gentoo-l1.asc",
	}
	testKeyRevoked = &testKey{
		fp:   "2d4b859915bf2213880748ae7c330458a06e162f",
		kv:   "04",
		kid:  "7c330458a06e162f",
		id:   "test@example.org",
		file: "test-key-revoked.asc",
	}
	testKeyUidRevoked = &testKey{
		fp:   "9a86c636b3f0f94ec6b42e6bebed28c0696c022c",
		kv:   "04",
		kid:  "ebed28c0696c022c",
		id:   "revokeduid@example.com",
		file: "test-key-uid-revoked.asc",
	}
	testKeySksDigest = &testKey{
		fp:   "646ad4c90a2d13f62d9d1bf4cc5112bdce353cf4",
		kv:   "04",
		kid:  "cc5112bdce353cf4",
		id:   "jennyo@transient.net",
		file: "sksdigest.asc",
	}

	testKeys = map[string]*testKey{
		testKeyDefault.fp:    testKeyDefault,
		testKeyBadSigs.fp:    testKeyBadSigs,
		testKeyGentoo.fp:     testKeyGentoo,
		testKeyRevoked.fp:    testKeyRevoked,
		testKeyUidRevoked.fp: testKeyUidRevoked,
		testKeySksDigest.fp:  testKeySksDigest,
	}
	testKeysById = map[string]*testKey{
		testKeyDefault.id:    testKeyDefault,
		testKeyBadSigs.id:    testKeyBadSigs,
		testKeyGentoo.id:     testKeyGentoo,
		testKeyRevoked.id:    testKeyRevoked,
		testKeyUidRevoked.id: testKeyUidRevoked,
		testKeySksDigest.id:  testKeySksDigest,
	}
)

// Takes a slice of n key identifiers, and returns a slice of n copies of testKeyDefault
// regardless of the actual identifiers.
func sliceOfDefaultKeys(keys []string, options ...string) ([]*storage.Record, error) {
	tk := testKeyDefault
	if len(keys) != 0 && testKeys[keys[0]] != nil {
		tk = testKeys[keys[0]]
	}
	pks := openpgp.MustReadArmorKeys(testing.MustInput(tk.file))
	records := make([]*storage.Record, len(keys))
	now := time.Now()
	for i := range keys {
		records[i] = &storage.Record{PrimaryKey: pks[0], Fingerprint: pks[0].Fingerprint, MD5: pks[0].MD5, CTime: now, MTime: now}
	}
	return records, nil
}

func Test(t *stdtesting.T) { gc.TestingT(t) }

type HandlerSuite struct {
	storage *mock.Storage
	srv     *httptest.Server
	handler *Handler
	digests int
}

var _ = gc.Suite(&HandlerSuite{})

// BEWARE that we have not supplied a mock.Update function, so this suite will only perform dry-run tests against Alice.
func (s *HandlerSuite) SetUpTest(c *gc.C) {
	s.storage = mock.NewStorage(
		mock.ResolveToFp(func(keys []string) ([]string, error) {
			tk := testKeyDefault
			if len(keys) == 1 && testKeys[keys[0]] != nil {
				tk = testKeys[keys[0]]
			}
			return []string{tk.fp}, nil
		}),
		mock.FetchRecordsByFp(sliceOfDefaultKeys),
		mock.FetchRecordsByVfp(sliceOfDefaultKeys),
		mock.FetchRecordsByIdentity(func(ids []string, options ...string) ([]*storage.Record, error) {
			tk := testKeyDefault
			records := make([]*storage.Record, len(ids))
			for i, id := range ids {
				if testKeysById[id] != nil {
					tk = testKeysById[id]
				}
				pks := openpgp.MustReadArmorKeys(testing.MustInput(tk.file))
				now := time.Now()
				records[i] = &storage.Record{PrimaryKey: pks[0], Fingerprint: pks[0].Fingerprint, MD5: pks[0].MD5, CTime: now, MTime: now}
			}
			return records, nil
		}),
		mock.FetchRecordsByMD5(sliceOfDefaultKeys),
		mock.FetchRecordsByKeyword(func(key string, options ...string) ([]*storage.Record, error) {
			tk := testKeyDefault
			if testKeys[key] != nil {
				tk = testKeys[key]
			}
			pks := openpgp.MustReadArmorKeys(testing.MustInput(tk.file))
			records := make([]*storage.Record, 1)
			now := time.Now()
			records[0] = &storage.Record{PrimaryKey: pks[0], Fingerprint: pks[0].Fingerprint, MD5: pks[0].MD5, CTime: now, MTime: now}
			return records, nil
		}),
	)

	r := httprouter.New()
	policy, err := openpgp.NewPolicy()
	c.Assert(err, gc.IsNil)
	handler, err := NewHandler(s.storage, policy, StatsFunc(s.StatsTest))
	c.Assert(err, gc.IsNil)
	s.handler = handler
	s.handler.Register(r)
	s.srv = httptest.NewServer(r)
	s.digests = 50
}

func (s *HandlerSuite) TearDownTest(c *gc.C) {
	s.srv.Close()
}

func (s *HandlerSuite) TestGetKeyIDHkp2(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(s.srv.URL + "/pks/v2/certs/by-keyid/" + tk.kid)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, tk.kid)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "alice <alice@example.com>")

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 0)
}

func (s *HandlerSuite) TestGetVFingerprintHkp2(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(s.srv.URL + "/pks/v2/certs/by-vfingerprint/" + tk.kv + tk.fp)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, tk.kid)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "alice <alice@example.com>")

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 0)
}

func (s *HandlerSuite) TestGetIdentityHkp2(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(s.srv.URL + "/pks/v2/certs/by-identity/" + tk.id)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, tk.kid)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "alice <alice@example.com>")

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 1)
}

func (s *HandlerSuite) TestGetKeyID(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x" + tk.kid)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, tk.kid)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "alice <alice@example.com>")

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 0)
}

func (s *HandlerSuite) TestGetKeyword(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=alice")
	c.Assert(err, gc.IsNil)
	defer res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 0)
}

func (s *HandlerSuite) TestGetMD5(c *gc.C) {
	// fake MD5, this is a mock
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=f49fba8f60c4957725dd97faa4b94647")
	c.Assert(err, gc.IsNil)
	defer res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 1)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 0)
}

func (s *HandlerSuite) TestIndexAlice(c *gc.C) {
	tk := testKeyDefault

	for _, op := range []string{"index", "vindex"} {
		res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=%s&search=0x"+tk.kid, s.srv.URL, op))
		c.Assert(err, gc.IsNil)
		doc, err := io.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

		var result []map[string]interface{}
		err = json.Unmarshal(doc, &result)
		c.Assert(err, gc.IsNil)

		c.Assert(result, gc.HasLen, 1)
		algorithm := result[0]["algorithm"]
		switch a := algorithm.(type) {
		case map[string]interface{}:
			c.Assert(fmt.Sprintf("%v", a["bitLength"]), gc.Equals, "2048")
		default:
			c.Logf("algorithm of unexpected type: %#v", a)
			c.Fail()
		}
	}

	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByKeyword"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("ResolveToFp"), gc.Equals, 2)
	c.Assert(s.storage.MethodCount("FetchRecordsByFp"), gc.Equals, 2)
	c.Assert(s.storage.MethodCount("FetchRecordsByVfp"), gc.Equals, 0)
	c.Assert(s.storage.MethodCount("FetchRecordsByIdentity"), gc.Equals, 0)
}

func (s *HandlerSuite) TestIndexAliceMR(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=0x"+tk.kid, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `info:1:1
pub:10FE8CF1B483F7525039AA2A361BC1F023E0DCCA:1:2048:1345589945::
uid:alice <alice@example.com>:1345589945::
`)
}

func (s *HandlerSuite) TestIndexAlicev2(c *gc.C) {
	tk := testKeyDefault

	res, err := http.Get(fmt.Sprintf("%s/pks/v2/index/"+tk.id, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `[
	{
		"packet": {
			"tag": 6
		},
		"fingerprint": "10fe8cf1b483f7525039aa2a361bc1f023e0dcca",
		"longKeyID": "361bc1f023e0dcca",
		"creation": "2012-08-21T22:59:05Z",
		"neverExpires": true,
		"version": 4,
		"algorithm": {
			"name": "rsa2048",
			"code": 1,
			"bitLength": 2048
		},
		"bitLength": 2048,
		"md5": "4b579f34dfc533283d425cf9e103f03f",
		"length": 1446,
		"subKeys": [
			{
				"packet": {
					"tag": 14
				},
				"fingerprint": "6da00a53ea7343cd17483eaa6a5b700bf3d13863",
				"longKeyID": "6a5b700bf3d13863",
				"creation": "2012-08-21T22:59:05Z",
				"neverExpires": true,
				"version": 4,
				"algorithm": {
					"name": "rsa2048",
					"code": 1,
					"bitLength": 2048
				},
				"bitLength": 2048,
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 24,
						"issuerKeyID": "361bc1f023e0dcca",
						"creation": "2012-08-21T22:59:05Z",
						"neverExpires": true
					}
				]
			}
		],
		"userIDs": [
			{
				"packet": {
					"tag": 13
				},
				"keywords": "alice \u003calice@example.com\u003e",
				"validsince": "2012-08-21T22:59:05Z",
				"neverExpires": true,
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "361bc1f023e0dcca",
						"creation": "2012-08-21T22:59:05Z",
						"neverExpires": true
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 16,
						"issuerKeyID": "62aea01d67640fb5",
						"creation": "2012-08-22T01:10:11Z",
						"neverExpires": true
					}
				]
			}
		]
	}
]`)
}

func (s *HandlerSuite) TestIndexKeyExpiryMR(c *gc.C) {
	tk := testKeyGentoo

	res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=0x"+tk.fp, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `info:1:1
pub:ABD00913019D6354BA1D9A132839FE0D796198B1:1:2048:1554117635:1782907200:
uid:Gentoo Authority Key L1 <openpgp-auth+l1@gentoo.org>:1554117635:1782907200:
`)
}

func (s *HandlerSuite) TestIndexKeyExpiryv2(c *gc.C) {
	tk := testKeyGentoo

	res, err := http.Get(fmt.Sprintf("%s/pks/v2/index/"+tk.id, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `[
	{
		"packet": {
			"tag": 6
		},
		"fingerprint": "abd00913019d6354ba1d9a132839fe0d796198b1",
		"longKeyID": "2839fe0d796198b1",
		"creation": "2019-04-01T11:20:35Z",
		"expiration": "2026-07-01T12:00:00Z",
		"version": 4,
		"algorithm": {
			"name": "rsa2048",
			"code": 1,
			"bitLength": 2048
		},
		"bitLength": 2048,
		"md5": "21eb8f7fdf500338aef41ed6f722a3ad",
		"length": 5466,
		"userIDs": [
			{
				"packet": {
					"tag": 13
				},
				"keywords": "Gentoo Authority Key L1 \u003copenpgp-auth+l1@gentoo.org\u003e",
				"validsince": "2019-04-01T11:20:35Z",
				"expiration": "2026-07-01T12:00:00Z",
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2024-04-21T05:55:16Z",
						"expiration": "2026-07-01T12:00:00Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2022-06-16T19:54:45Z",
						"expiration": "2024-07-01T12:00:02Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2021-11-29T14:43:32Z",
						"expiration": "2023-07-01T12:00:01Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2020-09-20T20:32:43Z",
						"expiration": "2022-07-01T12:00:00Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2020-04-24T08:57:34Z",
						"expiration": "2022-01-01T12:00:00Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2019-10-30T12:13:01Z",
						"expiration": "2021-01-01T12:00:00Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2019-04-27T14:49:54Z",
						"expiration": "2020-07-01T10:00:01Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "2839fe0d796198b1",
						"creation": "2019-04-01T11:20:35Z",
						"expiration": "2020-01-01T11:00:43Z"
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 16,
						"issuerKeyID": "08c170de55ec123a",
						"creation": "2019-04-13T23:22:07Z",
						"neverExpires": true
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 16,
						"issuerKeyID": "100565ab52446cb4",
						"creation": "2019-04-13T23:27:36Z",
						"neverExpires": true
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "df84256885283521",
						"creation": "2019-04-27T14:47:19Z",
						"neverExpires": true
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 18,
						"issuerKeyID": "a3c12d350d05ee04",
						"creation": "2019-05-04T03:56:16Z",
						"neverExpires": true
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 16,
						"issuerKeyID": "1f3d03348db1a3e2",
						"creation": "2022-01-13T04:53:15Z",
						"neverExpires": true
					}
				]
			}
		]
	}
]`)
}

func (s *HandlerSuite) TestIndexKeyRevocationMR(c *gc.C) {
	tk := testKeyRevoked

	res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=0x"+tk.fp, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `info:1:1
pub:2D4B859915BF2213880748AE7C330458A06E162F:1:3072:1611408173::r
`)
}

func (s *HandlerSuite) TestIndexKeyRevocationv2(c *gc.C) {
	tk := testKeyRevoked

	res, err := http.Get(fmt.Sprintf("%s/pks/v2/index/"+tk.id, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `[
	{
		"packet": {
			"tag": 6
		},
		"fingerprint": "2d4b859915bf2213880748ae7c330458a06e162f",
		"longKeyID": "7c330458a06e162f",
		"creation": "2021-01-23T13:22:53Z",
		"neverExpires": true,
		"version": 4,
		"algorithm": {
			"name": "rsa3072",
			"code": 1,
			"bitLength": 3072
		},
		"bitLength": 3072,
		"signatures": [
			{
				"packet": {
					"tag": 2
				},
				"sigType": 32,
				"revocation": true,
				"issuerKeyID": "7c330458a06e162f",
				"creation": "2021-01-23T13:23:06Z",
				"neverExpires": true
			}
		],
		"md5": "d4bd66d47e1efccd7001f9d1f96e5eb6",
		"length": 1670,
		"subKeys": [
			{
				"packet": {
					"tag": 14
				},
				"fingerprint": "65c9945b1f478a74386d01ea99e72dbb7a5f7024",
				"longKeyID": "99e72dbb7a5f7024",
				"creation": "2021-01-23T13:22:53Z",
				"neverExpires": true,
				"version": 4,
				"algorithm": {
					"name": "rsa3072",
					"code": 1,
					"bitLength": 3072
				},
				"bitLength": 3072,
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 24,
						"issuerKeyID": "7c330458a06e162f",
						"creation": "2021-01-23T13:22:53Z",
						"neverExpires": true
					}
				]
			}
		]
	}
]`)
}

func (s *HandlerSuite) TestIndexUidRevocationMR(c *gc.C) {
	tk := testKeyUidRevoked

	res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=0x"+tk.fp, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `info:1:1
pub:9A86C636B3F0F94EC6B42E6BEBED28C0696C022C:22:263:1723578245:1818186245:
uid:revokeduid@example.com:1723578310:1818186245:r
uid:uid@example.com:1723578382:1818186245:
`)
}

func (s *HandlerSuite) TestIndexUidRevocationv2(c *gc.C) {
	tk := testKeyUidRevoked

	res, err := http.Get(fmt.Sprintf("%s/pks/v2/index/"+tk.id, s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	c.Assert(string(doc), gc.Equals, `[
	{
		"packet": {
			"tag": 6
		},
		"fingerprint": "9a86c636b3f0f94ec6b42e6bebed28c0696c022c",
		"longKeyID": "ebed28c0696c022c",
		"creation": "2024-08-13T19:44:05Z",
		"expiration": "2027-08-13T19:44:05Z",
		"version": 4,
		"algorithm": {
			"name": "eddsa_Curve25519",
			"code": 22,
			"bitLength": 263,
			"curve": "Curve25519"
		},
		"bitLength": 263,
		"md5": "288866326a1210d18f872cd680bb7fe2",
		"length": 687,
		"subKeys": [
			{
				"packet": {
					"tag": 14
				},
				"fingerprint": "90f8320aeaac7186ad4237dd58c51a0da2aac11c",
				"longKeyID": "58c51a0da2aac11c",
				"creation": "2024-08-13T19:44:05Z",
				"neverExpires": true,
				"version": 4,
				"algorithm": {
					"name": "ecdh_Curve25519",
					"code": 18,
					"bitLength": 263,
					"curve": "Curve25519"
				},
				"bitLength": 263,
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 24,
						"issuerKeyID": "ebed28c0696c022c",
						"creation": "2024-08-13T19:44:05Z",
						"neverExpires": true
					}
				]
			}
		],
		"userIDs": [
			{
				"packet": {
					"tag": 13
				},
				"keywords": "revokeduid@example.com",
				"validsince": "2024-08-13T19:45:10Z",
				"expiration": "2027-08-13T19:44:05Z",
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 48,
						"revocation": true,
						"issuerKeyID": "ebed28c0696c022c",
						"creation": "2024-08-13T19:45:57Z",
						"neverExpires": true
					},
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"issuerKeyID": "ebed28c0696c022c",
						"creation": "2024-08-13T19:45:10Z",
						"expiration": "2027-08-13T19:44:05Z"
					}
				]
			},
			{
				"packet": {
					"tag": 13
				},
				"keywords": "uid@example.com",
				"validsince": "2024-08-13T19:46:22Z",
				"expiration": "2027-08-13T19:44:05Z",
				"signatures": [
					{
						"packet": {
							"tag": 2
						},
						"sigType": 19,
						"primary": true,
						"issuerKeyID": "ebed28c0696c022c",
						"creation": "2024-08-13T19:46:22Z",
						"expiration": "2027-08-13T19:44:05Z"
					}
				]
			}
		]
	}
]`)
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
	keytext, err := io.ReadAll(testing.MustInput("alice_unsigned.asc"))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	doc, err := io.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)

	var addRes SubmissionResponse
	err = json.Unmarshal(doc, &addRes)
	c.Assert(err, gc.IsNil)
	c.Assert(addRes.Ignored, gc.HasLen, 1)
}

func (s *HandlerSuite) TestPostCertsv2(c *gc.C) {
	armor, err := io.ReadAll(testing.MustInput("alice_unsigned.asc"))
	c.Assert(err, gc.IsNil)
	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	buf := &bytes.Buffer{}
	err = openpgp.WritePackets(buf, keys[0])
	c.Assert(err, gc.IsNil)
	// TODO: use proper content type
	res, err := http.Post(s.srv.URL+"/pks/v2/certs", "application/pgp-keys;armor=no", buf)
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	doc, err := io.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)

	var addRes SubmissionResponse
	err = json.Unmarshal(doc, &addRes)
	c.Assert(err, gc.IsNil)
	c.Assert(addRes.Ignored, gc.HasLen, 1)
}

// PUT canonical not implemented yet
//
// func (s *HandlerSuite) TestPutCanonicalv2(c *gc.C) {
// 	armor, err := io.ReadAll(testing.MustInput("alice_unsigned.asc"))
// 	c.Assert(err, gc.IsNil)
// 	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
// 	url, err := url.Parse(s.srv.URL + "/pks/v2/canonical/alice@example.com")
// 	c.Assert(err, gc.IsNil)
// 	buf := &bytes.Buffer{}
// 	err = openpgp.WritePackets(buf, keys[0])
// 	c.Assert(err, gc.IsNil)
// 	req := &http.Request{
// 		Method: http.MethodPut,
// 		URL:    url,
// 		Header: http.Header{
// 			// TODO: use proper content type
// 			"Content-type": []string{"application/raw-pgp-keys"},
// 		},
// 		Body: io.NopCloser(buf),
// 	}
// 	httpClient := http.Client{}
// 	res, err := httpClient.Do(req)
// 	c.Assert(err, gc.IsNil)
// 	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
// 	defer res.Body.Close()
// 	doc, err := io.ReadAll(res.Body)
// 	c.Assert(err, gc.IsNil)

// 	var addRes SubmissionResponse
// 	err = json.Unmarshal(doc, &addRes)
// 	c.Assert(err, gc.IsNil)
// 	c.Assert(addRes.Ignored, gc.HasLen, 1)
// }

func (s *HandlerSuite) TestFetchWithBadSigs(c *gc.C) {
	tk := testKeyBadSigs

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x" + tk.fp)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, tk.kid)
}

func (s *HandlerSuite) TestFetchWithTrustPackets(c *gc.C) {
	tk := testKeySksDigest

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x" + tk.fp)
	c.Assert(err, gc.IsNil)
	armor, err := io.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor))
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].KeyID, gc.Equals, tk.kid)
	c.Assert(keys[0].Trusts, gc.IsNil)
	c.Assert(keys[0].Signatures, gc.HasLen, 0)
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Trusts, gc.IsNil)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Signatures[0].Trusts, gc.IsNil)
	c.Assert(keys[0].SubKeys, gc.HasLen, 1)
	c.Assert(keys[0].SubKeys[0].Trusts, gc.IsNil)
	c.Assert(keys[0].SubKeys[0].Signatures, gc.HasLen, 1)
	c.Assert(keys[0].SubKeys[0].Signatures[0].Trusts, gc.IsNil)
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
		Body:   io.NopCloser(bytes.NewBuffer(buf.Bytes())),
	}
	w := httptest.NewRecorder()

	return w, req
}

func getNumberOfkeys(body *bytes.Buffer) (nk int, err error) {
	buf, err := io.ReadAll(body)
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
	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 1)
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
	c.Assert(s.storage.MethodCount("FetchRecordsByMD5"), gc.Equals, 1)
	c.Assert(nk, gc.Equals, 1)
}

func (s *HandlerSuite) SetupHealthTest(c *gc.C) (*httptest.ResponseRecorder, *http.Request) {
	url, err := url.Parse("/pks/health")
	c.Assert(err, gc.IsNil)
	// Create an HTTP request
	req := &http.Request{
		Method: "GET",
		URL:    url,
	}
	w := httptest.NewRecorder()

	return w, req
}

// Test Health endpoint
func (s *HandlerSuite) TestHealth(c *gc.C) {
	w, req := s.SetupHealthTest(c)
	s.handler.Health(w, req, nil)
	code := w.Result().StatusCode
	c.Assert(code, gc.Equals, 200)
}

// Function to return an empty stats page for testing
// TODO: make this a proper stats page
func (s *HandlerSuite) StatsTest(r *http.Request) (interface{}, error) {
	return "", nil
}

func (s *HandlerSuite) SetupStatsTest(c *gc.C) (*httptest.ResponseRecorder, *http.Request) {
	url, err := url.Parse("/pks/stats")
	c.Assert(err, gc.IsNil)
	// Create an HTTP request
	req := &http.Request{
		Method: "GET",
		URL:    url,
	}
	w := httptest.NewRecorder()

	return w, req
}

// Test Stats endpoint
func (s *HandlerSuite) TestStats(c *gc.C) {
	w, req := s.SetupStatsTest(c)
	s.handler.Stats(w, req, nil)
	code := w.Result().StatusCode
	c.Assert(code, gc.Equals, 200)
}
