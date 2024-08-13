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
	"net/http"
	"net/url"

	gc "gopkg.in/check.v1"
)

/*
	These server tests primarily exercise the request parsing and routing
	of requests and responses.
*/

type RequestsSuite struct{}

var _ = gc.Suite(&RequestsSuite{})

func (s *RequestsSuite) TestGetKeyword(c *gc.C) {
	// basic search
	testUrl, err := url.Parse("/pks/lookup?op=get&search=alice")
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err := ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Op, gc.Equals, OperationGet)
	c.Assert(lookup.Search, gc.Equals, "alice")
	c.Assert(lookup.Options, gc.HasLen, 0)
	c.Assert(lookup.Fingerprint, gc.Equals, false)
	c.Assert(lookup.Exact, gc.Equals, false)
}

func (s *RequestsSuite) TestGetFp(c *gc.C) {
	// fp search
	testUrl, err := url.Parse("/pks/lookup?op=get&search=0xdecafbad&options=mr,nm&fingerprint=on&exact=on")
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err := ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Op, gc.Equals, OperationGet)
	c.Assert(lookup.Search, gc.Equals, "0xdecafbad")
	c.Assert(lookup.Options[OptionMachineReadable], gc.Equals, true)
	c.Assert(lookup.Options[OptionNotModifiable], gc.Equals, true)
	c.Assert(lookup.Fingerprint, gc.Equals, true)
	c.Assert(lookup.Exact, gc.Equals, true)
}

func (s *RequestsSuite) TestIndex(c *gc.C) {
	// op=index
	testUrl, err := url.Parse("/pks/lookup?op=index&search=sharin") // as in, foo
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err := ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Op, gc.Equals, OperationIndex)
}

func (s *RequestsSuite) TestIndexBareFp(c *gc.C) {
	// bare v4-fp search (without 0x) - 40 nybbles; should get modified
	testUrl, err := url.Parse("/pks/lookup?op=index&search=decafbaddecafbaddecafbaddecafbaddecafbad")
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err := ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Search, gc.Equals, "0xdecafbaddecafbaddecafbaddecafbaddecafbad")
	// bare v4-fp search (without 0x) - 40 whitespaced nybbles with trailing space; should get modified
	testUrl, err = url.Parse("/pks/lookup?op=index&search=deca fbad deca fbad deca  fbad deca fbad deca fbad  ")
	c.Assert(err, gc.IsNil)
	req = &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err = ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Search, gc.Equals, "0xdecafbaddecafbaddecafbaddecafbaddecafbad")
	// bare v3-fp search (without 0x) - 32 nybbles; should get modified
	testUrl, err = url.Parse("/pks/lookup?op=index&search=decafbaddecafbaddecafbaddecafbad")
	c.Assert(err, gc.IsNil)
	req = &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err = ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Search, gc.Equals, "0xdecafbaddecafbaddecafbaddecafbad")
	// bare long-id search (without 0x) - 16 nybbles; should get modified
	testUrl, err = url.Parse("/pks/lookup?op=index&search=decafbaddecafbad")
	c.Assert(err, gc.IsNil)
	req = &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err = ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert("0xdecafbaddecafbad", gc.Equals, lookup.Search)
	// bare short-id search (without 0x) - 8 nybbles; should NOT get modified
	testUrl, err = url.Parse("/pks/lookup?op=index&search=decafbad")
	c.Assert(err, gc.IsNil)
	req = &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err = ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Search, gc.Equals, "decafbad")
}

func (s *RequestsSuite) TestVindex(c *gc.C) {
	// op=vindex
	testUrl, err := url.Parse("/pks/lookup?op=vindex&search=bob") // as in, foo
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	lookup, err := ParseLookup(req)
	c.Assert(err, gc.IsNil)
	c.Assert(lookup.Op, gc.Equals, OperationVIndex)
}

func (s *RequestsSuite) TestMissingSearch(c *gc.C) {
	// create an op=get lookup without the required search term
	testUrl, err := url.Parse("/pks/lookup?op=get")
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	_, err = ParseLookup(req)
	// error without search term
	c.Assert(err, gc.NotNil)
}

func (s *RequestsSuite) TestNoSuchOp(c *gc.C) {
	// hockeypuck does not know how to do a barrel roll
	testUrl, err := url.Parse("/pks/lookup?op=barrelroll")
	c.Assert(err, gc.IsNil)
	req := &http.Request{
		Method: "GET",
		URL:    testUrl}
	_, err = ParseLookup(req)
	// Unknown operation
	c.Assert(err, gc.NotNil)
}

func (s *RequestsSuite) TestAdd(c *gc.C) {
	// adding a key
	testUrl, err := url.Parse("/pks/add")
	c.Assert(err, gc.IsNil)
	postData := make(map[string][]string)
	postData["keytext"] = []string{"sus llaves aqui"}
	req, err := http.NewRequest("POST", testUrl.String(), bytes.NewBuffer(nil))
	req.PostForm = url.Values(postData)
	add, err := ParseAdd(req)
	c.Assert(err, gc.IsNil)
	c.Assert(add.Keytext, gc.Equals, "sus llaves aqui")
	c.Assert(add.Options, gc.HasLen, 0)
}

func (s *RequestsSuite) TestAddOptions(c *gc.C) {
	// adding a key with options
	testUrl, err := url.Parse("/pks/add?options=mr")
	c.Assert(err, gc.IsNil)
	postData := make(map[string][]string)
	postData["keytext"] = []string{"sus llaves estan aqui"}
	postData["options"] = []string{"mr"}
	req, err := http.NewRequest("POST", testUrl.String(), bytes.NewBuffer(nil))
	req.PostForm = url.Values(postData)
	add, err := ParseAdd(req)
	c.Assert(err, gc.IsNil)
	c.Assert(add.Keytext, gc.Equals, "sus llaves estan aqui")
	c.Assert(add.Options[OptionMachineReadable], gc.Equals, true)
	c.Assert(add.Options[OptionNotModifiable], gc.Equals, false)
}

func (s *RequestsSuite) TestAddMissingKey(c *gc.C) {
	// here's my key. wait, i forgot it.
	testUrl, err := url.Parse("/pks/add")
	c.Assert(err, gc.IsNil)
	postData := make(map[string][]string)
	req := &http.Request{
		Method: "POST",
		URL:    testUrl,
		Form:   url.Values(postData)}
	_, err = ParseAdd(req)
	// error without keytext
	c.Assert(err, gc.NotNil)
}
