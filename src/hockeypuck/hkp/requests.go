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
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"hockeypuck/conflux/recon"
)

// Operation enumerates the supported HKP operations (op parameter) in the request.
type Operation string

const (
	OperationIndex  = Operation("index")
	OperationVIndex = Operation("vindex")
	// Mark as "Other Operation": OpenPGP HTTP Keyserver Protocol (HKP), 3.1.2.4
	OperationMRIndex = Operation("x-mrindex")
	OperationGet     = Operation("get")
	OperationHGet    = Operation("hget")
	OperationStats   = Operation("stats")
)

func ParseOperation(s string) (Operation, bool) {
	op := Operation(s)
	switch op {
	case OperationIndex, OperationVIndex, OperationMRIndex,
		OperationGet, OperationHGet, OperationStats:
		return op, true
	}
	return Operation(""), false
}

// Option defines modifiers available to some HKP requests.
type Option string

const (
	OptionMachineReadable = Option("mr")
	OptionJSON            = Option("json")
	OptionNotModifiable   = Option("nm")
)

type OptionSet map[Option]bool

func ParseOptionSet(s string) OptionSet {
	result := OptionSet{}
	fields := strings.Split(s, ",")
	for _, field := range fields {
		if field != "" {
			result[Option(field)] = true
		}
	}
	return result
}

// Lookup contains all the parameters and options for a /pks/lookup request.
type Lookup struct {
	Op          Operation
	Search      string
	Options     OptionSet
	Fingerprint bool
	Exact       bool
	Hash        bool
}

func ParseLookup(req *http.Request) (*Lookup, error) {
	err := req.ParseForm()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var l Lookup
	var ok bool
	// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.1.2
	l.Op, ok = ParseOperation(req.Form.Get("op"))
	if !ok {
		return nil, errors.Errorf("invalid operation %q", req.Form.Get("op"))
	}

	if l.Op != OperationStats {
		// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.1.1
		l.Search = req.Form.Get("search")
		if l.Search == "" {
			return nil, errors.Errorf("missing required parameter: search")
		}
	}

	l.Options = ParseOptionSet(req.Form.Get("options"))
	mrOptions, found := l.Options[OptionMachineReadable]
	if (found && mrOptions) || (l.Op == OperationMRIndex) { l.Options[OptionMachineReadable] = true }

	// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.2.2
	l.Fingerprint = req.Form.Get("fingerprint") == "on"

	// Not in draft spec, SKS convention
	l.Hash = req.Form.Get("hash") == "on"

	// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.2.3
	l.Exact = req.Form.Get("exact") == "on"

	return &l, nil
}

// Add represents a valid /pks/add request content, parameters and options.
type Add struct {
	Keytext string
	Keysig  string
	Replace bool
	Options OptionSet
}

func ParseAdd(req *http.Request) (*Add, error) {
	if req.Method != "POST" {
		return nil, errors.Errorf("invalid HTTP method: %s", req.Method)
	}

	var add Add
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	add.Keytext = req.Form.Get("keytext")
	if add.Keytext == "" {
		return nil, errors.Errorf("missing required parameter: keytext")
	}
	add.Keysig = req.Form.Get("keysig")
	add.Replace, _ = strconv.ParseBool(req.Form.Get("replace"))

	add.Options = ParseOptionSet(req.Form.Get("options"))

	return &add, nil
}

// Replace represents a valid /pks/replace request content, parameters and options.
type Replace struct {
	Keytext string
	Keysig  string
}

func ParseReplace(req *http.Request) (*Replace, error) {
	if req.Method != "POST" {
		return nil, errors.Errorf("invalid HTTP method: %s", req.Method)
	}

	var replace Replace
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	replace.Keytext = req.Form.Get("keytext")
	if replace.Keytext == "" {
		return nil, errors.Errorf("missing required parameter: keytext")
	}
	replace.Keysig = req.Form.Get("keysig")
	if replace.Keysig == "" {
		return nil, errors.Errorf("missing required parameter: keysig")
	}

	return &replace, nil
}

// Delete represents a valid /pks/delete request content, parameters and options.
type Delete struct {
	Keytext string
	Keysig  string
}

func ParseDelete(req *http.Request) (*Delete, error) {
	if req.Method != "POST" {
		return nil, errors.Errorf("invalid HTTP method: %s", req.Method)
	}

	var del Delete
	err := req.ParseForm()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	del.Keytext = req.Form.Get("keytext")
	if del.Keytext == "" {
		return nil, errors.Errorf("missing required parameter: keytext")
	}
	del.Keysig = req.Form.Get("keysig")
	if del.Keysig == "" {
		return nil, errors.Errorf("missing required parameter: keytext")
	}

	return &del, nil
}

type HashQuery struct {
	Digests []string
}

func ParseHashQuery(req *http.Request) (*HashQuery, error) {
	if req.Method != "POST" {
		return nil, errors.Errorf("invalid HTTP method: %s", req.Method)
	}

	defer req.Body.Close()
	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	r := bytes.NewBuffer(buf)

	var hq HashQuery

	// Parse hashquery POST data
	n, err := recon.ReadInt(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	hq.Digests = make([]string, n)
	for i := 0; i < n; i++ {
		hashlen, err := recon.ReadInt(r)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		hash := make([]byte, hashlen)
		_, err = r.Read(hash)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		hq.Digests[i] = hex.EncodeToString(hash)
	}

	return &hq, nil
}
