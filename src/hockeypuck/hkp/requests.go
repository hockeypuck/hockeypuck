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
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"hockeypuck/conflux/recon"
)

// Operation enumerates the supported HKP operations (op parameter) in the request.
type Operation string

const (
	OperationGet    = Operation("get")
	OperationIndex  = Operation("index")
	OperationVIndex = Operation("vindex")
	OperationStats  = Operation("stats")
	OperationHGet   = Operation("hget")
)

func ParseOperation(s string) (Operation, bool) {
	op := Operation(s)
	switch op {
	case OperationGet, OperationIndex, OperationVIndex,
		OperationStats, OperationHGet:
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
		if l.Op == OperationIndex {
			// If it looks like a fingerprint or long-ID, normalise to "0x" format
			fingerprintRegex := regexp.MustCompile(`^(([a-fA-F0-9]{4}\s?\s?){4}|([a-fA-F0-9]{4}\s?\s?){8}|([a-fA-F0-9]{4}\s?\s?){10}|([a-fA-F0-9]{4}\s?\s?){16})\s*$`)
			tempString := fingerprintRegex.ReplaceAllString(l.Search, "0x$1")
			if tempString != l.Search {
				l.Search = strings.ReplaceAll(tempString, " ", "")
			}
		}
	}

	l.Options = ParseOptionSet(req.Form.Get("options"))

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
	if !strings.HasPrefix(replace.Keytext, "/pks/replace\n") && !strings.HasPrefix(replace.Keytext, "/pks/replace\r") {
		return nil, errors.Errorf("first line of keytext must be '/pks/replace'")
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
		return nil, errors.Errorf("missing required parameter: keysig")
	}
	if !strings.HasPrefix(del.Keytext, "/pks/delete\n") && !strings.HasPrefix(del.Keytext, "/pks/delete\r") {
		return nil, errors.Errorf("first line of keytext must be '/pks/delete'")
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
	buf, err := io.ReadAll(req.Body)
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
	seen := make(map[string]struct{})
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
		if _, exists := seen[hex.EncodeToString(hash)]; !exists {
			hq.Digests = append(hq.Digests, hex.EncodeToString(hash))
			seen[hex.EncodeToString(hash)] = struct{}{}
		}
	}

	return &hq, nil
}
