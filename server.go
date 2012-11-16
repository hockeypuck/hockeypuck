/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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

package hockeypuck

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"code.google.com/p/gorilla/mux"
)

// Create a new HKP server on the given Gorilla mux router.
func NewHkpServer(r *mux.Router) *HkpServer {
	hkp := &HkpServer{
		LookupRequests: make(LookupChan, HKP_CHAN_SIZE),
		AddRequests:    make(AddChan, HKP_CHAN_SIZE)}
	r.HandleFunc("/",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.index(resp, req)
		})
	r.HandleFunc("/add",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.addForm(resp, req)
		})
	r.HandleFunc(`/css/{filename:.*\.css}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
	        path := filepath.Join(WwwRoot, "css", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
                http.NotFound(resp, req)
                return
	        }
	        http.ServeFile(resp, req, path)
		})
	r.HandleFunc(`/fonts/{filename:.*\.ttf}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
	        path := filepath.Join(WwwRoot, "fonts", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
                http.NotFound(resp, req)
                return
	        }
	        http.ServeFile(resp, req, path)
		})
	r.HandleFunc("/pks/lookup",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.lookup(resp, req)
		})
	r.HandleFunc("/pks/add",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.add(resp, req)
		})
	return hkp
}

// Handle lookup HTTP requests
func (hkp *HkpServer) lookup(respWriter http.ResponseWriter, req *http.Request) error {
	// build Lookup from query arguments
	lookup, err := parseLookup(req)
	if err != nil {
		respError(respWriter, err)
		return err
	}
	hkp.LookupRequests <- lookup
	return respondWith(respWriter, lookup)
}

// Write a server error response
func respError(respWriter http.ResponseWriter, err error) error {
	respWriter.WriteHeader(500)
	_, writeErr := respWriter.Write([]byte(err.Error()))
	return writeErr
}

// Parse the lookup request into a model.
func parseLookup(req *http.Request) (*Lookup, error) {
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return nil, err
	}
	lookup := &Lookup{responseChan: make(chan Response)}
	// Parse the "search" variable (section 3.1.1)
	if lookup.Search = req.Form.Get("search"); lookup.Search == "" {
		return nil, errors.New("Missing required parameter: search")
	}
	// Parse the "op" variable (section 3.1.2)
	switch op := req.Form.Get("op"); op {
	case "get":
		lookup.Op = Get
	case "index":
		lookup.Op = Index
	case "vindex":
		lookup.Op = Vindex
	case "":
		return nil, errors.New("Missing required parameter: op")
	default:
		return nil, errors.New(fmt.Sprintf("Unknown operation: %s", op))
	}
	// Parse the "options" variable (section 3.2.1)
	lookup.Option = parseOptions(req.Form.Get("options"))
	// Parse the "fingerprint" variable (section 3.2.2)
	lookup.Fingerprint = req.Form.Get("fingerprint") == "on"
	// Parse the "exact" variable (section 3.2.3)
	lookup.Exact = req.Form.Get("exact") == "on"
	return lookup, nil
}

// Parse the value of the "options" variable (section 3.2.1)
// into a model.
func parseOptions(options string) Option {
	var result Option
	optionValues := strings.Split(options, ",")
	for _, option := range optionValues {
		switch option {
		case "mr":
			result |= MachineReadable
		case "nm":
			result |= NotModifiable
		}
	}
	return result
}

// Handle add HTTP requests
func (hkp *HkpServer) add(respWriter http.ResponseWriter, req *http.Request) error {
	add, err := parseAdd(req)
	if err != nil {
		respError(respWriter, err)
		return err
	}
	hkp.AddRequests <- add
	return respondWith(respWriter, add)
}

// Parse the add request into a model.
func parseAdd(req *http.Request) (*Add, error) {
	// Require HTTP POST
	if req.Method != "POST" {
		return nil, errors.New(fmt.Sprintf("Invalid method for add: %s", req.Method))
	}
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return nil, err
	}
	add := &Add{responseChan: make(chan Response)}
	if keytext := req.Form.Get("keytext"); keytext == "" {
		return nil, errors.New("Missing required parameter: op")
	} else {
		add.Keytext = keytext
	}
	add.Option = parseOptions(req.Form.Get("options"))
	return add, nil
}

// Receive a response and write it to the client
func respondWith(respWriter http.ResponseWriter, r HasResponse) error {
	response := <-r.Response()
	if err := response.Error(); err != nil {
		respWriter.WriteHeader(500)
		respWriter.Write([]byte(err.Error()))
		return nil
	}
	return response.WriteTo(respWriter)
}

func (hkp *HkpServer) index(respWriter http.ResponseWriter, req *http.Request) error {
	return SearchFormTemplate.ExecuteTemplate(respWriter, "layout", nil)
}

func (hkp *HkpServer) addForm(respWriter http.ResponseWriter, req *http.Request) error {
	return AddFormTemplate.ExecuteTemplate(respWriter, "layout", nil)
}