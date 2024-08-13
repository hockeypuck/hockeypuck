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
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"hockeypuck/hkp/jsonhkp"
	"hockeypuck/openpgp"
)

type IndexFormat interface {
	Write(w http.ResponseWriter, l *Lookup, keys []*openpgp.PrimaryKey) error
}

type JSONFormat struct{}

var jsonFormat = &JSONFormat{}

func (*JSONFormat) Write(w http.ResponseWriter, _ *Lookup, keys []*openpgp.PrimaryKey) error {
	w.Header().Set("Content-Type", "application/json")
	wireKeys := jsonhkp.NewPrimaryKeys(keys)
	out, err := json.MarshalIndent(wireKeys, "", "\t")
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = w.Write(out)
	return errors.WithStack(err)
}

type MRFormat struct{}

var mrFormat = &MRFormat{}

func (*MRFormat) Write(w http.ResponseWriter, l *Lookup, keys []*openpgp.PrimaryKey) error {
	w.Header().Set("Content-Type", "text/plain")

	fmt.Fprintf(w, "info:1:%d\n", len(keys))
	for _, key := range keys {
		selfsigs, _ := key.SigInfo()

		var keyID string
		if l.Fingerprint {
			keyID = key.Fingerprint()
		} else {
			keyID = key.KeyID()
		}
		keyID = strings.ToUpper(keyID)

		expiresAt, _ := selfsigs.ExpiresAt()
		_, isRevoked := selfsigs.RevokedSince()
		revocationFlag := ""
		if isRevoked {
			revocationFlag = "r"
		}
		fmt.Fprintf(w, "pub:%s:%d:%d:%d:%s:%s\n", keyID, key.Algorithm, key.BitLen,
			key.Creation.Unix(), mrTimeString(expiresAt), revocationFlag)

		for _, uid := range key.UserIDs {
			selfsigs, _ := uid.SigInfo(key)
			validSince, _ := selfsigs.ValidSince()
			expiresAt, _ := selfsigs.ExpiresAt()
			_, isRevoked := selfsigs.RevokedSince()
			revocationFlag = ""
			if isRevoked {
				revocationFlag = "r"
			}
			fmt.Fprintf(w, "uid:%s:%d:%s:%s\n", strings.Replace(uid.Keywords, ":", "%3a", -1),
				validSince.Unix(), mrTimeString(expiresAt), revocationFlag)
		}
	}
	return nil
}

type HTMLFormat struct {
	t *template.Template
}

func NewHTMLFormat(path string, extra []string) (*HTMLFormat, error) {
	f := &HTMLFormat{
		t: template.New(filepath.Base(path)).Funcs(template.FuncMap{
			"url": func(u *url.URL) template.URL {
				return template.URL(u.String())
			},
		}),
	}
	var err error
	if len(extra) > 0 {
		f.t, err = f.t.ParseFiles(append([]string{path}, extra...)...)
	} else {
		f.t, err = f.t.ParseGlob(path)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return f, nil
}

func (f *HTMLFormat) Write(w http.ResponseWriter, l *Lookup, keys []*openpgp.PrimaryKey) error {
	w.Header().Set("Content-Type", "text/html")
	wireKeys := jsonhkp.NewPrimaryKeys(keys)
	return errors.WithStack(f.t.Execute(w, struct {
		Keys  []*jsonhkp.PrimaryKey
		Query *Lookup
	}{wireKeys, l}))
}
