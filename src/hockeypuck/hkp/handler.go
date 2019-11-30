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
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/openpgp/armor"
	"gopkg.in/errgo.v1"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	log "hockeypuck/logrus"
	"hockeypuck/openpgp"
)

const (
	shortKeyIDLen       = 8
	longKeyIDLen        = 16
	fingerprintKeyIDLen = 40
)

var errKeywordSearchNotAvailable = errgo.New("keyword search is not available")

func httpError(w http.ResponseWriter, statusCode int, err error) {
	if statusCode != http.StatusNotFound {
		log.Errorf("HTTP %d: %v", statusCode, errgo.Details(err))
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

type Handler struct {
	storage storage.Storage

	indexWriter  IndexFormat
	vindexWriter IndexFormat

	statsTemplate *template.Template
	statsFunc     func() (interface{}, error)

	selfSignedOnly  bool
	fingerprintOnly bool
}

type HandlerOption func(h *Handler) error

func IndexTemplate(path string, extra ...string) HandlerOption {
	return func(h *Handler) error {
		tw, err := NewHTMLFormat(path, extra)
		if err != nil {
			return errgo.Mask(err)
		}
		h.indexWriter = tw
		return nil
	}
}

func VIndexTemplate(path string, extra ...string) HandlerOption {
	return func(h *Handler) error {
		tw, err := NewHTMLFormat(path, extra)
		if err != nil {
			return errgo.Mask(err)
		}
		h.vindexWriter = tw
		return nil
	}
}

func StatsTemplate(path string, extra ...string) HandlerOption {
	return func(h *Handler) error {
		t := template.New(filepath.Base(path)).Funcs(template.FuncMap{
			"url": func(u *url.URL) template.URL {
				return template.URL(u.String())
			},
			"day": func(t time.Time) string {
				return t.Format("2006-01-02")
			},
			"hour": func(t time.Time) string {
				return t.Format("2006-01-02 15")
			},
		})
		var err error
		if len(extra) > 0 {
			t, err = t.ParseFiles(append([]string{path}, extra...)...)
		} else {
			t, err = t.ParseGlob(path)
		}
		if err != nil {
			return errgo.Mask(err)
		}
		h.statsTemplate = t
		return nil
	}
}

func StatsFunc(f func() (interface{}, error)) HandlerOption {
	return func(h *Handler) error {
		h.statsFunc = f
		return nil
	}
}

func SelfSignedOnly(selfSignedOnly bool) HandlerOption {
	return func(h *Handler) error {
		h.selfSignedOnly = selfSignedOnly
		return nil
	}
}

func FingerprintOnly(fingerprintOnly bool) HandlerOption {
	return func(h *Handler) error {
		h.fingerprintOnly = fingerprintOnly
		return nil
	}
}

func NewHandler(storage storage.Storage, options ...HandlerOption) (*Handler, error) {
	h := &Handler{
		storage: storage,
	}
	for _, option := range options {
		err := option(h)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return h, nil
}

func (h *Handler) Register(r *httprouter.Router) {
	r.GET("/pks/lookup", h.Lookup)
	r.POST("/pks/add", h.Add)
	r.POST("/pks/hashquery", h.HashQuery)
}

func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	l, err := ParseLookup(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	switch l.Op {
	case OperationGet, OperationHGet:
		h.get(w, l)
	case OperationIndex:
		h.index(w, l, h.indexWriter)
	case OperationVIndex:
		h.index(w, l, h.vindexWriter)
	case OperationStats:
		h.stats(w, l)
	default:
		httpError(w, http.StatusNotFound, errgo.Newf("operation not found: %v", l.Op))
		return
	}
}

func (h *Handler) HashQuery(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	hq, err := ParseHashQuery(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}
	var result []*openpgp.PrimaryKey
	for _, digest := range hq.Digests {
		rfps, err := h.storage.MatchMD5([]string{digest})
		if err != nil {
			log.Errorf("error resolving hashquery digest %q", digest)
			continue
		}
		keys, err := h.storage.FetchKeys(rfps)
		if err != nil {
			log.Errorf("error fetching hashquery key %q", digest)
			continue
		}
		result = append(result, keys...)
	}

	w.Header().Set("Content-Type", "pgp/keys")

	// Write the number of keys
	err = recon.WriteInt(w, len(result))
	for _, key := range result {
		// Write each key in binary packet format, prefixed with length
		err = writeHashqueryKey(w, key)
		if err != nil {
			log.Errorf("error writing hashquery key %q: %v", key.RFingerprint, err)
			return
		}
	}

	// SKS expects hashquery response to terminate with a CRLF
	_, err = w.Write([]byte{0x0d, 0x0a})
	if err != nil {
		log.Errorf("error writing hashquery terminator: %v", err)
	}
}

func writeHashqueryKey(w http.ResponseWriter, key *openpgp.PrimaryKey) error {
	var buf bytes.Buffer
	err := openpgp.WritePackets(&buf, key)
	if err != nil {
		return errgo.Mask(err)
	}
	err = recon.WriteInt(w, buf.Len())
	if err != nil {
		return errgo.Mask(err)
	}
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (h *Handler) resolve(l *Lookup) ([]string, error) {
	if l.Op == OperationHGet {
		return h.storage.MatchMD5([]string{l.Search})
	}
	if strings.HasPrefix(l.Search, "0x") {
		keyID := openpgp.Reverse(strings.ToLower(l.Search[2:]))
		switch len(keyID) {
		case shortKeyIDLen, longKeyIDLen, fingerprintKeyIDLen:
			return h.storage.Resolve([]string{keyID})
		}
	}
	if h.fingerprintOnly {
		return nil, errKeywordSearchNotAvailable
	}
	return h.storage.MatchKeyword([]string{l.Search})
}

func (h *Handler) keys(l *Lookup) ([]*openpgp.PrimaryKey, error) {
	rfps, err := h.resolve(l)
	if err != nil {
		return nil, err
	}
	keys, err := h.storage.FetchKeys(rfps)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	for _, key := range keys {
		if err := openpgp.ValidSelfSigned(key, h.selfSignedOnly); err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return keys, nil
}

func (h *Handler) get(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errgo.New("not found"))
		return
	}

	// Drop malformed packets, since these break GPG imports.
	for _, key := range keys {
		var others []*openpgp.Packet
		for _, other := range key.Others {
			if other.Malformed {
				continue
			}
			others = append(others, other)
		}
		key.Others = others
	}

	w.Header().Set("Content-Type", "text/plain")
	err = openpgp.WriteArmoredPackets(w, keys)
	if err != nil {
		log.Errorf("get %q: error writing armored keys: %v", l.Search, err)
	}
	// Write a trailing newline as required by the HKP spec
	// (§3.1.2.1) and as expected by many tools, e.g. RPM.
	_, err = w.Write([]byte("\n"))
	if err != nil {
		log.Errorf("get %q: failed to write trailing newline: %v", l.Search, err)
	}
}

func (h *Handler) index(w http.ResponseWriter, l *Lookup, f IndexFormat) {
	keys, err := h.keys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errgo.New("not found"))
		return
	}

	if l.Options[OptionMachineReadable] {
		f = mrFormat
	} else if l.Options[OptionJSON] || f == nil {
		f = jsonFormat
	}

	err = f.Write(w, l, keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
}

func (h *Handler) indexJSON(w http.ResponseWriter, keys []*openpgp.PrimaryKey) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(&keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
}

func mrTimeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d", t.Unix())
}

type StatsResponse struct {
	Info  interface{}
	Stats *sks.Stats
}

func (h *Handler) stats(w http.ResponseWriter, l *Lookup) {
	if h.statsFunc == nil {
		httpError(w, http.StatusBadRequest, errgo.New("stats not configured"))
		fmt.Fprintln(w, "stats not configured")
		return
	}
	data, err := h.statsFunc()
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}

	if h.statsTemplate != nil && !(l.Options[OptionJSON]) {
		err = h.statsTemplate.Execute(w, data)
	} else {
		err = json.NewEncoder(w).Encode(data)
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
	}
}

type AddResponse struct {
	Inserted []string `json:"inserted"`
	Updated  []string `json:"updated"`
	Ignored  []string `json:"ignored"`
}

func (h *Handler) Add(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	add, err := ParseAdd(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}

	var result AddResponse
	for readKey := range openpgp.ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			httpError(w, http.StatusBadRequest, errgo.Mask(err))
			return
		}
		err := openpgp.DropDuplicates(readKey.PrimaryKey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errgo.Mask(err))
			return
		}
		change, err := storage.UpsertKey(h.storage, readKey.PrimaryKey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errgo.Mask(err))
			return
		}

		fp := readKey.PrimaryKey.QualifiedFingerprint()
		switch change.(type) {
		case storage.KeyAdded:
			result.Inserted = append(result.Inserted, fp)
		case storage.KeyReplaced:
			result.Updated = append(result.Updated, fp)
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, fp)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(&result)
}
