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
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	xopenpgp "golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

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

var errKeywordSearchNotAvailable = errors.New("keyword search is not available")

func httpError(w http.ResponseWriter, r *http.Request, statusCode int, err error) {
	if statusCode != http.StatusNotFound {
		log.Errorf("HTTP %d: %+v", statusCode, err)
		http.Error(w, http.StatusText(statusCode), statusCode)
	} else if r != nil && r.Method == "GET" {		// http.StatusNotFound
		// In order to redirect to 404.html for the current "locale",
		// the html page should set the "locale" in any requests that might get StatusNotFound
		var locale string
		locale = r.Form.Get("locale")
		// Sanitize (potentially user provided) locale input for GET requests
		if len(locale) != 7 || locale[:1] != "/" || locale[6:] != "/" || locale[3] != '_' {
			// locale string should be of this format "/en_US/", "/en_GB/", "/el_GR/" etc. Reset to en_US locale
			locale = "/en_US/"
		}			
		r.URL.Path = "/"
		http.Redirect(w, r, locale + "404.html", http.StatusSeeOther)
	} else {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

type Handler struct {
	storage storage.Storage

	indexWriter  IndexFormat
	vindexWriter IndexFormat

	statsTemplate *template.Template
	statsFunc     func() (interface{}, error)

	selfSignedOnly  bool
	fingerprintOnly bool

	keyReaderOptions []openpgp.KeyReaderOption
	keyWriterOptions []openpgp.KeyWriterOption
}

type HandlerOption func(h *Handler) error

func IndexTemplate(path string, extra ...string) HandlerOption {
	return func(h *Handler) error {
		tw, err := NewHTMLFormat(path, extra)
		if err != nil {
			return errors.WithStack(err)
		}
		h.indexWriter = tw
		return nil
	}
}

func VIndexTemplate(path string, extra ...string) HandlerOption {
	return func(h *Handler) error {
		tw, err := NewHTMLFormat(path, extra)
		if err != nil {
			return errors.WithStack(err)
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
			return errors.WithStack(err)
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

func KeyReaderOptions(opts []openpgp.KeyReaderOption) HandlerOption {
	return func(h *Handler) error {
		h.keyReaderOptions = opts
		return nil
	}
}

func KeyWriterOptions(opts []openpgp.KeyWriterOption) HandlerOption {
	return func(h *Handler) error {
		h.keyWriterOptions = opts
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
			return nil, errors.WithStack(err)
		}
	}
	return h, nil
}

func (h *Handler) Register(r *httprouter.Router) {
	r.GET("/pks/lookup", h.Lookup)
	r.POST("/pks/add", h.Add)
	r.POST("/pks/replace", h.Replace)
	r.POST("/pks/delete", h.Delete)
	r.POST("/pks/hashquery", h.HashQuery)
}

func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	l, err := ParseLookup(r)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, err)
		return
	}
	switch l.Op {
	case OperationGet, OperationHGet:
		h.get(w,r , l)
	case OperationIndex, OperationMRIndex:
		h.index(w, r, l, h.indexWriter)
	case OperationVIndex:
		h.index(w, r, l, h.vindexWriter)
	case OperationStats:
		h.stats(w, r, l)
	default:
		httpError(w, r, http.StatusNotFound, errors.Errorf("operation not found: %v", l.Op))
		return
	}
}

func (h *Handler) HashQuery(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	hq, err := ParseHashQuery(r)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
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
		log.WithFields(log.Fields{
			"fp":     key.Fingerprint(),
			"length": key.Length,
		}).Info("hashquery result")
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
		return errors.WithStack(err)
	}
	err = recon.WriteInt(w, buf.Len())
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (h *Handler) resolve(l *Lookup) ([]string, error) {
	searchStr := l.Search
	if strings.HasPrefix(l.Search, "0x") {
		searchStr = l.Search[2:]
	}

	if l.Op == OperationHGet {
		return h.storage.MatchMD5([]string{searchStr})
	}
	if strings.HasPrefix(l.Search, "0x") {
		keyID := openpgp.Reverse(strings.ToLower(searchStr))
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
		return nil, errors.WithStack(err)
	}
	for _, key := range keys {
		if err := openpgp.ValidSelfSigned(key, h.selfSignedOnly); err != nil {
			return nil, errors.WithStack(err)
		}
		log.WithFields(log.Fields{
			"fp":     key.Fingerprint(),
			"length": key.Length,
			"op":     l.Op,
		}).Info("lookup")
	}
	return keys, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request, l *Lookup) {
	keys, err := h.keys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	} else if err != nil {
		httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, r, http.StatusNotFound, errors.New("not found"))
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
	err = openpgp.WriteArmoredPackets(w, keys, h.keyWriterOptions...)
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

func (h *Handler) index(w http.ResponseWriter, r *http.Request, l *Lookup, f IndexFormat) {
	keys, err := h.keys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	} else if err != nil {
		httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, r, http.StatusNotFound, errors.New("No keys found"))
		return
	}

	if l.Options[OptionMachineReadable] {
		f = mrFormat
	} else if l.Options[OptionJSON] || f == nil {
		f = jsonFormat
	}

	err = f.Write(w, l, keys)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
}

func (h *Handler) indexJSON(w http.ResponseWriter, r *http.Request, keys []*openpgp.PrimaryKey) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(&keys)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
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

func (h *Handler) stats(w http.ResponseWriter, r *http.Request, l *Lookup) {
	if h.statsFunc == nil {
		httpError(w, r, http.StatusBadRequest, errors.New("stats not configured"))
		fmt.Fprintln(w, "stats not configured")
		return
	}
	data, err := h.statsFunc()
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
		return
	}

	if h.statsTemplate != nil && !(l.Options[OptionJSON] || l.Options[OptionMachineReadable]) {
		err = h.statsTemplate.Execute(w, data)
	} else {
		err = json.NewEncoder(w).Encode(data)
	}
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
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
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	var result AddResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		err := openpgp.DropDuplicates(key)
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
			return
		}

		change, err := storage.UpsertKey(h.storage, key)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, r, http.StatusNotFound, errors.WithStack(err))
			} else {
				httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
			}
			return
		}

		fp := key.QualifiedFingerprint()
		switch change.(type) {
		case storage.KeyAdded:
			result.Inserted = append(result.Inserted, fp)
		case storage.KeyReplaced:
			result.Updated = append(result.Updated, fp)
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, fp)
		}
	}
	log.WithFields(log.Fields{
		"inserted": result.Inserted,
		"updated":  result.Updated,
	}).Info("add")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(&result)
}

func (h *Handler) Replace(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	replace, err := ParseReplace(r)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	signingFp, err := h.checkSignature(replace.Keytext, replace.Keysig)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.Wrap(err, "invalid signature"))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(replace.Keytext))
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	var result AddResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		if signingFp != key.Fingerprint() {
			continue
		}
		err := openpgp.DropDuplicates(key)
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
			return
		}
		change, err := storage.ReplaceKey(h.storage, key)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, r, http.StatusNotFound, errors.WithStack(err))
			} else {
				httpError(w, r, http.StatusInternalServerError, errors.WithStack(err))
			}
			return
		}

		fp := key.QualifiedFingerprint()
		switch change.(type) {
		case storage.KeyAdded:
			result.Inserted = append(result.Inserted, fp)
		case storage.KeyReplaced:
			result.Updated = append(result.Updated, fp)
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, fp)
		}
	}
	log.WithFields(log.Fields{
		"inserted": result.Inserted,
		"updated":  result.Updated,
	}).Info("add")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(&result)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	del, err := ParseDelete(r)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	signingFp, err := h.checkSignature(del.Keytext, del.Keysig)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, errors.Wrap(err, "invalid signature"))
		return
	}

	change, err := storage.DeleteKey(h.storage, signingFp)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			httpError(w, r, http.StatusNotFound, errors.WithStack(err))
		} else {
			httpError(w, r, http.StatusInternalServerError, errors.Wrap(err, "failed to delete key"))
		}
		return
	}

	log.WithFields(log.Fields{
		"change":  change,
		"deleted": []string{signingFp},
	}).Info("delete")

	return
}

func (h *Handler) checkSignature(keytext, keysig string) (string, error) {
	keyring, err := xopenpgp.ReadArmoredKeyRing(bytes.NewBufferString(keytext))
	if err != nil {
		return "", errors.Wrap(err, "invalid or unsupported keytext")
	}
	signingKey, err := xopenpgp.CheckArmoredDetachedSignature(
		keyring, bytes.NewBufferString(keytext), bytes.NewBufferString(keysig), nil)
	if err != nil {
		return "", errors.Wrap(err, "invalid signature")
	}
	return hex.EncodeToString(signingKey.PrimaryKey.Fingerprint[:]), nil
}
