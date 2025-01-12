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
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	xopenpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgppacket "github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp/jsonhkp"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"
)

const (
	shortKeyIDLen       = 8
	longKeyIDLen        = 16
	fingerprintKeyIDLen = 40
)

var errKeywordSearchNotAvailable = errors.New("keyword search is not available")

func httpError(w http.ResponseWriter, statusCode int, err error) {
	if statusCode != http.StatusNotFound {
		log.Errorf("HTTP %d: %+v", statusCode, err)
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

type Handler struct {
	storage storage.Storage

	indexWriter  IndexFormat
	vindexWriter IndexFormat

	statsTemplate *template.Template
	statsFunc     func(req *http.Request) (interface{}, error)

	selfSignedOnly  bool
	fingerprintOnly bool

	keyReaderOptions []openpgp.KeyReaderOption
	keyWriterOptions []openpgp.KeyWriterOption
	maxResponseLen   int

	adminKeys []string
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

func StatsFunc(f func(req *http.Request) (interface{}, error)) HandlerOption {
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

func MaxResponseLen(maxResponseLen int) HandlerOption {
	return func(h *Handler) error {
		h.maxResponseLen = maxResponseLen
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

func AdminKeys(adminKeys []string) HandlerOption {
	// Normalise adminKeys to lowercase without 0x prefix on startup
	return func(h *Handler) error {
		for index, fp := range adminKeys {
			bareFp, _ := strings.CutPrefix(fp, "0x")
			adminKeys[index] = strings.ToLower(bareFp)
		}
		h.adminKeys = adminKeys
		return nil
	}
}

func NewHandler(storage storage.Storage, options ...HandlerOption) (*Handler, error) {
	h := &Handler{
		storage:        storage,
		maxResponseLen: 0,
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
	r.GET("/pks/health", h.Health)
	r.GET("/pks/stats", h.Stats)
	r.GET("/pks/lookup", h.Lookup)
	r.POST("/pks/add", h.Add)
	r.POST("/pks/replace", h.Replace)
	r.POST("/pks/delete", h.Delete)
	r.POST("/pks/hashquery", h.HashQuery)
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Errorf("error writing health: %v", err)
	}
}

func (h *Handler) Stats(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	o := ParseOptionSet(r.Form.Get("options"))
	h.stats(w, r, o)
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
		h.stats(w, r, l.Options)
	default:
		httpError(w, http.StatusNotImplemented, errors.Errorf("operation not implemented: %v", l.Op))
		return
	}
}

func (h *Handler) HashQuery(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	hq, err := ParseHashQuery(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	var result []*openpgp.PrimaryKey

	responseLen := 0
	for _, digest := range hq.Digests {
		keys, err := h.fetchKeysFromDigest(digest)
		if err != nil {
			log.Errorf("error fetching keys from digest %v: %v", digest, err)
			return
		}

		if numKeys := len(keys); numKeys > 0 {
			// Once per hashquery, pick a random key from the results and verify it.
			// If it changes or evaporates, call a writeback. This gently drains cruft.
			key := keys[rand.Intn(numKeys)]
			oldMD5 := key.MD5
			err = openpgp.ValidSelfSigned(key, false)
			if err == openpgp.KeyEvaporated {
				// This is most likely caused by our storage containing invalid cruft. Delete it.
				_, err := storage.DeleteKey(h.storage, key.Fingerprint())
				if err != nil {
					log.Warnf("could not delete evaporated key %s: %s", key.Fingerprint(), err.Error())
				}
			} else if err == nil && key.MD5 != oldMD5 {
				storage.UpsertKey(h.storage, key)
			}
		}

		keysLength := 0
		for _, key := range keys {
			keysLength = keysLength + key.Length
		}

		// If maxResponseLen is 0 we consider it unlimited
		if h.maxResponseLen != 0 {
			if responseLen+keysLength > h.maxResponseLen {
				log.Infof("Limiting response to %d bytes (maximum %d bytes)", responseLen, h.maxResponseLen)
				break
			}
		}
		responseLen = responseLen + keysLength
		result = append(result, keys...)
	}

	w.Header().Set("Content-Type", "pgp/keys")

	// Write the number of keys
	if err := recon.WriteInt(w, len(result)); err != nil {
		log.Errorf("error writing number of keys, peer connection lost: %v", err)
		return
	}
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
		}).Debug("hashquery result")
	}

	// SKS expects hashquery response to terminate with a CRLF
	_, err = w.Write([]byte{0x0d, 0x0a})
	if err != nil {
		log.Errorf("error writing hashquery terminator: %v", err)
	}
}

func (h *Handler) fetchKeysFromDigest(digest string) (keys []*openpgp.PrimaryKey, err error) {
	rfps, err := h.storage.MatchMD5([]string{digest})
	if err != nil {
		log.Errorf("error resolving hashquery digest %q", digest)
		return
	}
	keys, err = h.storage.FetchKeys(rfps, storage.AutoPreen)
	if err != nil {
		log.Errorf("error fetching hashquery key %q", digest)
		return
	}
	return
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
	keys, err := h.storage.FetchKeys(rfps, storage.AutoPreen)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, key := range keys {
		if err := openpgp.ValidSelfSigned(key, h.selfSignedOnly); err != nil {
			log.Debugf("ignoring invalid self-sig key %v", key.Fingerprint())
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

func (h *Handler) get(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusNotImplemented, errors.New("not available"))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	w.Header().Set("Content-Type", "application/pgp-keys")
	if l.Options[OptionMachineReadable] {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+keys[0].Fingerprint()+".asc\"")
	}

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

func (h *Handler) index(w http.ResponseWriter, l *Lookup, f IndexFormat) {
	keys, err := h.keys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusNotImplemented, errors.New("not available"))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	if l.Options[OptionMachineReadable] {
		f = mrFormat
		// always return full fingerprints in machine readable [v]index
		// this works around a known issue in GPGTools
		// https://gpgtools.tenderapp.com/discussions/problems/121371-cannot-upload-existing-public-keys-to-hockeypuck-key-servers
		l.Fingerprint = true
	}

	if l.Options[OptionJSON] || f == nil {
		f = jsonFormat
	}

	err = f.Write(w, l, keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
}

func (h *Handler) indexJSON(w http.ResponseWriter, keys []*openpgp.PrimaryKey) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(&keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
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

func (h *Handler) stats(w http.ResponseWriter, r *http.Request, o OptionSet) {
	if h.statsFunc == nil {
		httpError(w, http.StatusNotImplemented, errors.New("stats not configured"))
		fmt.Fprintln(w, "stats not configured")
		return
	}
	data, err := h.statsFunc(r)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}

	if h.statsTemplate != nil && !(o[OptionJSON] || o[OptionMachineReadable]) {
		err = h.statsTemplate.Execute(w, data)
	} else {
		err = json.NewEncoder(w).Encode(data)
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
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
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	var result AddResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err == openpgp.ErrBareRevocation {
		// try to find the primary key belonging to the revocation sig
		// we will need a fresh chain of readers as the existing has hit EOF
		armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
		if err != nil {
			httpError(w, http.StatusBadRequest, errors.WithStack(err))
			return
		}
		okr, _ := openpgp.NewOpaqueKeyReader(armorBlock.Body)
		keyrings, err := okr.Read()
		if err != nil {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			return
		}
		if len(keyrings) != 1 || len(keyrings[0].Packets) != 1 {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(errors.Errorf("No packets found in submitted block")))
			return
		}
		sig, err := openpgp.ParseSignature(keyrings[0].Packets[0], time.Now(), "", "")
		if err != nil {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			return
		}
		log.Infof("fetching primary key for %v", sig.IssuerKeyID())
		var l Lookup
		l.Search = "0x" + sig.IssuerKeyID()
		keys, err = h.keys(&l)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			} else {
				httpError(w, http.StatusInternalServerError, errors.WithStack(err))
			}
			return
		}
		for _, key := range keys {
			err = openpgp.MergeRevocationSig(key, sig)
			if err != nil {
				log.Infof("Could not merge revocation of %s into %s", sig.IssuerKeyID(), key.Fingerprint())
			}
			log.Infof("Merged revocation into %s", key.Fingerprint())
		}
	} else if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		err = openpgp.ValidSelfSigned(key, false)
		if err != nil {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			return
		}

		change, err := storage.UpsertKey(h.storage, key)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, http.StatusNotFound, errors.WithStack(err))
			} else {
				httpError(w, http.StatusInternalServerError, errors.WithStack(err))
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
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	_, err = h.checkSignature(replace.Keytext, replace.Keysig)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.Wrap(err, "invalid signature"))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(replace.Keytext))
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	var result AddResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		err = openpgp.ValidSelfSigned(key, false)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errors.WithStack(err))
			return
		}

		change, err := storage.ReplaceKey(h.storage, key)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, http.StatusNotFound, errors.WithStack(err))
			} else {
				httpError(w, http.StatusInternalServerError, errors.WithStack(err))
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

type DeleteResponse struct {
	Deleted []string `json:"deleted"`
	Ignored []string `json:"ignored"`
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	del, err := ParseDelete(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	_, err = h.checkSignature(del.Keytext, del.Keysig)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.Wrap(err, "invalid signature"))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(del.Keytext))
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	var result DeleteResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		change, err := storage.DeleteKey(h.storage, key.Fingerprint())
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, http.StatusNotFound, errors.WithStack(err))
			} else {
				httpError(w, http.StatusInternalServerError, errors.Wrap(err, "failed to delete key"))
			}
			return
		}

		fp := key.QualifiedFingerprint()
		switch change.(type) {
		case storage.KeyAdded:
			result.Deleted = append(result.Deleted, fp)
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, fp)
		}
	}

	log.WithFields(log.Fields{
		"deleted": result.Deleted,
	}).Info("delete")
}

func (h *Handler) checkSignature(keytext, keysig string) (string, error) {
	keyring := xopenpgp.EntityList{}
	rfps := []string{}
	for _, fp := range h.adminKeys {
		rfps = append(rfps, openpgp.Reverse(fp))
	}
	adminPKs, err := h.storage.FetchKeys(rfps, storage.AutoPreen)
	if err != nil {
		log.Errorf("could not fetch admin keys: %s", err)
	}
	for _, pk := range adminPKs {
		// Serialize the admin primary key via jsonhkp.PrimaryKey and re-parse as a gopenpgp Entity.
		// There must be a better way to do this...
		buffer := bytes.NewBuffer([]byte{})
		err := jsonhkp.NewPrimaryKey(pk).Serialize(buffer)
		if err != nil {
			log.Errorf("could not serialize admin key %s: %s", pk.Fingerprint(), err)
			continue
		}
		adminKey, err := xopenpgp.ReadEntity(pgppacket.NewReader(buffer))
		if err != nil {
			log.Errorf("could not parse admin key %s: %s", pk.Fingerprint(), err)
			continue
		}
		keyring = append(keyring, adminKey)
	}
	signingKey, err := xopenpgp.CheckArmoredDetachedSignature(
		keyring, bytes.NewBufferString(keytext), bytes.NewBufferString(keysig), nil)
	if err != nil {
		return "", errors.Wrap(err, "invalid signature")
	}
	return hex.EncodeToString(signingKey.PrimaryKey.Fingerprint[:]), nil
}
