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
	"slices"
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
	keyIDLen         = 16
	v4FingerprintLen = 40
	maxPrefixes      = 1000
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
	policy  *openpgp.Policy

	indexWriter  IndexFormat
	vindexWriter IndexFormat

	responseTemplate *template.Template

	statsTemplate *template.Template
	statsFunc     func(req *http.Request) (interface{}, error)

	selfSignedOnly  bool
	fingerprintOnly bool
	enableInexact   bool

	enumerableDomains []string

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

func ResponseTemplate(path string, extra ...string) HandlerOption {
	return func(h *Handler) error {
		t := template.New(filepath.Base(path)).Funcs(template.FuncMap{
			"url": func(u *url.URL) template.URL {
				return template.URL(u.String())
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
		h.responseTemplate = t
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

func EnableInexact(enableInexact bool) HandlerOption {
	return func(h *Handler) error {
		h.enableInexact = enableInexact
		return nil
	}
}

func EnumerableDomains(enumerableDomains []string) HandlerOption {
	return func(h *Handler) error {
		h.enumerableDomains = enumerableDomains
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

func NewHandler(storage storage.Storage, policy *openpgp.Policy, options ...HandlerOption) (*Handler, error) {
	h := &Handler{
		storage:        storage,
		policy:         policy,
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
	r.OPTIONS("/pks/health", h.HkpGetHeadOptions)
	r.HEAD("/pks/health", h.Health)
	r.GET("/pks/health", h.Health)

	r.OPTIONS("/pks/stats", h.HkpGetHeadOptions)
	r.HEAD("/pks/stats", h.Stats)
	r.GET("/pks/stats", h.Stats)

	r.OPTIONS("/pks/lookup", h.HkpGetOptions)
	r.GET("/pks/lookup", h.Lookup)

	r.OPTIONS("/pks/add", h.HkpPostOptions)
	r.POST("/pks/add", h.Add)

	r.OPTIONS("/pks/replace", h.HkpPostOptions)
	r.POST("/pks/replace", h.Replace)

	r.OPTIONS("/pks/delete", h.HkpPostOptions)
	r.POST("/pks/delete", h.Delete)

	r.POST("/pks/hashquery", h.HashQuery)

	r.OPTIONS("/pks/v2/certs/by-vfingerprint", h.HkpGetOptions)
	r.GET("/pks/v2/certs/by-vfingerprint/:vfp", h.VfpLookup)

	r.OPTIONS("/pks/v2/certs/by-identity", h.HkpGetOptions)
	r.GET("/pks/v2/certs/by-identity/:identity", h.IdentityLookup)

	r.OPTIONS("/pks/v2/certs/by-keyid", h.HkpGetOptions)
	r.GET("/pks/v2/certs/by-keyid/:keyid", h.KeyIdLookup)

	//	r.OPTIONS("/pks/v2/canonical", h.HkpPutGetOptions)
	//	r.GET("/pks/v2/canonical/:identity", h.GetCanonical)
	//	r.PUT("/pks/v2/canonical/:identity", h.PutCanonical)

	//	r.OPTIONS("/pks/v2/sendtoken", h.HkpPostOptionsSendToken)
	//	r.POST("/pks/v2/sendtoken/", h.SendToken)

	r.OPTIONS("/pks/v2/index", h.HkpGetOptions)
	r.GET("/pks/v2/index/:identity", h.Hkp2Index)

	r.OPTIONS("/pks/v2/prefixlog", h.HkpGetOptions)
	r.GET("/pks/v2/prefixlog/:date", h.PrefixLog)

	r.OPTIONS("/pks/v2/certs", h.HkpPostOptionsv2Sub)
	r.POST("/pks/v2/certs", h.Add)
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodHead {
		return
	}
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Errorf("error writing health: %v", err)
	}
}

func (h *Handler) Stats(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodHead {
		return
	}
	err := r.ParseForm()
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
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

func (h *Handler) VfpLookup(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	l := &Lookup{
		Op:     OperationByVFingerprint,
		Search: params.ByName("vfp"),
	}
	h.get2(w, l)
}

func (h *Handler) IdentityLookup(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	l := &Lookup{
		Op:     OperationByIdentity,
		Search: params.ByName("identity"),
	}
	h.get2(w, l)
}

func (h *Handler) KeyIdLookup(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	l := &Lookup{
		Op:     OperationByKeyId,
		Search: params.ByName("keyid"),
	}
	h.get2(w, l)
}

func (h *Handler) Hkp2Index(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	l := &Lookup{
		Op:     OperationByIdentity,
		Search: params.ByName("identity"),
	}
	h.index2(w, l)
}

func (h *Handler) PrefixLog(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	log.Infof("date: %q", params.ByName("date"))
	refTime, err := time.Parse(time.DateOnly, params.ByName("date"))
	maxTime := refTime.Add(time.Hour * 24)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var fps, newFps []string
	for {
		newFps, refTime, err = h.storage.ModifiedSinceToFp(refTime, maxTime)
		if len(newFps) == 0 {
			break
		}
		fps = append(fps, newFps...)
		if len(fps) > maxPrefixes {
			break
		}
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}

	// Set the prefix length using a rule of thumb.
	// This should be short enough to provide anonymity, but long enough to prevent excessive load.
	// TODO: use a proper algorithm! Base it on the total size of the dataset.
	prefixLen := 8
	crlf := []byte{0x0d, 0x0a}

	for _, fp := range fps {
		w.Write([]byte(fp[:prefixLen]))
		w.Write(crlf)
	}
}

// HashQuery takes a list of digests and returns all matching keys in the database, within limits.
// BEWARE that since SKS peers will generally make HashQuery requests in batches of 100, if
// Settings.OpenPGP.DB.RequestQueryLimit is reduced from the default 100, this may not return all
// available keys in each request, leading to increased sync retries.
func (h *Handler) HashQuery(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	hq, err := ParseHashQuery(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}
	var result []*storage.Record

	responseLen := 0
	records, err := h.storage.FetchRecordsByMD5(hq.Digests, storage.AutoPreen)
	if err != nil {
		log.Errorf("error fetching keys from digests %v: %v", hq.Digests, err)
		return
	}
	for _, record := range records {
		if record.PrimaryKey == nil {
			continue
		}
		// If maxResponseLen is 0 we consider it unlimited
		if h.maxResponseLen != 0 {
			if responseLen+record.Length > h.maxResponseLen {
				log.Infof("Limiting response to %d bytes (maximum %d bytes)", responseLen, h.maxResponseLen)
				break
			}
		}
		responseLen = responseLen + record.Length
		result = append(result, record)
	}

	if numKeys := len(result); numKeys > 0 {
		// Once per hashquery, pick a random key from the results and verify it.
		// If it changes or evaporates, call a writeback and try another key.
		// This gently drains crufty db entries as our peers request them from us.
		first := rand.Intn(numKeys)
		for i := first; i < first+numKeys; i++ {
			key := result[i%numKeys].PrimaryKey
			oldMD5 := key.MD5
			err = h.policy.ValidSelfSigned(key, false)
			if err == openpgp.ErrKeyEvaporated {
				// This is most likely caused by our storage containing invalid cruft. Delete it.
				_, err := storage.DeleteKey(h.storage, key.Fingerprint)
				if err != nil {
					log.Warnf("could not delete evaporated key %s: %s", key.Fingerprint, err.Error())
					break
				}
			} else if err != nil {
				log.Warnf("error validating %s: %s", key.Fingerprint, err.Error())
				break
			} else if key.MD5 == oldMD5 {
				// Stop processing after the first good key; don't hog the cpu.
				break
			}
			storage.UpsertKey(h.storage, key, h.policy)
		}
	}

	// TODO: use a proper content-type
	w.Header().Set("Content-Type", "pgp/keys")

	// Write the number of keys
	if err := recon.WriteInt(w, len(result)); err != nil {
		log.Errorf("error writing number of keys, peer connection lost: %v", err)
		return
	}
	for _, record := range result {
		// Write each key in binary packet format, prefixed with length
		err = writeHashqueryKey(w, record.PrimaryKey)
		if err != nil {
			log.Errorf("error writing hashquery key fp=%q: %v", record.Fingerprint, err)
			return
		}
		log.WithFields(log.Fields{
			"fp":     record.Fingerprint,
			"length": record.Length,
		}).Debug("hashquery result")
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

// fetchKeys() takes an HKP lookup request and returns a slice of matching keys from the database.
// It performs cleaning and optional writebacks on the returned keys to keep the records fresh.
func (h *Handler) fetchKeys(l *Lookup) ([]*openpgp.PrimaryKey, error) {
	var records []*storage.Record
	var err error
	switch l.Op {
	case OperationHGet:
		records, err = h.storage.FetchRecordsByMD5([]string{l.Search}, storage.AutoPreen)
	case OperationByVFingerprint:
		records, err = h.storage.FetchRecordsByVfp([]string{l.Search}, storage.AutoPreen)
	case OperationByIdentity:
		records, err = h.storage.FetchRecordsByIdentity([]string{l.Search}, storage.AutoPreen)
	case OperationByKeyId:
		var fps []string
		keyID := strings.ToLower(l.Search)
		if len(keyID) != keyIDLen {
			return nil, errors.Errorf("bad keyid length")
		}
		fps, err = h.storage.ResolveToFp([]string{keyID})
		if err == nil {
			log.Debugf("resolved search=%q to fps=%q", l.Search, fps)
			records, err = h.storage.FetchRecordsByFp(fps, storage.AutoPreen)
		}
	default:
		// HKPv1 free-text search
		if strings.HasPrefix(l.Search, "0x") {
			var fps []string
			keyID := strings.ToLower(l.Search[2:])
			switch len(keyID) {
			case keyIDLen, v4FingerprintLen:
				// always resolve v4 fingerprints in case they are subkey fingerprints
				fps, err = h.storage.ResolveToFp([]string{keyID})
				if err == nil {
					log.Debugf("resolved search=%q to fps=%q", l.Search, fps)
					records, err = h.storage.FetchRecordsByFp(fps, storage.AutoPreen)
				}
			}
		} else {
			if h.fingerprintOnly {
				return nil, errKeywordSearchNotAvailable
			}
			if (h.enableInexact && !l.Exact) || slices.Contains(h.enumerableDomains, l.Search) {
				records, err = h.storage.FetchRecordsByKeyword(l.Search, storage.AutoPreen)
			} else {
				records, err = h.storage.FetchRecordsByIdentity([]string{l.Search}, storage.AutoPreen)
			}
		}
	}
	if err != nil {
		return nil, err
	}

	var keys []*openpgp.PrimaryKey
	for _, record := range records {
		if record.PrimaryKey == nil {
			log.Debugf("ignoring evaporated key fp=%s", record.Fingerprint)
			continue
		}
		key := record.PrimaryKey
		if err := h.policy.ValidSelfSigned(key, h.selfSignedOnly); err != nil {
			log.Debugf("ignoring invalid self-sig key %v: %q", key.Fingerprint, err)
			continue
		}
		log.WithFields(log.Fields{
			"search": l.Search,
			"fp":     key.Fingerprint,
			"length": key.Length,
			"op":     l.Op,
		}).Info("lookup")
		keys = append(keys, key)
	}
	return keys, nil
}

func (h *Handler) get2(w http.ResponseWriter, l *Lookup) {
	keys, err := h.fetchKeys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusNotImplemented, errors.New("not available"))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	err = h.policy.SanitizeHKP(keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	// TODO: use proper content type
	w.Header().Set("Content-Type", "application/pgp")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+url.PathEscape(l.Search)+".pgp\"")

	for _, key := range keys {
		err = openpgp.WritePackets(w, key)
		if err != nil {
			log.Errorf("get %q: error writing keys: %v", l.Search, err)
		}
	}
	// TODO: write padding
}

func (h *Handler) get(w http.ResponseWriter, l *Lookup) {
	keys, err := h.fetchKeys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusNotImplemented, errors.New("not available"))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	err = h.policy.SanitizeHKP(keys)
	if err != nil {
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
		w.Header().Set("Content-Disposition", "attachment; filename=\""+url.PathEscape(l.Search)+".asc\"")
	}

	// Always set gpgClientCompat=true, because there's no reliable way to detect gpg so we have to play safe.
	err = openpgp.WriteArmoredPackets(w, keys, true, h.keyWriterOptions...)
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
	keys, err := h.fetchKeys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusNotImplemented, errors.New("not available"))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	err = h.policy.SanitizeIndex(keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	if l.Options[OptionMachineReadable] {
		f = mrFormat
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

func (h *Handler) index2(w http.ResponseWriter, l *Lookup) {
	keys, err := h.fetchKeys(l)
	if err == errKeywordSearchNotAvailable {
		httpError(w, http.StatusNotImplemented, errors.New("not available"))
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	err = h.policy.SanitizeIndex(keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	err = jsonFormat.Write(w, l, keys)
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
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(data)
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
	}
}

func (h *Handler) HkpGetOptions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Allow", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HkpGetHeadOptions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Allow", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HkpPostOptions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Allow", "POST, OPTIONS")
	w.Header().Set("Accept", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HkpPostOptionsv2Sub(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Allow", "POST, OPTIONS")
	w.Header().Set("Accept", "application/pgp")               // TODO: use proper content type
	w.Header().Set("Accept", "application/pgp-keys;armor=no") // TODO: use proper content type
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HkpPutOptions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Allow", "PUT, OPTIONS")
	w.Header().Set("Accept", "application/pgp")               // TODO: use proper content type
	w.Header().Set("Accept", "application/pgp-keys;armor=no") // TODO: use proper content type
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

type CertSummary struct {
	Version     uint8  `json:"version"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
}

func summary(key *openpgp.PrimaryKey, comment string) CertSummary {
	return CertSummary{key.Version, key.Fingerprint, comment}
}

type SubmissionResponse struct {
	Inserted []CertSummary `json:"inserted,omitempty"`
	Updated  []CertSummary `json:"updated,omitempty"`
	Deleted  []CertSummary `json:"deleted,omitempty"`
	Ignored  []CertSummary `json:"ignored,omitempty"`
	Invalid  []CertSummary `json:"invalid,omitempty"`
}

func (h *Handler) Add(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	add, err := ParseAdd(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}

	var result SubmissionResponse
	kr := openpgp.NewKeyReader(add.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err == openpgp.ErrBareRevocation {
		// try to find the primary key belonging to the revocation sig
		// we will need a fresh chain of readers as the existing has hit EOF
		// BEWARE that in HKPv2, add.Keytext will always be empty and this will fail
		armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
		if err != nil {
			httpError(w, http.StatusBadRequest, errors.WithStack(err))
			return
		}
		okr, _ := openpgp.NewOpaqueKeyReader(armorBlock.Body)
		keyring, err := okr.Read()
		if err != nil {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			return
		}
		if len(keyring) != 1 || len(keyring[0].Packets) != 1 {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(errors.Errorf("No packets found in submitted block")))
			return
		}
		sig, err := openpgp.ParseSignature(keyring[0].Packets[0], time.Now(), "", "")
		if err != nil {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			return
		}
		var l Lookup
		if sig.IssuerFingerprint != "" {
			log.Infof("fetching primary key for fp=%v", sig.IssuerFingerprint)
			l.Search = "0x" + sig.IssuerFingerprint
		} else {
			log.Infof("fetching primary key for kid=%v", sig.IssuerKeyID)
			l.Search = "0x" + sig.IssuerKeyID
		}
		keys, err = h.fetchKeys(&l)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
			} else {
				httpError(w, http.StatusInternalServerError, errors.WithStack(err))
			}
			return
		}
		for _, key := range keys {
			err = h.policy.MergeRevocationSig(key, sig)
			if err != nil {
				log.Infof("Could not merge revocation of %s into %s", l.Search, key.Fingerprint)
			}
			log.Infof("Merged revocation into %s", key.Fingerprint)
		}
	} else if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
		return
	}
	// We *do* expect trust packets from our PKS peers via this endpoint, so don't sanitize.
	// ValidSelfSigned will take care of anything unverifiable.
	for _, key := range keys {
		err = h.policy.ValidSelfSigned(key, false)
		if err != nil {
			result.Invalid = append(result.Invalid, summary(key, err.Error()))
			continue
		}

		change, err := storage.UpsertKey(h.storage, key, h.policy)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errors.WithStack(err))
			return
		}

		switch change.(type) {
		case storage.KeyAdded:
			result.Inserted = append(result.Inserted, summary(key, ""))
		case storage.KeyReplaced:
			result.Updated = append(result.Updated, summary(key, ""))
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, summary(key, ""))
		}
	}
	log.WithFields(log.Fields{
		"inserted": result.Inserted,
		"updated":  result.Updated,
		"ignored":  result.Ignored,
		"invalid":  result.Invalid,
	}).Info("add")

	w.Header().Set("Access-Control-Allow-Origin", "*")
	if h.responseTemplate != nil && !(add.Options[OptionJSON] || add.Options[OptionMachineReadable]) {
		err = h.responseTemplate.Execute(w, result)
	} else {
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(result)
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
	}
}

func (h *Handler) Replace(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	replace, err := ParseReplace(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	_, err = h.checkSignature(replace.Keytext, replace.Keysig)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.Wrap(err, "invalid signature"))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(replace.Keytext))
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
		return
	}

	var result SubmissionResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
		return
	}
	// We don't expect to receive trust packets via this endpoint
	err = h.policy.SanitizeHKP(keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		err = h.policy.ValidSelfSigned(key, false)
		if err != nil {
			httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
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

		switch change.(type) {
		case storage.KeyAdded:
			result.Inserted = append(result.Inserted, summary(key, ""))
		case storage.KeyReplaced:
			result.Updated = append(result.Updated, summary(key, ""))
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, summary(key, ""))
		}
	}
	log.WithFields(log.Fields{
		"inserted": result.Inserted,
		"updated":  result.Updated,
		"ignored":  result.Ignored,
	}).Info("add")

	w.Header().Set("Access-Control-Allow-Origin", "*")
	if h.responseTemplate != nil {
		err = h.responseTemplate.Execute(w, result)
	} else {
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(result)
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
	}
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	del, err := ParseDelete(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	_, err = h.checkSignature(del.Keytext, del.Keysig)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.Wrap(err, "invalid signature"))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(del.Keytext))
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
		return
	}

	var result SubmissionResponse
	kr := openpgp.NewKeyReader(armorBlock.Body, h.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, errors.WithStack(err))
		return
	}
	// We don't expect to receive trust packets via this endpoint
	err = h.policy.SanitizeHKP(keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
		return
	}
	for _, key := range keys {
		change, err := storage.DeleteKey(h.storage, key.Fingerprint)
		if err != nil {
			if errors.Is(err, storage.ErrKeyNotFound) {
				httpError(w, http.StatusNotFound, errors.WithStack(err))
			} else {
				httpError(w, http.StatusInternalServerError, errors.Wrap(err, "failed to delete key"))
			}
			return
		}

		switch change.(type) {
		case storage.KeyAdded:
			result.Deleted = append(result.Deleted, summary(key, ""))
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, summary(key, ""))
		}
	}

	log.WithFields(log.Fields{
		"deleted": result.Deleted,
		"ignored": result.Ignored,
	}).Info("delete")

	w.Header().Set("Access-Control-Allow-Origin", "*")
	if h.responseTemplate != nil {
		err = h.responseTemplate.Execute(w, result)
	} else {
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(result)
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, errors.WithStack(err))
	}
}

func (h *Handler) checkSignature(keytext, keysig string) (string, error) {
	keyring := xopenpgp.EntityList{}
	fps := []string{}
	for _, fp := range h.adminKeys {
		fps = append(fps, fp)
	}
	adminRecords, err := h.storage.FetchRecordsByFp(fps, storage.AutoPreen)
	if err != nil {
		log.Errorf("could not fetch admin keys: %s", err)
	}
	for _, record := range adminRecords {
		if record.PrimaryKey == nil {
			log.Errorf("evaporated admin key fp=%s: %s", record.Fingerprint, err)
			continue
		}
		// Serialize the admin primary key via jsonhkp.PrimaryKey and re-parse as a pm/gc Entity.
		// There must be a better way to do this...
		buffer := bytes.NewBuffer([]byte{})
		err := jsonhkp.NewPrimaryKey(record.PrimaryKey).Serialize(buffer)
		if err != nil {
			log.Errorf("could not serialize admin key fp=%s: %s", record.Fingerprint, err)
			continue
		}
		adminKey, err := xopenpgp.ReadEntity(pgppacket.NewReader(buffer))
		if err != nil {
			log.Errorf("could not parse admin key fp=%s: %s", record.Fingerprint, err)
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
