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

package sks

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	cf "hockeypuck/conflux"
	"hockeypuck/conflux/recon"
	"hockeypuck/conflux/recon/leveldb"
	"hockeypuck/hkp/storage"
	log "hockeypuck/logrus"
	"hockeypuck/openpgp"
)

const (
	RECON                  = "recon"
	httpClientTimeout      = 30
	maxKeyRecoveryAttempts = 10
	maxRequestChunkSize    = 100
	minRequestChunkSize    = 1
	recoveryRetryDelay     = 1
)

type keyRecoveryCounter map[string]int

type Peer struct {
	peer             *recon.Peer
	storage          storage.Storage
	settings         *recon.Settings
	ptree            recon.PrefixTree
	http             *http.Client
	keyReaderOptions []openpgp.KeyReaderOption
	userAgent        string

	// Adaptive request size
	requestChunkSize int
	slowStart        bool

	seenCache *lru.Cache

	path  string
	stats *Stats

	t tomb.Tomb
}

func NewPrefixTree(path string, s *recon.Settings) (recon.PrefixTree, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Debugf("creating prefix tree at: %q", path)
		err = os.MkdirAll(path, 0755)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return leveldb.New(s.PTreeConfig, path)
}

func NewPeer(st storage.Storage, path string, s *recon.Settings, opts []openpgp.KeyReaderOption, userAgent string) (*Peer, error) {
	if s == nil {
		s = recon.DefaultSettings()
	}

	ptree, err := NewPrefixTree(path, s)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = ptree.Create()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cache, err := lru.New(s.SeenCacheSize)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	peer := recon.NewPeer(s, ptree)
	sksPeer := &Peer{
		peer:     peer,
		storage:  st,
		settings: s,
		ptree:    ptree,
		http: &http.Client{
			Timeout: httpClientTimeout * time.Second,
		},
		requestChunkSize: minRequestChunkSize,
		slowStart:        true,
		seenCache:        cache,
		keyReaderOptions: opts,
		userAgent:        userAgent,
		path:             path,
	}
	sksPeer.readStats()
	st.Subscribe(sksPeer.updateDigests)
	return sksPeer, nil
}

func (p *Peer) log(label string) *log.Entry {
	return p.logFields(label, log.Fields{})
}

func (p *Peer) logAddr(label string, addr net.Addr) *log.Entry {
	return p.logFields(label, log.Fields{"remoteAddr": addr})
}

func (p *Peer) logFields(label string, fields log.Fields) *log.Entry {
	fields["label"] = fmt.Sprintf("%s %s", label, p.settings.ReconAddr)
	return log.WithFields(fields)
}

func StatsFilename(path string) string {
	dir, base := filepath.Dir(path), filepath.Base(path)
	return filepath.Join(dir, "."+base+".stats")
}

func (p *Peer) readStats() {
	fn := StatsFilename(p.path)
	stats := NewStats()
	err := stats.ReadFile(fn)
	if err != nil {
		p.log(RECON).Warningf("cannot open stats %q: %v", fn, err)
		stats = NewStats()
	}

	root, err := p.ptree.Root()
	if err != nil {
		p.log(RECON).Warningf("error accessing prefix tree root: %v", err)
	} else {
		stats.Total = root.Size()
	}

	p.stats = stats
}

func (p *Peer) writeStats() {
	fn := StatsFilename(p.path)
	err := p.stats.WriteFile(fn)
	if err != nil {
		p.log(RECON).Warningf("cannot write stats %q: %v", fn, err)
	}
}

func (p *Peer) pruneStats() error {
	timer := time.NewTimer(time.Hour)
	for {
		select {
		case <-p.t.Dying():
			return nil
		case <-timer.C:
			p.stats.prune()
			timer.Reset(time.Hour)
		}
	}
}

func (r *Peer) Stats() *Stats {
	return r.stats.clone()
}

func (r *Peer) Start() {
	r.t.Go(r.handleRecovery)
	r.t.Go(r.pruneStats)
	r.peer.Start()
}

func (r *Peer) StartMode(mode recon.PeerMode) {
	r.t.Go(r.handleRecovery)
	r.t.Go(r.pruneStats)
	r.peer.StartMode(mode)
}

func (r *Peer) Stop() {
	r.log(RECON).Info("recon processing: stopping")
	r.t.Kill(nil)
	err := r.t.Wait()
	if err != nil {
		r.log(RECON).Errorf("%+v", err)
	}
	r.log(RECON).Info("recon processing: stopped")

	r.log(RECON).Info("recon peer: stopping")
	err = errors.WithStack(r.peer.Stop())
	if err != nil {
		r.log(RECON).Errorf("%+v", err)
	}
	r.log(RECON).Info("recon peer: stopped")

	err = r.ptree.Close()
	if err != nil {
		r.log(RECON).Errorf("error closing prefix tree: %+v", err)
	}

	r.writeStats()
}

func DigestZp(digest string, zp *cf.Zp) error {
	buf, err := hex.DecodeString(digest)
	if err != nil {
		return errors.WithStack(err)
	}
	buf = recon.PadSksElement(buf)
	zp.In(cf.P_SKS).SetBytes(buf)
	zp.Norm()
	return nil
}

func (r *Peer) updateDigests(change storage.KeyChange) error {
	r.stats.Update(change)
	for _, digest := range change.InsertDigests() {
		toInsert := make([]cf.Zp, 1)
		err := DigestZp(digest, &toInsert[0])
		if err != nil {
			return errors.Wrapf(err, "bad digest %q", digest)
		}
		r.peer.Insert(toInsert...)
	}
	for _, digest := range change.RemoveDigests() {
		toRemove := make([]cf.Zp, 1)
		err := DigestZp(digest, &toRemove[0])
		if err != nil {
			return errors.Wrapf(err, "bad digest %q", digest)
		}
		r.peer.Remove(toRemove...)
	}
	return nil
}

func (r *Peer) handleRecovery() error {
	for {
		select {
		case <-r.t.Dying():
			return nil
		case rcvr := <-r.peer.RecoverChan:
			func() {
				defer close(rcvr.Done)
				if err := r.requestRecovered(rcvr); err != nil {
					r.logAddr(RECON, rcvr.RemoteAddr).Errorf("recovery completed with errors: %v", err)
				}
			}()
		}
	}
}

func (r *Peer) unseenRemoteElements(rcvr *recon.Recover) []cf.Zp {
	unseenElements := make([]cf.Zp, 0)
	for _, v := range rcvr.RemoteElements {
		_, found := r.seenCache.Get(v.FullKeyHash())
		if !found {
			unseenElements = append(unseenElements, v)
		}
	}
	if len(unseenElements) < len(rcvr.RemoteElements) {
		r.logAddr(RECON, rcvr.RemoteAddr).Errorf("recovering %d instead of %d due to seenCache(%d)",
			len(unseenElements), len(rcvr.RemoteElements), r.seenCache.Len())
	}
	return unseenElements
}

func (r *Peer) requestRecovered(rcvr *recon.Recover) error {
	items := r.unseenRemoteElements(rcvr)
	errCount := 0
	// Chunk requests to keep the hashquery message size and peer load reasonable.
	// Using additive increase, multiplicative decrease (AIMD) to adapt chunk size,
	// similar to TCP, including "slow start" (exponential increase at start when
	// not yet in AIMD mode).
	for len(items) > 0 {
		chunksize := r.requestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]

		err := r.requestChunk(rcvr, chunk)
		if err == nil || chunksize <= minRequestChunkSize {
			// Advance chunk window if successful or already at minimum size.
			// (If it failed, we will retry with a smaller chunk size.)
			items = items[chunksize:]
		}
		if err != nil {
			// Failure: Multiplicate Decrease and end Slow Start.
			r.requestChunkSize = len(chunk) / 2
			r.slowStart = false
			if r.requestChunkSize < minRequestChunkSize {
				r.requestChunkSize = minRequestChunkSize
			}
			r.logAddr(RECON, rcvr.RemoteAddr).Errorf("failed to request chunk of %d keys, shrinking: %v", len(chunk), err)
			errCount += 1
			time.Sleep(recoveryRetryDelay * time.Second)
		} else {
			if r.slowStart {
				r.requestChunkSize *= 2
			} else {
				r.requestChunkSize += 1
			}
			if r.requestChunkSize > maxRequestChunkSize {
				r.requestChunkSize = maxRequestChunkSize
			}
			for _, v := range chunk {
				r.seenCache.Add(v.FullKeyHash(), nil)
			}
		}
		if errCount == maxKeyRecoveryAttempts {
			return errors.Errorf("Too many errors (%d) requesting chunks", errCount)
		}
	}
	if errCount > 0 {
		return errors.Errorf("%d errors requesting chunks", errCount)
	}
	return nil
}

func (r *Peer) requestChunk(rcvr *recon.Recover, chunk []cf.Zp) error {
	var remoteAddr string
	remoteAddr, err := rcvr.HkpAddr()
	if err != nil {
		return errors.WithStack(err)
	}
	r.logAddr(RECON, rcvr.RemoteAddr).Debugf("requesting %d keys from %q via hashquery", len(chunk), remoteAddr)
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(chunk))
	if err != nil {
		return errors.WithStack(err)
	}
	for i := range chunk {
		zb := chunk[i].Bytes()
		zb = recon.PadSksElement(zb)
		// Hashquery elements are 16 bytes (length_of(P_SKS)-1)
		zb = zb[:len(zb)-1]
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return errors.WithStack(err)
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	url := fmt.Sprintf("http://%s/pks/hashquery", remoteAddr)
	req, err := http.NewRequest("POST", url, bytes.NewReader(hqBuf.Bytes()))
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Set("Content-type", "sks/hashquery")
	if r.userAgent != "" {
		req.Header.Set("User-agent", r.userAgent)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to query hashes")
	}

	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	bodyBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.WithStack(err)
	}
	body = bytes.NewBuffer(bodyBuf)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("error response from %q: %v", remoteAddr, string(bodyBuf))
	}

	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(body)
	if err != nil {
		return errors.WithStack(err)
	}
	r.logAddr(RECON, rcvr.RemoteAddr).Debugf("hashquery response from %q: %d keys found", remoteAddr, nkeys)
	summary := &upsertResult{}
	defer func() {
		fields := r.logAddr(RECON, rcvr.RemoteAddr)
		fields.Data["inserted"] = summary.inserted
		fields.Data["updated"] = summary.updated
		fields.Data["unchanged"] = summary.unchanged
		fields.Infof("upsert")
	}()
	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(body)
		if err != nil {
			return errors.WithStack(err)
		}
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, body, int64(keyLen))
		if err != nil {
			return errors.WithStack(err)
		}
		r.logAddr(RECON, rcvr.RemoteAddr).Debugf("key# %d: %d bytes", i+1, keyLen)
		// Merge locally
		res, err := r.upsertKeys(rcvr, keyBuf.Bytes())
		if err != nil {
			r.logAddr(RECON, rcvr.RemoteAddr).Errorf("cannot upsert: %v", err)
			continue
		}
		summary.add(res)
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return nil
}

type upsertResult struct {
	inserted  int
	updated   int
	unchanged int
}

func (r *upsertResult) add(r2 *upsertResult) {
	r.inserted += r2.inserted
	r.updated += r2.updated
	r.unchanged += r2.unchanged
}

func (r *Peer) upsertKeys(rcvr *recon.Recover, buf []byte) (*upsertResult, error) {
	kr := openpgp.NewKeyReader(bytes.NewBuffer(buf), r.keyReaderOptions...)
	keys, err := kr.Read()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	result := &upsertResult{}
	for _, key := range keys {
		err := openpgp.DropDuplicates(key)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		keyChange, err := storage.UpsertKey(r.storage, key)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		r.logAddr(RECON, rcvr.RemoteAddr).Debug(keyChange)
		switch keyChange.(type) {
		case storage.KeyAdded:
			result.inserted++
		case storage.KeyReplaced:
			result.updated++
		case storage.KeyNotChanged:
			result.unchanged++
		}
	}
	return result, nil
}
