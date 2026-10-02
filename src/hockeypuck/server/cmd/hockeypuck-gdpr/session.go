/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

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

package main

import (
	"sort"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"hockeypuck/gdpr"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
)

// session holds the storage handles a subcommand works through.
type session struct {
	settings *server.Settings
	storage  storage.Storage
	// peer is an sks.Peer that is instantiated but never started, purely so it
	// receives KeyChange notifications and keeps the reconciliation prefix tree
	// in step. It is nil for read-only work and when -no-ptree is given.
	peer *sks.Peer
}

// openSession dials storage. When ptree is true it also opens the
// reconciliation prefix tree, which is required for erasures to be reflected in
// what this node offers its partners.
func openSession(settings *server.Settings, ptree bool) (*session, error) {
	policy, err := openpgp.NewPolicy(server.PolicyOptions(settings)...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	st, err := server.DialStorage(settings, policy)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s := &session{settings: settings, storage: st}
	if ptree {
		// Instantiate an sks.Peer to handle KeyChange events, but don't Start() it.
		peer, err := sks.NewPeer(st, settings.Conflux.Recon.LevelDB.Path,
			&settings.Conflux.Recon.Settings, nil, "", nil, policy)
		if err != nil {
			st.Close()
			return nil, preconditionf(
				"cannot open the reconciliation prefix tree at %q: %v\n"+
					"The prefix tree is locked for as long as hockeypuck is running. Either stop the\n"+
					"server and re-run, or pass -no-ptree to erase from the database alone and then\n"+
					"%s.\n"+
					"A -dry-run needs no access to the prefix tree at all.",
				settings.Conflux.Recon.LevelDB.Path, err, ptreeRepair)
		}
		peer.Idle()
		s.peer = peer
	}
	return s, nil
}

// Close flushes any queued prefix tree mutations and releases both handles.
func (s *session) Close() {
	if s.peer != nil {
		s.peer.Stop()
	}
	if s.storage != nil {
		if err := s.storage.Close(); err != nil {
			log.Errorf("error closing storage: %v", err)
		}
	}
}

// resolve looks up every target and returns the matching primary key records,
// deduplicated by fingerprint and ordered so that output is reproducible.
//
// A key ID, a subkey fingerprint and a primary key fingerprint all resolve to
// the primary key, which is the unit that can be erased.
func (s *session) resolve(targets []gdpr.Target) ([]*storage.Record, error) {
	byFingerprint := make(map[string]*storage.Record)
	for _, target := range targets {
		records, err := s.resolveOne(target)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot resolve %s", target)
		}
		if len(records) == 0 {
			log.Infof("no keys match %s", target)
			continue
		}
		for _, record := range records {
			byFingerprint[record.Fingerprint] = record
		}
	}
	result := make([]*storage.Record, 0, len(byFingerprint))
	for _, record := range byFingerprint {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Fingerprint < result[j].Fingerprint })
	return result, nil
}

func (s *session) resolveOne(target gdpr.Target) ([]*storage.Record, error) {
	switch target.Kind {
	case gdpr.KindFingerprint, gdpr.KindKeyID:
		fps, err := s.storage.ResolveToFp([]string{target.Value})
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if len(fps) == 0 {
			return nil, nil
		}
		records, err := s.storage.FetchRecordsByFp(fps)
		return records, errors.WithStack(err)
	case gdpr.KindEmail:
		records, err := s.storage.FetchRecordsByIdentity([]string{target.Value})
		if err != nil {
			return nil, errors.WithStack(err)
		}
		s.warnIfTruncated(target, len(records))
		return records, nil
	default:
		records, err := s.storage.FetchRecordsByKeyword(target.Value)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		s.warnIfTruncated(target, len(records))
		return records, nil
	}
}

// warnIfTruncated flags a result set that hit the server's per-query row limit.
// Silently acting on a truncated set would leave part of an erasure request
// unactioned, so the operator needs to know to narrow the search or raise
// requestQueryLimit.
func (s *session) warnIfTruncated(target gdpr.Target, count int) {
	limit := s.settings.OpenPGP.DB.RequestQueryLimit
	if limit > 0 && count >= limit {
		log.Warnf("%s matched the query limit of %d keys; there may be more. "+
			"Narrow the search, or raise hockeypuck.openpgp.db.requestQueryLimit and re-run.",
			target, limit)
	}
}
