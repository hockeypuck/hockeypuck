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
	"encoding/json"
	"os"
	"sync"
	"time"

	"hockeypuck/hkp/storage"

	"github.com/pkg/errors"
)

type LoadStat struct {
	Inserted       int
	Updated        int
	Removed        int
	InsertedJitter int
	RemovedJitter  int
}

type LoadStatMap map[time.Time]*LoadStat

func (m LoadStatMap) MarshalJSON() ([]byte, error) {
	doc := map[string]*LoadStat{}
	for k, v := range m {
		doc[k.Format(time.RFC3339)] = v
	}
	return json.Marshal(&doc)
}

func (m LoadStatMap) UnmarshalJSON(b []byte) error {
	doc := map[string]*LoadStat{}
	err := json.Unmarshal(b, &doc)
	if err != nil {
		return errors.WithStack(err)
	}
	for k, v := range doc {
		t, err := time.Parse(time.RFC3339, k)
		if err != nil {
			return errors.WithStack(err)
		}
		m[t] = v
	}
	return nil
}

func (m LoadStatMap) update(t time.Time, kc storage.KeyChange) {
	ls, ok := m[t]
	if !ok {
		ls = &LoadStat{}
		m[t] = ls
	}
	switch kc.(type) {
	case storage.KeyAdded:
		ls.Inserted++
	case storage.KeyRemoved:
		ls.Removed++
	case storage.KeyAddedJitter:
		ls.InsertedJitter++
	case storage.KeyRemovedJitter:
		ls.RemovedJitter++
	case storage.KeyReplaced:
		ls.Updated++
	}
}

type Stats struct {
	Total int

	mu     sync.Mutex
	Hourly LoadStatMap
	Daily  LoadStatMap
}

func NewStats() *Stats {
	return &Stats{
		Hourly: LoadStatMap{},
		Daily:  LoadStatMap{},
	}
}

// reset resets statistics. The caller must hold s.mu.
func (s *Stats) reset() {
	s.Total = 0
	s.Hourly = LoadStatMap{}
	s.Daily = LoadStatMap{}
}

func (s *Stats) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()

	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	lastWeek := time.Now().UTC().Add(-24 * 7 * time.Hour)
	for k := range s.Hourly {
		if k.Before(yesterday) {
			delete(s.Hourly, k)
		}
	}
	for k := range s.Daily {
		if k.Before(lastWeek) {
			delete(s.Daily, k)
		}
	}
}

func (s *Stats) Update(kc storage.KeyChange) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Hourly.update(time.Now().UTC().Truncate(time.Hour), kc)
	s.Daily.update(time.Now().UTC().Truncate(24*time.Hour), kc)
}

func (s *Stats) clone() *Stats {
	s.mu.Lock()
	defer s.mu.Unlock()

	clone := NewStats()
	clone.Total = s.Total
	for k, v := range s.Hourly {
		clone.Hourly[k] = v
	}
	for k, v := range s.Daily {
		clone.Daily[k] = v
	}
	return clone
}

func (s *Stats) ReadFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		s.reset()
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "cannot open stats %q", path)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(s); err != nil {
		return errors.Wrapf(err, "cannot decode stats")
	}
	return nil
}

func (s *Stats) WriteFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "cannot open stats %q", path)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(s); err != nil {
		return errors.Wrapf(err, "cannot encode stats")
	}
	return nil
}
