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

package mock

import (
	"time"

	"hockeypuck/openpgp"

	"hockeypuck/hkp/storage"
)

type MethodCall struct {
	Name string
	Args []interface{}
}

type Recorder struct {
	Calls []MethodCall
}

func (m *Recorder) record(name string, args ...interface{}) {
	m.Calls = append(m.Calls, MethodCall{Name: name, Args: args})
}

func (m *Recorder) MethodCount(name string) int {
	var n int
	for _, call := range m.Calls {
		if name == call.Name {
			n++
		}
	}
	return n
}

type closeFunc func() error
type resolverFunc func([]string) ([]string, error)
type modifiedSinceFunc func(time.Time) ([]string, error)
type fetchKeysFunc func([]string) ([]*openpgp.PrimaryKey, error)
type fetchKeyringsFunc func([]string) ([]*storage.Keyring, error)
type insertFunc func([]*openpgp.PrimaryKey) (int, int, error)
type replaceFunc func(*openpgp.PrimaryKey) (string, error)
type updateFunc func(*openpgp.PrimaryKey, string, string) error
type deleteFunc func(string) (string, error)
type renotifyAllFunc func() error

type Storage struct {
	Recorder
	close_        closeFunc
	matchMD5      resolverFunc
	resolve       resolverFunc
	matchKeyword  resolverFunc
	modifiedSince modifiedSinceFunc
	fetchKeys     fetchKeysFunc
	fetchKeyrings fetchKeyringsFunc
	insert        insertFunc
	replace       replaceFunc
	update        updateFunc
	delete        deleteFunc
	renotifyAll   renotifyAllFunc

	notified []func(storage.KeyChange) error
}

type Option func(*Storage)

func Close(f closeFunc) Option       { return func(m *Storage) { m.close_ = f } }
func MatchMD5(f resolverFunc) Option { return func(m *Storage) { m.matchMD5 = f } }
func Resolve(f resolverFunc) Option  { return func(m *Storage) { m.resolve = f } }
func MatchKeyword(f resolverFunc) Option {
	return func(m *Storage) { m.matchKeyword = f }
}
func ModifiedSince(f modifiedSinceFunc) Option {
	return func(m *Storage) { m.modifiedSince = f }
}
func FetchKeys(f fetchKeysFunc) Option { return func(m *Storage) { m.fetchKeys = f } }
func FetchKeyrings(f fetchKeyringsFunc) Option {
	return func(m *Storage) { m.fetchKeyrings = f }
}
func Insert(f insertFunc) Option           { return func(m *Storage) { m.insert = f } }
func Replace(f replaceFunc) Option         { return func(m *Storage) { m.replace = f } }
func Update(f updateFunc) Option           { return func(m *Storage) { m.update = f } }
func RenotifyAll(f renotifyAllFunc) Option { return func(m *Storage) { m.renotifyAll = f } }

func NewStorage(options ...Option) *Storage {
	m := &Storage{}
	for _, option := range options {
		option(m)
	}
	return m
}

func (m *Storage) Close() error {
	m.record("Close")
	if m.close_ != nil {
		return m.close_()
	}
	return nil
}
func (m *Storage) MatchMD5(s []string) ([]string, error) {
	m.record("MatchMD5", s)
	if m.matchMD5 != nil {
		return m.matchMD5(s)
	}
	return nil, nil
}
func (m *Storage) Resolve(s []string) ([]string, error) {
	m.record("Resolve", s)
	if m.resolve != nil {
		return m.resolve(s)
	}
	return nil, nil
}
func (m *Storage) MatchKeyword(s []string) ([]string, error) {
	m.record("MatchKeyword", s)
	if m.matchKeyword != nil {
		return m.matchKeyword(s)
	}
	return nil, nil
}
func (m *Storage) ModifiedSince(t time.Time) ([]string, error) {
	m.record("ModifiedSince", t)
	if m.modifiedSince != nil {
		return m.modifiedSince(t)
	}
	return nil, nil
}
func (m *Storage) FetchKeys(s []string, options ...string) ([]*openpgp.PrimaryKey, error) {
	m.record("FetchKeys", s)
	if m.fetchKeys != nil {
		return m.fetchKeys(s)
	}
	return nil, nil
}
func (m *Storage) FetchKeyrings(s []string, options ...string) ([]*storage.Keyring, error) {
	m.record("FetchKeyrings", s)
	if m.fetchKeyrings != nil {
		return m.fetchKeyrings(s)
	}
	return nil, nil
}
func (m *Storage) Insert(keys []*openpgp.PrimaryKey) (int, int, error) {
	m.record("Insert", keys)
	if m.insert != nil {
		return m.insert(keys)
	}
	return 0, 0, nil
}
func (m *Storage) Replace(key *openpgp.PrimaryKey) (string, error) {
	m.record("Replace", key)
	if m.replace != nil {
		return m.replace(key)
	}
	return "", nil
}
func (m *Storage) Delete(fp string) (string, error) {
	m.record("Delete", fp)
	if m.delete != nil {
		return m.delete(fp)
	}
	return "", nil
}
func (m *Storage) Update(key *openpgp.PrimaryKey, lastID string, lastMD5 string) error {
	m.record("Update", key)
	if m.update != nil {
		return m.update(key, lastID, lastMD5)
	}
	return nil
}
func (m *Storage) Subscribe(f func(storage.KeyChange) error) {
	m.notified = append(m.notified, f)
}
func (m *Storage) Notify(change storage.KeyChange) error {
	for _, cb := range m.notified {
		err := cb(change)
		if err != nil {
			return err
		}
	}
	return nil
}
func (m *Storage) RenotifyAll() error {
	m.record("RenotifyAll")
	if m.renotifyAll != nil {
		return m.renotifyAll()
	}
	return nil
}
