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

	pksstorage "hockeypuck/hkp/pks/storage"
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
type fetchRecordsFunc func([]string) ([]*storage.Record, error)
type insertFunc func([]*openpgp.PrimaryKey) (int, int, error)
type replaceFunc func(*openpgp.PrimaryKey) (string, error)
type updateFunc func(*openpgp.PrimaryKey, string, string) error
type deleteFunc func(string) (string, error)
type renotifyAllFunc func() error
type pksInitFunc func(string, time.Time) error
type pksAllFunc func() ([]*pksstorage.Status, error)
type pksUpdateFunc func(*pksstorage.Status) error
type pksRemoveFunc func(string) error
type pksGetFunc func(string) *pksstorage.Status

type Storage struct {
	Recorder
	close_            closeFunc
	matchMD5ToFp      resolverFunc
	resolveToFp       resolverFunc
	matchKeywordToFp  resolverFunc
	modifiedSinceToFp modifiedSinceFunc
	fetchRecordsByFp  fetchRecordsFunc
	insert            insertFunc
	replace           replaceFunc
	update            updateFunc
	delete            deleteFunc
	renotifyAll       renotifyAllFunc
	pksInit           pksInitFunc
	pksAll            pksAllFunc
	pksUpdate         pksUpdateFunc
	pksRemove         pksRemoveFunc
	pksGet            pksGetFunc

	notified []func(storage.KeyChange) error
}

type Option func(*Storage)

func Close(f closeFunc) Option           { return func(m *Storage) { m.close_ = f } }
func MatchMD5ToFp(f resolverFunc) Option { return func(m *Storage) { m.matchMD5ToFp = f } }
func ResolveToFp(f resolverFunc) Option  { return func(m *Storage) { m.resolveToFp = f } }
func MatchKeywordToFp(f resolverFunc) Option {
	return func(m *Storage) { m.matchKeywordToFp = f }
}
func ModifiedSinceToFp(f modifiedSinceFunc) Option {
	return func(m *Storage) { m.modifiedSinceToFp = f }
}
func FetchRecordsByFp(f fetchRecordsFunc) Option {
	return func(m *Storage) { m.fetchRecordsByFp = f }
}
func Insert(f insertFunc) Option           { return func(m *Storage) { m.insert = f } }
func Replace(f replaceFunc) Option         { return func(m *Storage) { m.replace = f } }
func Update(f updateFunc) Option           { return func(m *Storage) { m.update = f } }
func RenotifyAll(f renotifyAllFunc) Option { return func(m *Storage) { m.renotifyAll = f } }
func PksInit(f pksInitFunc) Option         { return func(m *Storage) { m.pksInit = f } }
func PksAll(f pksAllFunc) Option           { return func(m *Storage) { m.pksAll = f } }
func PksUpdate(f pksUpdateFunc) Option     { return func(m *Storage) { m.pksUpdate = f } }
func PksRemove(f pksRemoveFunc) Option     { return func(m *Storage) { m.pksRemove = f } }
func PksGet(f pksGetFunc) Option           { return func(m *Storage) { m.pksGet = f } }

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

// TODO: implement direct lookup by MD5/KeyID/Keyword and deprecate MatchMD5ToFp/ResolveToFp/MatchKeywordToFp (#228)
func (m *Storage) MatchMD5ToFp(s []string) ([]string, error) {
	m.record("MatchMD5", s)
	if m.matchMD5ToFp != nil {
		return m.matchMD5ToFp(s)
	}
	return nil, nil
}
func (m *Storage) ResolveToFp(s []string) ([]string, error) {
	m.record("Resolve", s)
	if m.resolveToFp != nil {
		return m.resolveToFp(s)
	}
	return nil, nil
}
func (m *Storage) MatchKeywordToFp(s []string) ([]string, error) {
	m.record("MatchKeyword", s)
	if m.matchKeywordToFp != nil {
		return m.matchKeywordToFp(s)
	}
	return nil, nil
}
func (m *Storage) ModifiedSinceToFp(t time.Time) ([]string, error) {
	m.record("ModifiedSince", t)
	if m.modifiedSinceToFp != nil {
		return m.modifiedSinceToFp(t)
	}
	return nil, nil
}
func (m *Storage) FetchRecordsByFp(s []string, options ...string) ([]*storage.Record, error) {
	m.record("FetchRecords", s)
	if m.fetchRecordsByFp != nil {
		return m.fetchRecordsByFp(s)
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
func (m *Storage) StartReindex(startDelay, loadDelay, interval int) {
	m.record("StartReindex", startDelay, loadDelay, interval)
}
func (m *Storage) Reload() (int, int, error) {
	m.record("Reload")
	return 0, 0, nil
}
func (m *Storage) PKSInit(addr string, lastSync time.Time) error {
	m.record("PKSInit", addr, lastSync)
	if m.pksInit != nil {
		return m.pksInit(addr, lastSync)
	}
	return nil
}
func (m *Storage) PKSAll() ([]*pksstorage.Status, error) {
	m.record("PKSAll")
	if m.pksAll != nil {
		return m.pksAll()
	}
	return nil, nil
}
func (m *Storage) PKSUpdate(status *pksstorage.Status) error {
	m.record("PKSUpdate")
	if m.pksUpdate != nil {
		return m.pksUpdate(status)
	}
	return nil
}
func (m *Storage) PKSRemove(addr string) error {
	m.record("PKSRemove", addr)
	if m.pksRemove != nil {
		return m.pksRemove(addr)
	}
	return nil
}
func (m *Storage) PKSGet(addr string) (*pksstorage.Status, error) {
	m.record("PKSGet", addr)
	if m.pksGet != nil {
		return m.pksGet(addr), nil
	}
	return nil, nil
}
