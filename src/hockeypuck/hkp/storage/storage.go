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

package storage

import (
	"fmt"
	"io"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	pksstorage "hockeypuck/hkp/pks/storage"
	"hockeypuck/openpgp"
)

var ErrKeyNotFound = fmt.Errorf("key not found")
var ErrDigestMismatch = fmt.Errorf("digest mismatch")
var AutoPreen = "AutoPreen"

func IsNotFound(err error) bool {
	return errors.Is(err, ErrKeyNotFound)
}

const (
	DefaultDBDriver                  = "postgres-jsonb"
	DefaultDBDSN                     = "database=hockeypuck host=/var/run/postgresql port=5432 sslmode=disable"
	DefaultDBReindexOnStartup        = true
	DefaultDBReindexStartupDelaySecs = 60 * 5
	DefaultDBReindexLoadDelaySecs    = 60 * 60 * 24
	DefaultDBReindexIntervalSecs     = 60 * 60 * 24 * 7
	DefaultDBRequestQueryLimit       = 100
)

// DBConfig represents the database configuration.
type DBConfig struct {
	Driver                  string `toml:"driver"`
	DSN                     string `toml:"dsn"`
	ReindexOnStartup        bool   `toml:"reindexOnStartup"`
	ReindexStartupDelaySecs int    `toml:"reindexStartupDelaySecs"`
	ReindexLoadDelaySecs    int    `toml:"reindexLoadDelaySecs"`
	ReindexIntervalSecs     int    `toml:"reindexIntervalSecs"`
	RequestQueryLimit       int    `toml:"requestQueryLimit"`
}

func DefaultDBConfig() DBConfig {
	return DBConfig{
		Driver:                  DefaultDBDriver,
		DSN:                     DefaultDBDSN,
		ReindexOnStartup:        DefaultDBReindexOnStartup,
		ReindexStartupDelaySecs: DefaultDBReindexStartupDelaySecs,
		ReindexLoadDelaySecs:    DefaultDBReindexLoadDelaySecs,
		ReindexIntervalSecs:     DefaultDBReindexIntervalSecs,
		RequestQueryLimit:       DefaultDBRequestQueryLimit,
	}
}

// Record is a PrimaryKey annotated with selected fields returned by the DB layer.
// It is not a faithful representation of the underlying DB schema.
type Record struct {
	*openpgp.PrimaryKey

	Fingerprint string
	MD5         string

	CTime time.Time
	MTime time.Time
}

// Storage defines the API that is needed to implement a complete storage
// backend for an HKP service.
type Storage interface {
	io.Closer
	Queryer
	Updater
	Deleter
	Notifier
	Reindexer
	Reloader
	pksstorage.Storage
}

// Queryer defines the storage API for search and retrieval of public key material.
// TODO: implement direct lookup by MD5/KeyID/Keyword and deprecate MatchMD5ToFp/ResolveToFp/MatchKeywordToFp (#228)
type Queryer interface {

	// MatchMD5ToFp returns the matching Fingerprint IDs for the given public key MD5 hashes.
	// The MD5 is calculated using the "SKS method".
	MatchMD5ToFp([]string) ([]string, error)

	// ResolveToFp returns the matching Fingerprint IDs for the given public key IDs.
	// Key IDs are typically short (8 hex digits), long (16 digits) or full (40 digits).
	// Matches are made against key IDs and subkey IDs.
	ResolveToFp([]string) ([]string, error)

	// MatchKeywordToFp returns the matching Fingerprint IDs for the given keyword search.
	// The keyword search is storage dependant and results may vary among
	// different implementations.
	MatchKeywordToFp([]string) ([]string, error)

	// ModifiedSinceToFp returns matching Fingerprint IDs for records modified
	// since the given time.
	ModifiedSinceToFp(time.Time) ([]string, error)

	// FetchRecordsByFp returns the database records matching the given Fingerprint slice.
	// Beware that PrimaryKey fields MAY be nil, and MUST be tested for by the caller.
	FetchRecordsByFp([]string, ...string) ([]*Record, error)
}

// Inserter defines the storage API for inserting key material.
type Inserter interface {

	// Insert inserts new public keys if they are not already stored. If they
	// are, then nothing is changed.
	// Returns (u, n, err) where
	// <u>   is the number of keys updated, if any. When a PrimaryKey in the input is
	//       already in the DB (same fingerprint), but has a different md5 (e.g., because
	//       of a non-overlapping set of signatures), the keys are merged together. If
	//       signatures, attributes etc are a subset of those of the key in the DB, the
	//       input key is considered a duplicate and there is no update.
	// <n>   is the number of keys inserted in the DB, if any; keys inserted had no key
	//       of matching fingerprint in the DB before.
	// <err> are any errors that have occurred during insertion, or nil if none.
	Insert([]*openpgp.PrimaryKey) (int, int, error)
}

// Updater defines the storage API for writing key material.
type Updater interface {
	Inserter

	// Update updates the stored PrimaryKey with the given contents, if the current
	// contents of the key in storage matches the given digest. If it does not
	// match, the update should be retried again later.
	Update(pubkey *openpgp.PrimaryKey, priorID string, priorMD5 string) error

	// Replace unconditionally replaces any existing Primary key with the given
	// contents, adding it if it did not exist.
	Replace(pubkey *openpgp.PrimaryKey) (string, error)
}

type Deleter interface {
	// Delete unconditionally deletes any existing Primary key with the given
	// fingerprint.
	Delete(fp string) (string, error)
}

type Notifier interface {
	// Subscribe registers a key change callback function.
	Subscribe(func(KeyChange) error)

	// Notify invokes all registered callbacks with a key change notification.
	Notify(change KeyChange) error

	// RenotifyAll() invokes all registered callbacks with KeyAdded notifications
	// for each key in the Storage.
	RenotifyAll() error
}

type KeyChange interface {
	InsertDigests() []string
	RemoveDigests() []string
}

type KeyAdded struct {
	ID     string
	Digest string
}

func (ka KeyAdded) InsertDigests() []string {
	return []string{ka.Digest}
}

func (ka KeyAdded) RemoveDigests() []string {
	return nil
}

func (ka KeyAdded) String() string {
	return fmt.Sprintf("key 0x%s with hash %s added", ka.ID, ka.Digest)
}

type KeyAddedJitter struct {
	ID     string
	Digest string
}

func (ka KeyAddedJitter) InsertDigests() []string {
	return []string{ka.Digest}
}

func (ka KeyAddedJitter) RemoveDigests() []string {
	return nil
}

func (ka KeyAddedJitter) String() string {
	return fmt.Sprintf("key 0x%s with hash %s force-added (jitter)", ka.ID, ka.Digest)
}

type KeyReplaced struct {
	OldID     string
	OldDigest string
	NewID     string
	NewDigest string
}

func (kr KeyReplaced) InsertDigests() []string {
	return []string{kr.NewDigest}
}

func (kr KeyReplaced) RemoveDigests() []string {
	return []string{kr.OldDigest}
}

func (kr KeyReplaced) String() string {
	return fmt.Sprintf("key 0x%s with hash %s replaced key 0x%s with hash %s", kr.NewID, kr.NewDigest, kr.OldID, kr.OldDigest)
}

type KeyNotChanged struct {
	ID     string
	Digest string
}

func (knc KeyNotChanged) InsertDigests() []string { return nil }

func (knc KeyNotChanged) RemoveDigests() []string { return nil }

func (knc KeyNotChanged) String() string {
	return fmt.Sprintf("key 0x%s with hash %s not changed", knc.ID, knc.Digest)
}

type KeyRemoved struct {
	ID     string
	Digest string
}

func (ka KeyRemoved) InsertDigests() []string {
	return nil
}

func (ka KeyRemoved) RemoveDigests() []string {
	return []string{ka.Digest}
}

func (ka KeyRemoved) String() string {
	return fmt.Sprintf("key 0x%s with hash %s removed", ka.ID, ka.Digest)
}

type KeyRemovedJitter struct {
	ID     string
	Digest string
}

func (ka KeyRemovedJitter) InsertDigests() []string {
	return nil
}

func (ka KeyRemovedJitter) RemoveDigests() []string {
	return []string{ka.Digest}
}

func (ka KeyRemovedJitter) String() string {
	return fmt.Sprintf("key 0x%s with hash %s force-removed (jitter)", ka.ID, ka.Digest)
}

type KeysBulkUpdated struct {
	Inserted []string
	Removed  []string
}

func (ka KeysBulkUpdated) InsertDigests() []string {
	return ka.Inserted
}

func (ka KeysBulkUpdated) RemoveDigests() []string {
	return ka.Removed
}

func (ka KeysBulkUpdated) String() string {
	return fmt.Sprintf("%d hashes inserted and %d hashes removed in bulk", len(ka.Inserted), len(ka.Removed))
}

type InsertError struct {
	Duplicates []*openpgp.PrimaryKey
	Errors     []error
	Warnings   []error
}

func (err InsertError) Error() string {
	return fmt.Sprintf("%d duplicates, %d errors, %d warnings", len(err.Duplicates), len(err.Errors), len(err.Warnings))
}

func Duplicates(err error) []*openpgp.PrimaryKey {
	insertErr, ok := err.(InsertError)
	if !ok {
		return nil
	}
	return insertErr.Duplicates
}

func firstMatch(records []*Record, match string) (*Record, error) {
	for _, record := range records {
		if record.Fingerprint == match {
			return record, nil
		}
	}
	return nil, ErrKeyNotFound
}

func UpsertKey(storage Storage, pubkey *openpgp.PrimaryKey) (kc KeyChange, err error) {
	var record *Record
	records, err := storage.FetchRecordsByFp([]string{pubkey.Fingerprint})
	if err == nil {
		// match primary fingerprint -- someone might have reused a subkey somewhere
		record, err = firstMatch(records, pubkey.Fingerprint)
	}
	if IsNotFound(err) {
		_, _, err = storage.Insert([]*openpgp.PrimaryKey{pubkey})
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return KeyAdded{ID: pubkey.KeyID, Digest: pubkey.MD5}, nil
	} else if err != nil {
		return nil, errors.WithStack(err)
	}
	// TDOO: do we need to handle other errors?
	if record.PrimaryKey == nil {
		// The copy on disk has evaporated; replace it instead
		log.Debugf("evaporated key fp=%v during upsert; replacing", pubkey.Fingerprint)
		kc, err := ReplaceKey(storage, pubkey)
		return kc, err
	}

	if pubkey.UUID != record.UUID {
		return nil, errors.Errorf("upsert key %q lookup failed, found mismatch %q", pubkey.UUID, record.UUID)
	}
	lastID := record.KeyID
	lastMD5 := record.MD5
	err = openpgp.Merge(record.PrimaryKey, pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if lastMD5 != record.PrimaryKey.MD5 {
		err = storage.Update(record.PrimaryKey, lastID, lastMD5)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: record.KeyID, NewDigest: record.PrimaryKey.MD5}, nil
	}
	return KeyNotChanged{ID: lastID, Digest: lastMD5}, nil
}

func ReplaceKey(storage Storage, pubkey *openpgp.PrimaryKey) (KeyChange, error) {
	lastMD5, err := storage.Replace(pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if lastMD5 != "" {
		return KeyReplaced{OldID: pubkey.KeyID, OldDigest: lastMD5, NewID: pubkey.KeyID, NewDigest: pubkey.MD5}, nil
	}
	return KeyAdded{ID: pubkey.KeyID, Digest: pubkey.MD5}, nil
}

func DeleteKey(storage Storage, fp string) (KeyChange, error) {
	lastMD5, err := storage.Delete(fp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return KeyRemoved{ID: fp, Digest: lastMD5}, nil
}

type Reindexer interface {
	// Reindex is a goroutine that reindexes the keydb in-place, oldest-modified items first.
	StartReindex(reindexStartupDelaySecs, reindexLoadDelaySecs, reindexIntervalSecs int)
}

type Reloader interface {
	// Reload is a function that reloads the keydb in-place, oldest-created items first.
	Reload() (totalUpdated, totalDeleted int, err error)
}
