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

	"hockeypuck/openpgp"
)

var ErrKeyNotFound = fmt.Errorf("key not found")

func IsNotFound(err error) bool {
	return errors.Is(err, ErrKeyNotFound)
}

type Keyring struct {
	*openpgp.PrimaryKey

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
}

// Queryer defines the storage API for search and retrieval of public key material.
type Queryer interface {

	// MatchMD5 returns the matching RFingerprint IDs for the given public key MD5 hashes.
	// The MD5 is calculated using the "SKS method".
	MatchMD5([]string) ([]string, error)

	// Resolve returns the matching RFingerprint IDs for the given public key IDs.
	// Key IDs are typically short (8 hex digits), long (16 digits) or full (40 digits).
	// Matches are made against key IDs and subkey IDs.
	Resolve([]string) ([]string, error)

	// MatchKeyword returns the matching RFingerprint IDs for the given keyword search.
	// The keyword search is storage dependant and results may vary among
	// different implementations.
	MatchKeyword([]string) ([]string, error)

	// ModifiedSince returns matching RFingerprint IDs for keyrings modified
	// since the given time.
	ModifiedSince(time.Time) ([]string, error)

	// FetchKeys returns the public key material matching the given RFingerprint slice.
	FetchKeys([]string) ([]*openpgp.PrimaryKey, error)

	// FetchKeyrings returns the keyring records matching the given RFingerprint slice.
	FetchKeyrings([]string) ([]*Keyring, error)
}

// Inserter defines the storage API for inserting key material.
type Inserter interface {

	// Insert inserts new public keys if they are not already stored. If they
	// are, then nothing is changed.
	// Returns (u, n, err) where
	// <u>   is the number of keys updated, if any. When a PrimaryKey in the input is
	//       already in the DB (same rfingerprint), but has a different md5 (e.g., because
	//       of a non-overlapping set of signatures), the keys are merged together. If
	//       signatures, attributes etc are a subset of those of the key in the DB, the
	//       input key is considered a duplicate and there is no update.
	// <n>   is the number of keys inserted in the DB, if any; keys inserted had no key
	//       of matching rfingerprint in the DB before.
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

type InsertError struct {
	Duplicates []*openpgp.PrimaryKey
	Errors     []error
}

func (err InsertError) Error() string {
	return fmt.Sprintf("%d duplicates, %d errors", len(err.Duplicates), len(err.Errors))
}

func Duplicates(err error) []*openpgp.PrimaryKey {
	insertErr, ok := err.(InsertError)
	if !ok {
		return nil
	}
	return insertErr.Duplicates
}

func firstMatch(results []*openpgp.PrimaryKey, match string) (*openpgp.PrimaryKey, error) {
	for _, key := range results {
		if key.RFingerprint == match {
			return key, nil
		}
	}
	return nil, ErrKeyNotFound
}

func UpsertKey(storage Storage, pubkey *openpgp.PrimaryKey) (kc KeyChange, err error) {
	var lastKey *openpgp.PrimaryKey
	lastKeys, err := storage.FetchKeys([]string{pubkey.RFingerprint})
	if err == nil {
		// match primary fingerprint -- someone might have reused a subkey somewhere
		lastKey, err = firstMatch(lastKeys, pubkey.RFingerprint)
	}
	if IsNotFound(err) {
		_, _, err = storage.Insert([]*openpgp.PrimaryKey{pubkey})
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return KeyAdded{ID: pubkey.KeyID(), Digest: pubkey.MD5}, nil
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	if pubkey.UUID != lastKey.UUID {
		return nil, errors.Errorf("upsert key %q lookup failed, found mismatch %q", pubkey.UUID, lastKey.UUID)
	}
	lastID := lastKey.KeyID()
	lastMD5 := lastKey.MD5
	err = openpgp.Merge(lastKey, pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if lastMD5 != lastKey.MD5 {
		err = storage.Update(lastKey, lastID, lastMD5)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return KeyReplaced{OldID: lastID, OldDigest: lastMD5, NewID: lastKey.KeyID(), NewDigest: lastKey.MD5}, nil
	}
	return KeyNotChanged{ID: lastID, Digest: lastMD5}, nil
}

func ReplaceKey(storage Storage, pubkey *openpgp.PrimaryKey) (KeyChange, error) {
	lastMD5, err := storage.Replace(pubkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if lastMD5 != "" {
		return KeyReplaced{OldID: pubkey.KeyID(), OldDigest: lastMD5, NewID: pubkey.KeyID(), NewDigest: pubkey.MD5}, nil
	}
	return KeyAdded{ID: pubkey.KeyID(), Digest: pubkey.MD5}, nil
}

func DeleteKey(storage Storage, fp string) (KeyChange, error) {
	lastMD5, err := storage.Delete(fp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return KeyRemoved{ID: fp, Digest: lastMD5}, nil
}
