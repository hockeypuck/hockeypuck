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

package openpgp

import (
	"bytes"
	"crypto/rand"
	"encoding/ascii85"
	"fmt"
	"io"
	"log"
	"time"

	"code.google.com/p/go.crypto/openpgp/armor"
	"github.com/jmoiron/sqlx"
	"github.com/juju/errors"

	. "github.com/hockeypuck/hockeypuck/errors"
	"github.com/hockeypuck/hockeypuck/hkp"
)

// KeyChangeChan channels are used for sending and receiving
// key changes resulting from adding a new key or merging
// updates into an existing one.
type KeyChangeChan chan *KeyChange

// Add responds to /pks/add HKP requests.
func (w *Worker) Add(a *hkp.Add) {
	// Parse armored keytext
	var changes []*KeyChange
	var readErrors []*ReadKeyResult
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(a.Keytext))
	if err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	for readKey := range ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			readErrors = append(readErrors, readKey)
		} else {
			change := w.UpsertKey(readKey.Pubkey)
			if change.Error != nil {
				log.Printf("Error updating key [%s]: %v\n", readKey.Pubkey.Fingerprint(),
					change.Error)
			} else {
				go w.notifyChange(change)
			}
			changes = append(changes, change)
		}
	}
	a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
}

// recoverKey responds to public keys recovered from the recon
// protocol.
func (w *Worker) recoverKey(rk *RecoverKey) hkp.Response {
	resp := &RecoverKeyResponse{}
	// Attempt to parse and upsert key
	var pubkeys []*Pubkey
	var err error
	for readKey := range ReadKeys(bytes.NewBuffer(rk.Keytext)) {
		if readKey.Error != nil {
			err = readKey.Error
		} else {
			pubkeys = append(pubkeys, readKey.Pubkey)
		}
	}
	if err != nil {
		return &ErrorResponse{err}
	}
	if len(pubkeys) == 0 {
		return &ErrorResponse{ErrKeyNotFound}
	} else if len(pubkeys) > 1 {
		return &ErrorResponse{ErrTooManyResponses}
	}
	resp.Change = w.UpsertKey(pubkeys[0])
	if resp.Change.Error != nil {
		return &ErrorResponse{resp.Change.Error}
	}
	w.notifyChange(resp.Change)
	return resp
}

// ErrSubKeyChanges is an error occurring when attempting to subscribe
// to KeyChange messages on a worker that already has a subscriber.
var ErrSubKeyChanges error = fmt.Errorf("Worker already has a key change subscriber")

// SubKeyChanges subscribes a KeyChange channel to receive updates on
// any keys added or updated by this worker.
func (w *Worker) SubKeyChanges(keyChanges KeyChangeChan) error {
	if w.keyChanges != nil {
		return ErrSubKeyChanges
	}
	w.keyChanges = keyChanges
	return nil
}

// notifyChange is used by the worker to broadcast key changes
// to a subscriber, if any.
func (w *Worker) notifyChange(keyChange *KeyChange) {
	if w.keyChanges != nil {
		w.keyChanges <- keyChange
	}
}

// KeyChangeType identifies the type of change that a worker has
// made to a public key.
type KeyChangeType int

const (
	// KeyChangeInvalid indicates that the attempted key change information
	// does not describe an expected, valid event.
	KeyChangeInvalid KeyChangeType = iota
	// KeyNotChanged indicates that a request to update an existing public key
	// did not result in any change or addition of new key material.
	KeyNotChanged KeyChangeType = iota
	// KeyAdded indicates a new key was added to the database.
	KeyAdded KeyChangeType = iota
	// KeyModified indicates that an existing key was updated with new information.
	KeyModified KeyChangeType = iota
)

// KeyChange describes the change made to a public key resulting from
// a /pks/add HKP request.
type KeyChange struct {
	// Fingerprint is the public key fingerprint
	Fingerprint string
	// CurrentMd5 contains the new digest of the key (SKS compatible).
	CurrentMd5 string
	// PreviousMd5 contains the digest of the key prior to update, if any (SKS compatible).
	PreviousMd5 string
	// CurrentSha256 contains the new digest of the key.
	CurrentSha256 string
	// PreviousSha256 contains the digest of the key prior to update, if any.
	PreviousSha256 string
	// Error captures the error that prevented the change from occurring, otherwise nil.
	Error error
	// Type indicates the type of key change that occurred, as indicated by KeyChangeType.
	Type KeyChangeType
}

// String represents the key change event as a string for diagnostic purposes.
func (kc *KeyChange) String() string {
	w := bytes.NewBuffer(nil)
	var msg string
	switch kc.Type {
	case KeyChangeInvalid:
		msg = fmt.Sprintf("Invalid key change for [%s] could not be processed",
			kc.Fingerprint)
	case KeyAdded:
		msg = fmt.Sprintf("Add key %s, [%s..]", kc.Fingerprint, kc.CurrentSha256[:8])
	case KeyModified:
		msg = fmt.Sprintf("Modify key %s, [%s.. -> %s..]", kc.Fingerprint,
			kc.PreviousSha256[:8], kc.CurrentSha256[:8])
	case KeyNotChanged:
		msg = fmt.Sprintf("No change in key %s", kc.Fingerprint)
	}
	w.Write([]byte(msg))
	if kc.Error != nil {
		w.Write([]byte(fmt.Sprintf(": Error: %v", kc.Error)))
	}
	return w.String()
}

func (change *KeyChange) calcType() KeyChangeType {
	if change.CurrentSha256 == "" {
		return KeyChangeInvalid
	} else if change.PreviousSha256 == "" {
		return KeyAdded
	} else if change.PreviousSha256 == change.CurrentSha256 {
		return KeyNotChanged
	}
	return KeyModified
}

func (w *Worker) UpsertKey(key *Pubkey) *KeyChange {
	change := &KeyChange{
		Fingerprint:   key.Fingerprint(),
		Type:          KeyChangeInvalid,
		CurrentMd5:    key.Md5,
		CurrentSha256: key.Sha256}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == ErrKeyNotFound {
		change.Type = KeyAdded
	} else if err != nil {
		change.Error = err
		return change
	} else {
		change.PreviousMd5 = lastKey.Md5
		change.PreviousSha256 = lastKey.Sha256
		MergeKey(lastKey, key)
		change.CurrentMd5 = lastKey.Md5
		change.CurrentSha256 = lastKey.Sha256
		if change.PreviousMd5 == change.CurrentMd5 && change.PreviousSha256 == change.CurrentSha256 {
			change.Type = KeyNotChanged
		} else {
			change.Type = KeyModified
		}
	}
	if change.CurrentSha256 == "" {
		change.Type = KeyChangeInvalid
	}
	switch change.Type {
	case KeyModified:
		lastKey.Mtime = time.Now()
		if change.Error = w.UpdateKey(lastKey); change.Error == nil {
			w.UpdateKeyRelations(lastKey)
		} else {
			log.Println(change.Error)
		}
	case KeyAdded:
		key.Ctime = time.Now()
		key.Mtime = key.Ctime
		if change.Error = w.InsertKey(key); change.Error == nil {
			w.UpdateKeyRelations(key)
		} else {
			log.Println(change.Error)
		}
	}
	if change.Type != KeyNotChanged {
		log.Println(change)
	}
	return change
}

// UpdateKey updates the database to the contents of the given public key.
func (w *Worker) UpdateKey(pubkey *Pubkey) error {
	err := w.InsertKey(pubkey)
	if err != nil {
		return err
	}

	tx, err := w.Begin()
	if err != nil {
		return err
	}

	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) (err error) {
		switch r := rec.(type) {
		case *Pubkey:
		 	_, err := Query().UpdatePubkey(tx, r)
			if err != nil {
				return err
			}
			signable = r
		case *Subkey:
			_, err := Query().UpdateSubkey(tx, r)
			if err != nil {
				return err
			}
			signable = r
		case *UserId:
			_, err := Query().UpdateUserId(tx, r)
			if err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			_, err := Query().UpdateUserAttribute(tx, r)
			if err != nil {
				return err
			}
			signable = r
		case *Signature:
			_, err := Query().UpdateSignature(tx, r)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		tx.Rollback()
	} else {
		return tx.Commit()
	}
	return nil
}

// UUID_LEN is the size of unique primary keys generated for certain
// database records. The length is chosen to approximate 256 bits of security.
// When Ascii85 encoding is used, log(2**256, 85) = 39.9413926456896
const UUID_LEN = 40

// NewUuid creates a new randomly generated, secure unique identifier.
func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := ascii85.NewEncoder(buf)
	n, err := io.CopyN(enc, rand.Reader, UUID_LEN)
	if err != nil {
		return "", err
	}
	if n < UUID_LEN {
		return "", fmt.Errorf("Failed to generate UUID")
	}
	return string(buf.Bytes()), nil
}

// UpdateKeyRelations updates the foreign-key relations between
// matching public key packet records to represent the state of the
// given public key.
func (w *Worker) UpdateKeyRelations(pubkey *Pubkey) error {
	tx, err := w.Begin()
	if err != nil {
		return err
	}

	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			signable = r
		case *Subkey:
			signable = r
		case *UserId:
			return w.updatePrimaryUid(tx, pubkey, r)
			signable = r
		case *UserAttribute:
			return w.updatePrimaryUat(tx, pubkey, r)
			signable = r
		case *Signature:
			switch s := signable.(type) {
			case *Pubkey:
				return w.updatePubkeyRevsig(tx, s, r)
			case *Subkey:
				return w.updateSubkeyRevsig(tx, s, r)
			case *UserId:
				return w.updateUidRevsig(tx, s, r)
			case *UserAttribute:
				return w.updateUatRevsig(tx, s, r)
			}
		}
		return nil
	})
	if err != nil {
		err = errors.Wrap(err, tx.Rollback())
	} else {
		return tx.Commit()
	}
	return err
}

func (w *Worker) updatePubkeyRevsig(tx *sqlx.Tx, pubkey *Pubkey, r *Signature) error {
	if pubkey.RevSigDigest.String == r.ScopedDigest {
		_, err := Query().UpdatePubkeyRevsig(tx, pubkey, r)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updateSubkeyRevsig(tx *sqlx.Tx, subkey *Subkey, r *Signature) error {
	if subkey.RevSigDigest.String == r.ScopedDigest {
		_, err := Query().UpdateSubkeyRevsig(tx, subkey, r)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updateUidRevsig(tx *sqlx.Tx, uid *UserId, r *Signature) error {
	if uid.RevSigDigest.String == r.ScopedDigest {
		_, err := Query().UpdateUidRevsig(tx, uid, r)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updateUatRevsig(tx *sqlx.Tx, uat *UserAttribute, r *Signature) error {
	if uat.RevSigDigest.String == r.ScopedDigest {
		_, err := Query().UpdateUatRevsig(tx, uat, r)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updatePrimaryUid(tx *sqlx.Tx, pubkey *Pubkey, r *UserId) error {
	if pubkey.PrimaryUid.String == r.ScopedDigest {
		if _, err := Execv(tx, `
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updatePrimaryUat(tx *sqlx.Tx, pubkey *Pubkey, r *UserAttribute) error {
	if pubkey.PrimaryUat.String == r.ScopedDigest {
		if _, err := Execv(tx, `
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}
