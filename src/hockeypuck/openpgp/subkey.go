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

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

type SubKey struct {
	PublicKey
}

// contents implements the packetNode interface for sub-keys.
func (subkey *SubKey) contents() []packetNode {
	result := []packetNode{subkey}
	for _, sig := range subkey.Signatures {
		result = append(result, sig.contents()...)
	}
	return result
}

func ParseSubKey(op *packet.OpaquePacket) (*SubKey, error) {
	var buf bytes.Buffer
	var err error

	if err = op.Serialize(&buf); err != nil {
		return nil, errors.WithStack(err)
	}
	subkey := &SubKey{
		PublicKey: PublicKey{
			Packet: Packet{
				Tag:    op.Tag,
				Packet: buf.Bytes(),
			},
		},
	}

	// Attempt to parse the opaque packet into a public key type.
	err = subkey.parse(op, true)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return subkey, nil
}

func (subkey *SubKey) removeDuplicate(parent packetNode, dup packetNode) error {
	pubkey, ok := parent.(*PrimaryKey)
	if !ok {
		return errors.Errorf("invalid subkey parent: %+v", parent)
	}
	dupSubKey, ok := dup.(*SubKey)
	if !ok {
		return errors.Errorf("invalid subkey duplicate: %+v", dup)
	}

	subkey.Signatures = append(subkey.Signatures, dupSubKey.Signatures...)
	pubkey.SubKeys = subkeySlice(pubkey.SubKeys).without(dupSubKey)
	return nil
}

type subkeySlice []*SubKey

func (ss subkeySlice) without(target *SubKey) []*SubKey {
	var result []*SubKey
	for _, subkey := range ss {
		if subkey != target {
			result = append(result, subkey)
		}
	}
	return result
}

func (subkey *SubKey) SigInfo(pubkey *PrimaryKey) (*SelfSigs, []*Signature) {
	selfSigs := &SelfSigs{target: subkey}
	var otherSigs []*Signature
	for _, sig := range subkey.Signatures {
		// Plausify rather than verify non-self-certifications.
		if !(pubkey.KeyID == sig.IssuerKeyID || pubkey.VFingerprint == sig.IssuerFingerprint) {
			checkSig := &CheckSig{
				PrimaryKey: pubkey,
				Signature:  sig,
				Error:      pubkey.plausifySubKeySig(&subkey.PublicKey, sig),
			}
			if checkSig.Error == nil {
				switch sig.SigType {
				// NB: third-party SubkeyBinding sigs are meaningless
				case packet.SigTypeSubkeyRevocation:
					otherSigs = append(otherSigs, sig)
				}
			}
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifySubKeySelfSig(&subkey.PublicKey, sig),
		}
		if checkSig.Error != nil {
			selfSigs.Errors = append(selfSigs.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case packet.SigTypeSubkeyRevocation:
			selfSigs.Revocations = append(selfSigs.Revocations, checkSig)
		case packet.SigTypeSubkeyBinding:
			selfSigs.Certifications = append(selfSigs.Certifications, checkSig)
		}
	}
	selfSigs.resolve()
	return selfSigs, otherSigs
}
