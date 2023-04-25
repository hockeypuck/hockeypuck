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
	"strings"

	"github.com/pkg/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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
	for _, p := range subkey.Others {
		result = append(result, p.contents()...)
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
	parseErr := subkey.parse(op, true)
	if parseErr != nil {
		subkey.setUnsupported(op)
	} else {
		subkey.Parsed = true
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
	subkey.Others = append(subkey.Others, dupSubKey.Others...)
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
		// Skip non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			otherSigs = append(otherSigs, sig)
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifyPublicKeySelfSig(&subkey.PublicKey, sig),
		}
		if checkSig.Error != nil {
			selfSigs.Errors = append(selfSigs.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case 0x28: // packet.SigTypeSubKeyRevocation
			selfSigs.Revocations = append(selfSigs.Revocations, checkSig)
		case 0x18: // packet.SigTypeSubKeyBinding
			selfSigs.Certifications = append(selfSigs.Certifications, checkSig)
			if !sig.Expiration.IsZero() {
				selfSigs.Expirations = append(selfSigs.Expirations, checkSig)
			}
		}
	}
	selfSigs.resolve()
	return selfSigs, otherSigs
}
