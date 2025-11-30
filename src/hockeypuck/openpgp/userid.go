/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  Casey Marshall and the Hockeypuck Contributors

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

type UserID struct {
	Packet

	Keywords string

	Signatures []*Signature
}

const uidTag = "{uid}"

// contents implements the packetNode interface for user IDs.
func (uid *UserID) contents() []packetNode {
	result := []packetNode{uid}
	for _, sig := range uid.Signatures {
		result = append(result, sig.contents()...)
	}
	return result
}

// appendSignature implements signable.
func (uid *UserID) appendSignature(sig *Signature) {
	uid.Signatures = append(uid.Signatures, sig)
}

func (uid *UserID) removeDuplicate(parent packetNode, dup packetNode) error {
	pubkey, ok := parent.(*PrimaryKey)
	if !ok {
		return errors.Errorf("invalid uid parent: %+v", parent)
	}
	dupUserID, ok := dup.(*UserID)
	if !ok {
		return errors.Errorf("invalid uid duplicate: %+v", dup)
	}

	uid.Signatures = append(uid.Signatures, dupUserID.Signatures...)
	pubkey.UserIDs = uidSlice(pubkey.UserIDs).without(dupUserID)
	return nil
}

type uidSlice []*UserID

func (us uidSlice) without(target *UserID) []*UserID {
	var result []*UserID
	for _, uid := range us {
		if uid != target {
			result = append(result, uid)
		}
	}
	return result
}

func ParseUserID(op *packet.OpaquePacket, parentID string) (*UserID, error) {
	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		return nil, errors.WithStack(err)
	}
	uid := &UserID{
		Packet: Packet{
			UUID:   scopedDigest([]string{parentID}, uidTag, buf.Bytes()),
			Tag:    op.Tag,
			Packet: buf.Bytes(),
		},
	}

	p, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	u, ok := p.(*packet.UserId)
	if !ok {
		return nil, errors.WithStack(ErrInvalidPacketType)
	}
	err = uid.setUserID(u)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return uid, nil
}

func (uid *UserID) userIDPacket() (*packet.UserId, error) {
	op, err := uid.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	u, ok := p.(*packet.UserId)
	if !ok {
		return nil, errors.Errorf("expected user ID packet, got %T", p)
	}
	return u, nil
}

func (uid *UserID) setUserID(u *packet.UserId) (err error) {
	uid.Keywords, err = CleanUtf8(u.Id)
	return
}

func (uid *UserID) SigInfo(pubkey *PrimaryKey) (*SelfSigs, []*Signature) {
	selfSigs := &SelfSigs{target: uid}
	var otherSigs []*Signature
	for _, sig := range uid.Signatures {
		// Plausify rather than verify non-self-certifications.
		if !(pubkey.KeyID == sig.IssuerKeyID || pubkey.VFingerprint == sig.IssuerFingerprint) {
			checkSig := &CheckSig{
				PrimaryKey: pubkey,
				Signature:  sig,
				Error:      pubkey.plausifyUserIDSig(uid, sig),
			}
			if checkSig.Error == nil {
				switch sig.SigType {
				case packet.SigTypeCertificationRevocation, packet.SigTypeGenericCert, packet.SigTypePersonaCert, packet.SigTypeCasualCert, packet.SigTypePositiveCert:
					otherSigs = append(otherSigs, sig)
				}
			}
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifyUserIDSelfSig(uid, sig),
		}
		if checkSig.Error != nil {
			selfSigs.Errors = append(selfSigs.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case packet.SigTypeCertificationRevocation:
			selfSigs.Revocations = append(selfSigs.Revocations, checkSig)
		case packet.SigTypeGenericCert, packet.SigTypePersonaCert, packet.SigTypeCasualCert, packet.SigTypePositiveCert:
			selfSigs.Certifications = append(selfSigs.Certifications, checkSig)
			if sig.Primary {
				selfSigs.Primaries = append(selfSigs.Primaries, checkSig)
			}
		}
	}
	selfSigs.resolve()
	return selfSigs, otherSigs
}
