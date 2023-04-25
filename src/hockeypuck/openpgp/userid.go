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
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

type UserID struct {
	Packet

	Keywords string

	Signatures []*Signature
	Others     []*Packet
}

const uidTag = "{uid}"

// contents implements the packetNode interface for user IDs.
func (uid *UserID) contents() []packetNode {
	result := []packetNode{uid}
	for _, sig := range uid.Signatures {
		result = append(result, sig.contents()...)
	}
	for _, p := range uid.Others {
		result = append(result, p.contents()...)
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
	uid.Others = append(uid.Others, dupUserID.Others...)
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
		return nil, ErrInvalidPacketType
	}
	err = uid.setUserID(u)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	uid.Parsed = true
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

func (uid *UserID) setUserID(u *packet.UserId) error {
	uid.Keywords = cleanUtf8(u.Id)
	return nil
}

func cleanUtf8(s string) string {
	var runes []rune
	for _, r := range s {
		if r == utf8.RuneError {
			r = '?'
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		runes = append(runes, r)
	}
	return string(runes)
}

func (uid *UserID) SigInfo(pubkey *PrimaryKey) (*SelfSigs, []*Signature) {
	selfSigs := &SelfSigs{target: uid}
	var otherSigs []*Signature
	for _, sig := range uid.Signatures {
		// Skip non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			otherSigs = append(otherSigs, sig)
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
		case 0x30: // packet.SigTypeCertRevocation
			selfSigs.Revocations = append(selfSigs.Revocations, checkSig)
		case 0x10, 0x11, 0x12, 0x13:
			selfSigs.Certifications = append(selfSigs.Certifications, checkSig)
			if !sig.Expiration.IsZero() {
				selfSigs.Expirations = append(selfSigs.Expirations, checkSig)
			}
			if sig.Primary {
				selfSigs.Primaries = append(selfSigs.Primaries, checkSig)
			}
		}
	}
	selfSigs.resolve()
	return selfSigs, otherSigs
}
