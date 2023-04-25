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

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

type UserAttribute struct {
	Packet

	Images [][]byte

	Signatures []*Signature
	Others     []*Packet
}

const uatTag = "{uat}"

// contents implements the packetNode interface for user attributes.
func (uat *UserAttribute) contents() []packetNode {
	result := []packetNode{uat}
	for _, sig := range uat.Signatures {
		result = append(result, sig.contents()...)
	}
	for _, p := range uat.Others {
		result = append(result, p.contents()...)
	}
	return result
}

// appendSignature implements signable.
func (uat *UserAttribute) appendSignature(sig *Signature) {
	uat.Signatures = append(uat.Signatures, sig)
}

func (uat *UserAttribute) removeDuplicate(parent packetNode, dup packetNode) error {
	pubkey, ok := parent.(*PrimaryKey)
	if !ok {
		return errors.Errorf("invalid uat parent: %+v", parent)
	}
	dupUserAttribute, ok := dup.(*UserAttribute)
	if !ok {
		return errors.Errorf("invalid uat duplicate: %+v", dup)
	}

	uat.Signatures = append(uat.Signatures, dupUserAttribute.Signatures...)
	uat.Others = append(uat.Others, dupUserAttribute.Others...)
	pubkey.UserAttributes = uatSlice(pubkey.UserAttributes).without(dupUserAttribute)
	return nil
}

type uatSlice []*UserAttribute

func (us uatSlice) without(target *UserAttribute) []*UserAttribute {
	var result []*UserAttribute
	for _, uat := range us {
		if uat != target {
			result = append(result, uat)
		}
	}
	return result
}

func ParseUserAttribute(op *packet.OpaquePacket, parentID string) (*UserAttribute, error) {
	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		return nil, errors.WithStack(err)
	}
	uat := &UserAttribute{
		Packet: Packet{
			UUID:   scopedDigest([]string{parentID}, uatTag, buf.Bytes()),
			Tag:    op.Tag,
			Packet: buf.Bytes(),
		},
	}

	u, err := uat.userAttributePacket()
	if err != nil {
		return nil, errors.Wrapf(ErrInvalidPacketType, "%v", err)
	}

	uat.Images = u.ImageData()
	uat.Parsed = true
	return uat, nil
}

func (uat *UserAttribute) userAttributePacket() (*packet.UserAttribute, error) {
	op, err := uat.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	u, ok := p.(*packet.UserAttribute)
	if !ok {
		return nil, errors.Errorf("expected user attribute packet, got %T", p)
	}
	return u, nil
}

func (uat *UserAttribute) SigInfo(pubkey *PrimaryKey) (*SelfSigs, []*Signature) {
	selfSigs := &SelfSigs{target: uat}
	var otherSigs []*Signature
	for _, sig := range uat.Signatures {
		// Skip non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			otherSigs = append(otherSigs, sig)
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifyUserAttrSelfSig(uat, sig),
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
