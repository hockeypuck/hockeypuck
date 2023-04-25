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
	"crypto"
	"hash"

	"github.com/pkg/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func (pubkey *PrimaryKey) verifyPublicKeySelfSig(signed *PublicKey, sig *Signature) error {
	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	switch pk := pkParsed.(type) {
	case *packet.PublicKey:
		s, err := sig.signaturePacket()
		if err != nil {
			return errors.WithStack(err)
		}
		signedPk, err := signed.publicKeyPacket()
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(pk.VerifyKeySignature(signedPk, s))
	case *packet.PublicKeyV3:
		s, err := sig.signatureV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		signedPk, err := signed.publicKeyV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(pk.VerifyKeySignatureV3(signedPk, s))
	}
	return ErrInvalidPacketType
}

func (pubkey *PrimaryKey) verifyUserIDSelfSig(uid *UserID, sig *Signature) error {
	u, err := uid.userIDPacket()
	if err != nil {
		return errors.WithStack(err)
	}

	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	switch pk := pkParsed.(type) {
	case *packet.PublicKey:
		sOpaque, err := sig.opaquePacket()
		if err != nil {
			return errors.WithStack(err)
		}
		sParsed, err := sOpaque.Parse()
		if err != nil {
			return errors.WithStack(err)
		}
		switch s := sParsed.(type) {
		case *packet.Signature:
			return errors.WithStack(pk.VerifyUserIdSignature(u.Id, pk, s))
		case *packet.SignatureV3:
			return errors.WithStack(pk.VerifyUserIdSignatureV3(u.Id, pk, s))
		default:
			return errors.WithStack(ErrInvalidPacketType)
		}
	case *packet.PublicKeyV3:
		s, err := sig.signatureV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(pk.VerifyUserIdSignatureV3(u.Id, pk, s))
	default:
		return errors.WithStack(ErrInvalidPacketType)
	}
}

func (pubkey *PrimaryKey) verifyUserAttrSelfSig(uat *UserAttribute, sig *Signature) error {
	pk, err := pubkey.PublicKey.publicKeyPacket()
	if err != nil {
		return errors.WithStack(err)
	}
	s, err := sig.signaturePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	h, err := pubkey.sigSerializeUserAttribute(uat, s.Hash)
	if err != nil {
		return errors.WithStack(err)
	}
	return pk.VerifySignature(h, s)
}

// sigSerializeUserAttribute calculates the user attribute packet hash
// TODO: clean up & contribute this to github.com/ProtonMail/go-crypto/openpgp.
func (pubkey *PrimaryKey) sigSerializeUserAttribute(uat *UserAttribute, hashFunc crypto.Hash) (hash.Hash, error) {
	if !hashFunc.Available() {
		return nil, errors.Errorf("unsupported hash function: %v", hashFunc)
	}
	h := hashFunc.New()

	// Get user attribute opaque packet
	uatOpaque, err := uat.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// Get public key opaque packet.
	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// Get public key v4 packet. User attributes not supported pre-v4.
	pk, err := pubkey.PublicKey.publicKeyPacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// RFC 4880, section 5.2.4
	// Write the signature prefix and public key contents to hash
	pk.SerializeSignaturePrefix(h)
	h.Write(pkOpaque.Contents)

	// V4 certification hash
	var buf [5]byte
	// User attribute constant
	buf[0] = 0xd1
	// Big-endian length of user attribute contents
	l := len(uatOpaque.Contents)
	buf[1] = byte(l >> 24)
	buf[2] = byte(l >> 16)
	buf[3] = byte(l >> 8)
	buf[4] = byte(l)
	h.Write(buf[:])
	// User attribute contents
	h.Write(uatOpaque.Contents)
	return h, nil
}
