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
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

func (pubkey *PrimaryKey) verifyPrimaryKeySelfSig(sig *Signature) error {
	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	if err != nil {
		return errors.WithStack(err)
	}
	switch pk := pkParsed.(type) {
	case *packet.PublicKey:
		s, err := sig.signaturePacket()
		if err == nil {
			switch s.SigType {
			case packet.SigTypeKeyRevocation:
				return errors.WithStack(pk.VerifyRevocationSignature(s))
			case packet.SigTypeDirectSignature:
				// VerifyRevocationSignature verifies *any* direct sig, despite the name
				return errors.WithStack(pk.VerifyRevocationSignature(s))
			}
			return errors.WithStack(ErrInvalidPacketType)
		}
		// v4 keys can also make v3 direct sigs over themselves
		s3, err3 := sig.signatureV3Packet()
		if err3 != nil {
			// return the earlier error
			return errors.WithStack(err)
		}
		// v4 primary keys can have v3 direct revocations
		// Note: v3 sigs can't have subpackets, so v3 revocations have no ReasonForRevocation
		if pk.Version == 4 && s3.SigType == packet.SigTypeKeyRevocation {
			return errors.WithStack(pk.VerifyRevocationSignatureV3(s3))
		}
	case *packet.PublicKeyV3:
		// Note: v3 sigs can't have subpackets, so v3 revocations have no ReasonForRevocation
		s3, err := sig.signatureV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		if s3.SigType == packet.SigTypeKeyRevocation {
			return errors.WithStack(pk.VerifyRevocationSignatureV3(s3))
		}
	}
	return errors.WithStack(ErrInvalidPacketType)
}

func (pubkey *PrimaryKey) plausifyPrimaryKeySig(sig *Signature) error {
	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	if err != nil {
		return errors.WithStack(err)
	}
	switch pk := pkParsed.(type) {
	case *packet.PublicKey:
		s, err := sig.signaturePacket()
		if err == nil {
			switch s.SigType {
			case packet.SigTypeKeyRevocation:
				return errors.WithStack(pk.VerifyRevocationHashTag(s))
			case packet.SigTypeDirectSignature:
				// VerifyRevocationHashTag handles *any* direct sig, despite the name
				return errors.WithStack(pk.VerifyRevocationHashTag(s))
			}
			return errors.WithStack(ErrInvalidPacketType)
		}
		// v4 keys can also make v3 direct sigs over themselves
		s3, err3 := sig.signatureV3Packet()
		if err3 != nil {
			// return the earlier error
			return errors.WithStack(err)
		}
		// v4 primary keys can have v3 direct revocations
		// Note: v3 sigs can't have subpackets, so v3 revocations have no ReasonForRevocation
		if pk.Version == 4 && s3.SigType == packet.SigTypeKeyRevocation {
			return errors.WithStack(pk.VerifyRevocationHashTagV3(s3))
		}
	case *packet.PublicKeyV3:
		// Note: v3 sigs can't have subpackets, so v3 revocations have no ReasonForRevocation
		s3, err := sig.signatureV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		if s3.SigType == packet.SigTypeKeyRevocation {
			return errors.WithStack(pk.VerifyRevocationHashTagV3(s3))
		}
	}
	return errors.WithStack(ErrInvalidPacketType)
}

func (pubkey *PrimaryKey) verifySubKeySelfSig(signed *PublicKey, sig *Signature) error {
	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	if err != nil {
		return errors.WithStack(err)
	}
	switch pk := pkParsed.(type) {
	case *packet.PublicKey:
		signedPk, err := signed.publicKeyPacket()
		if err != nil {
			return errors.WithStack(err)
		}
		s, err := sig.signaturePacket()
		if err == nil {
			return errors.WithStack(pk.VerifyKeySignature(signedPk, s))
		}
		// v4 keys can also make v3 sigs over v4 encryption subkeys
		s3, err3 := sig.signatureV3Packet()
		if err3 != nil {
			// return the earlier error
			return errors.WithStack(err)
		}
		if signedPk.Version == 4 {
			return errors.WithStack(pk.VerifyKeySignatureV3(signedPk, s3))
		}
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
	return errors.WithStack(ErrInvalidPacketType)
}

func (pubkey *PrimaryKey) plausifySubKeySig(signed *PublicKey, sig *Signature) error {
	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	if err != nil {
		return errors.WithStack(err)
	}
	switch pk := pkParsed.(type) {
	case *packet.PublicKey:
		signedPk, err := signed.publicKeyPacket()
		if err != nil {
			return errors.WithStack(err)
		}
		s, err := sig.signaturePacket()
		if err == nil {
			return errors.WithStack(pk.VerifyKeyHashTag(signedPk, s))
		}
		// v4 keys can also make v3 sigs over v4 encryption subkeys
		s3, err3 := sig.signatureV3Packet()
		if err3 != nil {
			// return the earlier error
			return errors.WithStack(err)
		}
		if signedPk.Version == 4 {
			return errors.WithStack(pk.VerifyKeyHashTagV3(signedPk, s3))
		}
	case *packet.PublicKeyV3:
		s, err := sig.signatureV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		signedPk, err := signed.publicKeyV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(pk.VerifyKeyHashTagV3(signedPk, s))
	}
	return errors.WithStack(ErrInvalidPacketType)
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
	if err != nil {
		return errors.WithStack(err)
	}
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

func (pubkey *PrimaryKey) plausifyUserIDSig(uid *UserID, sig *Signature) error {
	u, err := uid.userIDPacket()
	if err != nil {
		return errors.WithStack(err)
	}

	pkOpaque, err := pubkey.opaquePacket()
	if err != nil {
		return errors.WithStack(err)
	}
	pkParsed, err := pkOpaque.Parse()
	if err != nil {
		return errors.WithStack(err)
	}
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
			return errors.WithStack(pk.VerifyUserIdHashTag(u.Id, s))
		case *packet.SignatureV3:
			return errors.WithStack(pk.VerifyUserIdHashTagV3(u.Id, s))
		default:
			return errors.WithStack(ErrInvalidPacketType)
		}
	case *packet.PublicKeyV3:
		s, err := sig.signatureV3Packet()
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(pk.VerifyUserIdHashTagV3(u.Id, s))
	default:
		return errors.WithStack(ErrInvalidPacketType)
	}
}
