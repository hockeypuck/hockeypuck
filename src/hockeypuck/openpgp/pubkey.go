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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

type PublicKey struct {
	Packet

	RFingerprint string
	RKeyID       string
	RShortID     string
	Version      uint8

	// Creation stores the timestamp when the public key was created.
	Creation time.Time

	// Expiration stores the timestamp when the public key expires.
	Expiration time.Time

	// Algorithm stores the algorithm type of the public key.
	Algorithm int

	// BitLen stores the bit length of the public key.
	BitLen int

	Signatures []*Signature
}

func AlgorithmName(code int) string {
	switch code {
	case 1:
		return "rsa"
	case 2:
		return "rsaE"
	case 3:
		return "rsaS"
	case 16:
		return "elgE"
	case 17:
		return "dsa"
	case 18:
		return "ecdh"
	case 19:
		return "ecdsa"
	case 20:
		return "elg!"
	case 21:
		return "dh?"
	case 22:
		return "eddsa"
	case 23:
		return "aedh?"
	case 24:
		return "aedsa?"
	default:
		return fmt.Sprintf("unk(#%d)", code)
	}
}

func (pk *PublicKey) QualifiedFingerprint() string {
	return fmt.Sprintf("(%d)%s%d/%s", pk.Version, AlgorithmName(pk.Algorithm), pk.BitLen, Reverse(pk.RFingerprint))
}

func (pk *PublicKey) ShortID() string {
	return Reverse(pk.RShortID)
}

func (pk *PublicKey) KeyID() string {
	return Reverse(pk.RKeyID)
}

func (pk *PublicKey) Fingerprint() string {
	return Reverse(pk.RFingerprint)
}

// appendSignature implements signable.
func (pk *PublicKey) appendSignature(sig *Signature) {
	pk.Signatures = append(pk.Signatures, sig)
}

func (pkp *PublicKey) publicKeyPacket() (*packet.PublicKey, error) {
	op, err := pkp.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pk, ok := p.(*packet.PublicKey)
	if !ok {
		return nil, errors.Errorf("expected public key packet, got %T", p)
	}
	return pk, nil
}

func (pkp *PublicKey) publicKeyV3Packet() (*packet.PublicKeyV3, error) {
	op, err := pkp.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pk, ok := p.(*packet.PublicKeyV3)
	if !ok {
		return nil, errors.Errorf("expected public key V3 packet, got %T", p)
	}
	return pk, nil
}

func (pkp *PublicKey) parse(op *packet.OpaquePacket, subkey bool) error {
	p, err := op.Parse()
	if err != nil {
		return errors.WithStack(err)
	}

	switch pk := p.(type) {
	case *packet.PublicKey:
		if pk.IsSubkey != subkey {
			return errors.WithStack(ErrInvalidPacketType)
		}
		return pkp.setPublicKey(pk)
	case *packet.PublicKeyV3:
		if pk.IsSubkey != subkey {
			return errors.WithStack(ErrInvalidPacketType)
		}
		return pkp.setPublicKeyV3(pk)
	default:
	}

	return errors.WithStack(ErrInvalidPacketType)
}

func (pkp *PublicKey) setPublicKey(pk *packet.PublicKey) error {
	buf := bytes.NewBuffer(nil)
	err := pk.Serialize(buf)
	if err != nil {
		return errors.WithStack(err)
	}
	fingerprint := hex.EncodeToString(pk.Fingerprint[:])
	bitLen, err := pk.BitLength()
	if err != nil {
		return errors.WithStack(err)
	}
	pkp.RFingerprint = Reverse(fingerprint)
	pkp.UUID = pkp.RFingerprint
	err = pkp.setV4IDs(pkp.UUID)
	if err != nil {
		return errors.WithStack(err)
	}
	pkp.Creation = pk.CreationTime
	pkp.Algorithm = int(pk.PubKeyAlgo)
	pkp.BitLen = int(bitLen)
	pkp.Version = 4
	return nil
}

func (pkp *PublicKey) setV4IDs(rfp string) error {
	if len(rfp) < 8 {
		return errors.Errorf("invalid fingerprint %q", rfp)
	}
	pkp.RShortID = rfp[:8]
	if len(rfp) < 16 {
		return errors.Errorf("invalid fingerprint %q", rfp)
	}
	pkp.RKeyID = rfp[:16]
	return nil
}

func (pkp *PublicKey) setPublicKeyV3(pk *packet.PublicKeyV3) error {
	var buf bytes.Buffer
	err := pk.Serialize(&buf)
	if err != nil {
		return errors.WithStack(err)
	}
	fingerprint := hex.EncodeToString(pk.Fingerprint[:])
	bitLen, err := pk.BitLength()
	if err != nil {
		return errors.WithStack(err)
	}
	pkp.RFingerprint = Reverse(fingerprint)
	pkp.UUID = pkp.RFingerprint
	pkp.RShortID = Reverse(fmt.Sprintf("%08x", uint32(pk.KeyId)))
	pkp.RKeyID = Reverse(fmt.Sprintf("%016x", pk.KeyId))
	pkp.Creation = pk.CreationTime
	if pk.DaysToExpire > 0 {
		pkp.Expiration = pkp.Creation.Add(time.Duration(pk.DaysToExpire) * time.Hour * 24)
	}
	pkp.Algorithm = int(pk.PubKeyAlgo)
	pkp.BitLen = int(bitLen)
	pkp.Version = 3
	return nil
}

type PrimaryKey struct {
	PublicKey

	MD5    string
	Length int

	SubKeys []*SubKey
	UserIDs []*UserID
}

// contents implements the packetNode interface for top-level public keys.
func (pubkey *PrimaryKey) contents() []packetNode {
	result := []packetNode{pubkey}
	for _, sig := range pubkey.Signatures {
		result = append(result, sig.contents()...)
	}
	for _, uid := range pubkey.UserIDs {
		result = append(result, uid.contents()...)
	}
	for _, subkey := range pubkey.SubKeys {
		result = append(result, subkey.contents()...)
	}
	return result
}

func (*PrimaryKey) removeDuplicate(parent packetNode, dup packetNode) error {
	return errors.New("cannot remove a duplicate primary pubkey")
}

func ParsePrimaryKey(op *packet.OpaquePacket) (*PrimaryKey, error) {
	var buf bytes.Buffer
	var err error

	if err = op.Serialize(&buf); err != nil {
		return nil, errors.WithStack(err)
	}
	pubkey := &PrimaryKey{
		PublicKey: PublicKey{
			Packet: Packet{
				Tag:    op.Tag,
				Packet: buf.Bytes(),
			},
		},
	}

	// Attempt to parse the opaque packet into a public key type.
	err = pubkey.parse(op, false)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return pubkey, nil
}

func (pubkey *PrimaryKey) setPublicKey(pk *packet.PublicKey) error {
	if pk.IsSubkey {
		return errors.Wrap(ErrInvalidPacketType, "expected primary public key packet, got sub-key")
	}
	return pubkey.PublicKey.setPublicKey(pk)
}

func (pubkey *PrimaryKey) setPublicKeyV3(pk *packet.PublicKeyV3) error {
	if pk.IsSubkey {
		return errors.Wrap(ErrInvalidPacketType, "expected primary public key packet, got sub-key")
	}
	return pubkey.PublicKey.setPublicKeyV3(pk)
}

func (pubkey *PrimaryKey) SigInfo() (*SelfSigs, []*Signature) {
	selfSigs := &SelfSigs{target: pubkey}
	var otherSigs []*Signature
	for _, sig := range pubkey.Signatures {
		// Plausify rather than verify non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			checkSig := &CheckSig{
				PrimaryKey: pubkey,
				Signature:  sig,
				Error:      pubkey.plausifyPrimaryKeySig(sig),
			}
			if checkSig.Error == nil {
				switch sig.SigType {
				case packet.SigTypeKeyRevocation, packet.SigTypeDirectSignature:
					otherSigs = append(otherSigs, sig)
				}
			}
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifyPrimaryKeySelfSig(sig),
		}
		if checkSig.Error != nil {
			selfSigs.Errors = append(selfSigs.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case packet.SigTypeKeyRevocation:
			selfSigs.Revocations = append(selfSigs.Revocations, checkSig)
		case packet.SigTypeDirectSignature:
			selfSigs.Certifications = append(selfSigs.Certifications, checkSig)
		}
	}
	selfSigs.resolve()
	return selfSigs, otherSigs
}

// RedactingSignature returns the most recent redacting sig, if one exists.
// Redacting signatures are direct-key revocations with the reasons nil, "no reason", "key compromised",
// and (TO BE IMPLEMENTED, #294) "user ID no longer valid".
func (pubkey *PrimaryKey) RedactingSignature() (*Signature, error) {
	var revoc *Signature
	selfSigs, _ := pubkey.SigInfo()
	for _, checkSig := range selfSigs.Revocations {
		// Find the most recent redacting signature. Don't assume the sigs are sorted.
		reason := checkSig.Signature.RevocationReason
		if reason == nil || *reason == packet.KeyCompromised || *reason == packet.NoReason {
			date := checkSig.Signature.Creation
			if revoc == nil || revoc.Creation.Before(date) {
				revoc = checkSig.Signature
			}
		}
	}
	return revoc, nil
}

func (pubkey *PrimaryKey) updateMD5() error {
	digest, err := SksDigest(pubkey, md5.New())
	if err != nil {
		return errors.WithStack(err)
	}
	pubkey.MD5 = digest
	return nil
}
