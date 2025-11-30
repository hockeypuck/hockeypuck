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
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

type PublicKey struct {
	Packet

	Fingerprint  string
	Version      uint8
	VFingerprint string
	KeyID        string

	// Creation stores the timestamp when the public key was created.
	Creation time.Time

	// Expiration stores the timestamp when the public key expires.
	Expiration time.Time

	// Algorithm stores the algorithm type of the public key.
	Algorithm int

	// BitLen stores the bit length of the public key.
	BitLen int

	// Curve stores the ECC curve of the public key.
	Curve string

	Signatures []*Signature
}

func AlgorithmName(code int, len int, curve string) string {
	switch code {
	case 1:
		return fmt.Sprintf("rsa%d", len)
	case 2:
		return fmt.Sprintf("rsaE%d", len)
	case 3:
		return fmt.Sprintf("rsaS%d", len)
	case 8:
		return "kyber?"
	case 16:
		return fmt.Sprintf("elgE%d", len)
	case 17:
		return fmt.Sprintf("dsa%d", len)
	case 18:
		return fmt.Sprintf("ecdh_%s", curve)
	case 19:
		return fmt.Sprintf("ecdsa_%s", curve)
	case 20:
		return fmt.Sprintf("elg!%d", len)
	case 21:
		return "dh?"
	case 22:
		return fmt.Sprintf("eddsa_%s", curve)
	case 23:
		return "aedh?"
	case 24:
		return "aedsa?"
	case 25:
		return "x25519"
	case 26:
		return "x448"
	case 27:
		return "ed25519"
	case 28:
		return "ed448"
	default:
		return fmt.Sprintf("unk(#%d)", code)
	}
}

func (pk *PublicKey) QualifiedFingerprint() string {
	return fmt.Sprintf("(%d)%s/%s", pk.Version, AlgorithmName(pk.Algorithm, pk.BitLen, pk.Curve), pk.Fingerprint)
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
	curve, err := pk.Curve()
	if err == nil {
		pkp.Curve = string(curve)
	}
	pkp.Version = uint8(pk.Version)
	pkp.Fingerprint = fingerprint
	pkp.VFingerprint = fmt.Sprintf("%02x%s", pkp.Version, fingerprint)
	pkp.UUID = pkp.Fingerprint
	err = pkp.setKeyID(pkp.Version, pkp.Fingerprint)
	if err != nil {
		return errors.WithStack(err)
	}
	pkp.Creation = pk.CreationTime
	pkp.Algorithm = int(pk.PubKeyAlgo)
	pkp.BitLen = int(bitLen)
	return nil
}

func (pkp *PublicKey) setKeyID(v uint8, fp string) error {
	if len(fp) < 40 {
		return errors.Errorf("invalid fingerprint %q", fp)
	}
	switch v {
	case 4:
		pkp.KeyID = fp[24:]
	default:
		pkp.KeyID = fp[:16]
	}
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
	pkp.Fingerprint = fingerprint
	pkp.VFingerprint = "03" + fingerprint
	pkp.UUID = pkp.Fingerprint
	pkp.KeyID = fmt.Sprintf("%016x", pk.KeyId)
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
		if !(pubkey.KeyID == sig.IssuerKeyID || pubkey.VFingerprint == sig.IssuerFingerprint) {
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

// RedactingSignature returns the most relevant redacting sig, if one exists.
// Redacting signatures are direct-key revocations with the reasons nil, "no reason", "key compromised",
// and (TO BE IMPLEMENTED, #294) "user ID no longer valid".
// Any hard revocation is returned. It doesn't matter which, all hard revocations are equivalent.
// Otherwise (TO BE IMPLEMENTED) the most recent redacting sig is returned.
func (pubkey *PrimaryKey) RedactingSignature() (*Signature, error) {
	var revoc *Signature
	selfSigs, _ := pubkey.SigInfo()
	for _, checkSig := range selfSigs.Revocations {
		reason := checkSig.Signature.RevocationReason
		if reason == nil || *reason == packet.KeyCompromised || *reason == packet.NoReason {
			return checkSig.Signature, nil
		}
		// else if revoc == nil && *reason == packet.UIDNoLongerValid {
		//	revoc = checkSig.Signature
		//}
	}
	return revoc, nil
}

// PrimaryUserIDSig returns the most recent signature on the currently-active primary UserID, if one exists.
// In V4 keys, this signature contains the default metadata for the primary key.
func (pubkey *PrimaryKey) PrimaryUserIDSig() (*Signature, error) {
	var primarySig *Signature
	var loneUserID = false
	if len(pubkey.UserIDs) == 1 {
		// If there is only one UserID then it is the primary by default
		loneUserID = true
	}
	for _, userID := range pubkey.UserIDs {
		selfSigs, _ := userID.SigInfo(pubkey)
		if len(selfSigs.Certifications) > 0 {
			checkSig := selfSigs.Certifications[0]
			if loneUserID || checkSig.Signature.Primary {
				date := checkSig.Signature.Creation
				if primarySig == nil || primarySig.Creation.Before(date) {
					primarySig = checkSig.Signature
				}
			}
		}
	}
	return primarySig, nil
}

func packetBodyLength(packet []byte) int {
	if packet[0]&0xc0 == 0xc0 {
		// OpenPGP packet length
		if packet[1] <= 191 {
			return len(packet) - 2
		} else if packet[1] <= 223 {
			return len(packet) - 3
		} else if packet[1] == 255 {
			// there SHOULD NOT be partial packets in keyrings
			return 0
		} else {
			return len(packet) - 6
		}
	} else if packet[0]&0xc0 == 0x80 {
		// Legacy packet length
		lengthType := packet[0] & 0x03
		switch lengthType {
		case 0x00:
			return len(packet) - 2
		case 0x01:
			return len(packet) - 3
		case 0x02:
			return len(packet) - 5
		default:
			// there MUST NOT be indeterminate length packets in keyrings
			return 0
		}
	} else {
		// not an OpenPGP packet
		return 0
	}
}

// updateMD5 also refreshes the primary key's Length field
// (https://github.com/hockeypuck/hockeypuck/issues/282)
// Note that Packet.Packet includes framing, but OpaquePacket does not.
// Count only the body length, for consistency with (*OpaqueKeyring)Parse().
func (pubkey *PrimaryKey) updateMD5() error {
	digest, err := SksDigest(pubkey, md5.New())
	if err != nil {
		return errors.WithStack(err)
	}
	pubkey.MD5 = digest
	length := packetBodyLength(pubkey.Packet.Packet)
	for _, sig := range pubkey.Signatures {
		length += packetBodyLength(sig.Packet.Packet)
	}
	for _, uid := range pubkey.UserIDs {
		length += packetBodyLength(uid.Packet.Packet)
		for _, sig := range uid.Signatures {
			length += packetBodyLength(sig.Packet.Packet)
		}
	}
	for _, subkey := range pubkey.SubKeys {
		length += packetBodyLength(subkey.Packet.Packet)
		for _, sig := range subkey.Signatures {
			length += packetBodyLength(sig.Packet.Packet)
		}
	}
	pubkey.Length = length
	return nil
}
