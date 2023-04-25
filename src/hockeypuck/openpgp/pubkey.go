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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type PublicKey struct {
	Packet

	RFingerprint string
	RKeyID       string
	RShortID     string

	// Creation stores the timestamp when the public key was created.
	Creation time.Time

	// Expiration stores the timestamp when the public key expires.
	Expiration time.Time

	// Algorithm stores the algorithm type of the public key.
	Algorithm int

	// BitLen stores the bit length of the public key.
	BitLen int

	Signatures []*Signature
	Others     []*Packet
}

func AlgorithmName(code int) string {
	switch code {
	case 1, 2, 3:
		return "rsa"
	case 16:
		return "elg"
	case 17:
		return "dsa"
	case 18:
		return "ecdh"
	case 19:
		return "ecdsa"
	case 20:
		return "elg"
	case 22:
		return "eddsa"
	default:
		return fmt.Sprintf("unk(#%d)", code)
	}
}

func (pk *PublicKey) QualifiedFingerprint() string {
	return fmt.Sprintf("%s%d/%s", AlgorithmName(pk.Algorithm), pk.BitLen, Reverse(pk.RFingerprint))
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
			return ErrInvalidPacketType
		}
		return pkp.setPublicKey(pk)
	case *packet.PublicKeyV3:
		if pk.IsSubkey != subkey {
			return ErrInvalidPacketType
		}
		return pkp.setPublicKeyV3(pk)
	default:
	}

	return errors.WithStack(ErrInvalidPacketType)
}

func (pkp *PublicKey) setUnsupported(op *packet.OpaquePacket) error {
	// Calculate opaque fingerprint on unsupported public key packet
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(op.Contents) >> 8), byte(len(op.Contents))})
	h.Write(op.Contents)
	fpr := hex.EncodeToString(h.Sum(nil))
	pkp.RFingerprint = Reverse(fpr)
	pkp.UUID = pkp.RFingerprint
	return pkp.setV4IDs(pkp.UUID)
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
	pkp.Parsed = true
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
	pkp.Parsed = true
	return nil
}

type PrimaryKey struct {
	PublicKey

	MD5    string
	Length int

	SubKeys        []*SubKey
	UserIDs        []*UserID
	UserAttributes []*UserAttribute
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
	for _, uat := range pubkey.UserAttributes {
		result = append(result, uat.contents()...)
	}
	for _, subkey := range pubkey.SubKeys {
		result = append(result, subkey.contents()...)
	}
	for _, other := range pubkey.Others {
		result = append(result, other.contents()...)
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
	parseErr := pubkey.parse(op, false)
	if parseErr != nil {
		err = pubkey.setUnsupported(op)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		pubkey.Parsed = true
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
		// Skip non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			otherSigs = append(otherSigs, sig)
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifyPublicKeySelfSig(&pubkey.PublicKey, sig),
		}
		if checkSig.Error != nil {
			selfSigs.Errors = append(selfSigs.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case 0x20: // packet.SigTypeKeyRevocation
			selfSigs.Revocations = append(selfSigs.Revocations, checkSig)
		}
	}
	selfSigs.resolve()
	return selfSigs, otherSigs
}

func (pubkey *PrimaryKey) updateMD5() error {
	digest, err := SksDigest(pubkey, md5.New())
	if err != nil {
		return errors.WithStack(err)
	}
	pubkey.MD5 = digest
	return nil
}
