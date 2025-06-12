/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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

// Package jsonhkp defines an arbitrary, Hockeypuck-specific, JSON-friendly
// document model for representation of OpenPGP key material. Intended to be
// used by front-end Javascript as well as server-side HTML template developers.
package jsonhkp

import (
	"io"
	"time"

	"github.com/pkg/errors"

	"hockeypuck/openpgp"
)

type Packet struct {
	Tag    uint8  `json:"tag"`
	Data   []byte `json:"data"`
	Parsed bool   `json:"parsed"`

	/*
	   // NEW FIELD required for lossless roundtripping
	   Frames []*Frame  `json:"frames,omitempty"`
	*/
}

func NewPacket(from *openpgp.Packet) *Packet {
	return &Packet{
		Tag:  from.Tag,
		Data: from.Packet,
	}
}

type Algorithm struct {
	Name      string `json:"name"`
	Code      int    `json:"code"`
	BitLength int    `json:"bitLength"` // TODO: should this be optional?
	Curve     string `json:"curve,omitempty"`
}

type PublicKey struct {
	Fingerprint  string       `json:"fingerprint"`
	LongKeyID    string       `json:"longKeyID"`
	ShortKeyID   string       `json:"shortKeyID"`         // only used for testing
	Creation     string       `json:"creation,omitempty"` // TODO: is this ever empty?
	Expiration   string       `json:"expiration,omitempty"`
	NeverExpires bool         `json:"neverExpires,omitempty"`
	Version      uint8        `json:"version"`
	Algorithm    Algorithm    `json:"algorithm"`
	BitLength    int          `json:"bitLength"` // now under Algorithm; not meaningful for all algorithm types
	Signatures   []*Signature `json:"signatures,omitempty"`
	Packet       *Packet      `json:"packet,omitempty"`
	/*
	   // NEW CONTEXT-DERIVED FIELD
	   TrustPacket *TrustPacket `json:"trustPacket,omitempty"`
	*/
}

func newPublicKey(from *openpgp.PublicKey) *PublicKey {
	to := &PublicKey{
		Fingerprint: from.Fingerprint(),
		LongKeyID:   from.KeyID(),
		ShortKeyID:  from.ShortID(),
		Version:     from.Version,
		Algorithm: Algorithm{
			Name:      openpgp.AlgorithmName(from.Algorithm, from.BitLen, from.Curve),
			Code:      from.Algorithm,
			BitLength: from.BitLen,
			Curve:     from.Curve,
		},
		// The proper value of BitLength is in the Algorithm subsection above.
		// This field is maintained so that old template files don't nil deref,
		// and on-disk keyDocs will properly unmarshal.
		BitLength: from.BitLen,
		Packet:    NewPacket(&from.Packet),
	}

	if !from.Creation.IsZero() {
		// can happen if openpgp.v1 isn't able to parse this type of key
		to.Creation = from.Creation.UTC().Format(time.RFC3339)
	}

	if !from.Expiration.IsZero() {
		to.Expiration = from.Expiration.UTC().Format(time.RFC3339)
	} else {
		to.NeverExpires = true
	}

	for _, fromSig := range from.Signatures {
		to.Signatures = append(to.Signatures, NewSignature(fromSig))
	}

	return to
}

type PrimaryKey struct {
	*PublicKey

	MD5     string    `json:"md5"` // SKS digest
	Length  int       `json:"length"`
	SubKeys []*SubKey `json:"subKeys,omitempty"`
	UserIDs []*UserID `json:"userIDs,omitempty"`
	/*
		// no longer used
		UserAttrs []*UserAttribute `json:"userAttrs,omitempty"`
	*/
}

func NewPrimaryKeys(froms []*openpgp.PrimaryKey) []*PrimaryKey {
	var result []*PrimaryKey
	for _, from := range froms {
		result = append(result, NewPrimaryKey(from))
	}
	return result
}

func NewPrimaryKey(from *openpgp.PrimaryKey) *PrimaryKey {
	to := &PrimaryKey{
		PublicKey: newPublicKey(&from.PublicKey),
		MD5:       from.MD5,
		Length:    from.Length,
	}
	for _, fromSubKey := range from.SubKeys {
		to.SubKeys = append(to.SubKeys, NewSubKey(fromSubKey))
	}
	for _, fromUid := range from.UserIDs {
		to.UserIDs = append(to.UserIDs, NewUserID(fromUid))
	}
	return to
}

func (pk *PrimaryKey) Serialize(w io.Writer) error {
	packets := pk.packets()
	for _, packet := range packets {
		_, err := w.Write(packet.Data)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

type SubKey struct {
	*PublicKey
}

func NewSubKey(from *openpgp.SubKey) *SubKey {
	return &SubKey{
		newPublicKey(&from.PublicKey),
	}
}

type UserID struct {
	Keywords   string       `json:"keywords"`
	Packet     *Packet      `json:"packet,omitempty"`
	Signatures []*Signature `json:"signatures,omitempty"`
	/*
	   // NEW CONTEXT-DERIVED FIELD
	   TrustPacket *TrustPacket `json:"trustPacket,omitempty"`
	*/
}

func NewUserID(from *openpgp.UserID) *UserID {
	to := &UserID{
		Keywords: from.Keywords,
		Packet:   NewPacket(&from.Packet),
	}
	for _, fromSig := range from.Signatures {
		to.Signatures = append(to.Signatures, NewSignature(fromSig))
	}
	return to
}

/*
// no longer used by hockeypuck

type UserAttribute struct {
    Photos      []*Photo     `json:"photos,omitempty"`
    Packet      *Packet      `json:"packet,omitempty"`
    Signatures  []*Signature `json:"signatures,omitempty"`

    // NEW CONTEXT-DERIVED FIELD
    TrustPacket *TrustPacket `json:"trustPacket,omitempty"`
}

type Photo struct {
    MIMEType string `json:"mimeType"` // always 'image/jpeg'
    Contents []byte `json:"contents"`
}
*/

type Signature struct {
	SigType      int     `json:"sigType"`
	Revocation   bool    `json:"revocation,omitempty"`
	Primary      bool    `json:"primary,omitempty"`
	IssuerKeyID  string  `json:"issuerKeyID,omitempty"`
	Creation     string  `json:"creation,omitempty"`
	Expiration   string  `json:"expiration,omitempty"` // EITHER sig OR key expiration
	NeverExpires bool    `json:"neverExpires,omitempty"`
	Packet       *Packet `json:"packet,omitempty"`
	PolicyURI    string  `json:"policyURI,omitempty"`

	/*
	   // NEW PACKET FIELDS
	   Version         uint8        `json:"version"`
	   PubkeyAlgorithm Algorithm    `json:"pubkeyAlgorithm"`
	   HashAlgorithm   Algorithm    `json:"hashAlgorithm"`
	   HashedArea      []*Subpacket `json:"hashedArea,omitempty"`
	   UnhashedArea    []*Subpacket `json:"unhashedArea,omitempty"`

	   // NEW SUBPACKET-DERIVED FIELDS
	   Exportable       bool           `json:"exportable" default:"true"`
	   TrustSig         *TrustSig      `json:"trustSig,omitempty"`
	   Regex            string         `json:"regexes,omitempty"`
	   Revocable        bool           `json:"revocable" default:"true"`
	   PrefSymmetric    []Algorithm    `json:"prefSymmetric,omitempty"`
	   RevocationKeys   []string       `json:"revocationKeys,omitempty"`
	   Notations        []*Notation    `json:"notations,omitempty"`
	   PrefHash         []Algorithm    `json:"prefHash,omitempty"`
	   PrefCompression  []Algorithm    `json:"prefCompression,omitempty"`
	   KeyServerPrefs   *KeyServerPrefs `json:"keyserverPrefs,omitempty"`
	   PrefKeyServer    string         `json:"prefKeyserver,omitempty"`
	   Flags            *Flags         `json:"flags,omitempty"`
	   SignerUserID     string         `json:"signerUserID,omitempty"`
	   RevocationReason *Reason        `json:"revocationReason,omitempty"`
	   Features         *Features      `json:"features,omitempty"`
	   SigTarget        *SigTarget     `json:"sigTarget,omitempty"`
	   EmbeddedSigs     []*Signature   `json:"embeddedSigs,omitempty"` // BEWARE recursion
	   Issuer           *VFP           `json:"issuer,omitempty"`
	   Recipients       []VFP          `json:"recipients,omitempty"`
	   ApprovedCerts    [][]byte       `json:"approvedCerts,omitempty"`
	   KeyBlocks        []*KeyBlock    `json:"keyBlocks,omitempty"`    // BEWARE recursion
	   PrefAEAD         []Algorithm    `json:"prefAEAD,omitempty"`
	   PrefSuites       []AEADSuite    `json:"prefSuites,omitempty"`
	   LiteralMetadata  *MetaData      `json:"literalMetadata,omitempty"`
	   Replacement      *Replacement   `json:"replacement,omitempty"`

	   // NEW CONTEXT-DERIVED FIELD
	   TrustPacket *TrustPacket `json:"trustPacket,omitempty"`
	*/
}

func NewSignature(from *openpgp.Signature) *Signature {
	to := &Signature{
		Packet:      NewPacket(&from.Packet),
		SigType:     int(from.SigType),
		IssuerKeyID: from.IssuerKeyID(),
		Primary:     from.Primary,
		PolicyURI:   from.PolicyURI,
	}

	switch to.SigType {
	case 0x20, 0x28, 0x30:
		to.Revocation = true
	}

	if !from.Creation.IsZero() {
		// can happen if openpgp.v1 isn't able to parse this type of signature
		to.Creation = from.Creation.UTC().Format(time.RFC3339)
	}

	if !from.Expiration.IsZero() {
		to.Expiration = from.Expiration.UTC().Format(time.RFC3339)
	} else {
		to.NeverExpires = true
	}

	return to
}

func (pk *PrimaryKey) Bytes() []byte {
	var buf []byte
	for _, pkt := range pk.packets() {
		buf = append(buf, pkt.Data...)
	}
	return buf
}

func (s *Signature) packets() []*Packet {
	packets := []*Packet{s.Packet}
	return packets
}

func (pk *PublicKey) packets() []*Packet {
	packets := []*Packet{pk.Packet}
	for _, s := range pk.Signatures {
		packets = append(packets, s.packets()...)
	}
	return packets
}

func (u *UserID) packets() []*Packet {
	packets := []*Packet{u.Packet}
	for _, s := range u.Signatures {
		packets = append(packets, s.packets()...)
	}
	return packets
}

func (pk *PrimaryKey) packets() []*Packet {
	packets := pk.PublicKey.packets()
	for _, u := range pk.UserIDs {
		packets = append(packets, u.packets()...)
	}
	for _, s := range pk.SubKeys {
		packets = append(packets, s.packets()...)
	}
	return packets
}

/*
// NEW STRUCTS

type Subpacket struct {
    Tag      uint8  `json:"tag"`
    Critical bool   `json:"critical"`
    Data     []byte `json:"data"`
    Parsed   bool   `json:"parsed"`          // If true, the value has been copied to the parent object
	Frame	 *Frame `json:"frame,omitempty"` // lossless roundtripping
}

// packets

type SessionKey struct {
    Version   uint8     `json:"version"`
    Packet    *Packet   `json:"packet,omitempty"`
}

type PKESK struct {
    *SessionKey

    Algorithm Algorithm `json:"algorithm"`
    Recipient *VFP      `json:"recipient,omitempty"` // v6
    LongKeyID string    `json:"longKeyID,omitempty"` // v3
}

type SKESK struct {
    *SessionKey

    S2KSpecifier  S2KSpecifier `json:"s2kSpecifier"`
    Algorithm     *Algorithm   `json:"algorithm,omitempty"` // v4
    AEADSuite     *AEADSuite   `json:"suite,omitempty"` // v6
    IV            []byte       `json:"iv,omitempty"` // v6
    AuthTag       []byte       `json:"authTag,omitempty"` // v6
}

type CompressedData struct {
    Algorithm Algorithm `json:"algorithm"`
    Packet    *Packet   `json:"packet,omitempty"`
}

type LiteralData struct {
    Metadata VerbatimMetadata `json:"metadata"`
    Packet   *Packet          `json:"packet,omitempty"`
}

type SED struct {
    Packet    *Packet   `json:"packet,omitempty"`
}

type SEIPD struct {
    Version   uint8     `json:"version"`
    Suite     *AEADSuite `json:"suite,omitempty"`    // v2
    ChunkSize uint8     `json:"chunkSize,omitempty"` // v2
    Salt      []byte    `json:"salt,omitempty"`      // v2
    Packet    *Packet   `json:"packet,omitempty"`
}

// as per draft-ietf-rfc4880bis-10
// this has had too many names, so identify by packet tag
type Type20 {
    Version   uint8     `json:"version"`
    Suite     AEADSuite `json:"suite"`
    ChunkSize uint8     `json:"chunkSize"`
    IV        []byte    `json:"iv"`
    Packet    *Packet   `json:"packet,omitempty"`
}

// trust packets are treated as blobs
type TrustPacket {
	Packet *Packet `json:"packet,omitempty"`
}

// packet sequences

type Message struct {
    SessionKeys    []*SessionKey   `json:"sessionKeys,omitempty"`
    CompressedData *CompressedData `json:"compressedData,omitempty"`
    LiteralData    *LiteralData    `json:"literalData,omitempty"`
    SED            *SED            `json:"sed,omitempty"`
    SEIPD          *SEIPD          `json:"seipd,omitempty"`
    Type20         *Type20         `json:"type20,omitempty"`
    Signatures     []*Signature    `json:"signatures,omitempty"`
}

// as per draft-gallagher-openpgp-hkp
// TODO: needs a better name!
type MixedKeyring struct {
    Signatures   []*Signature  `json:"signatures,omitempty"`
    Certificates []*PrimaryKey `json:"certificates,omitempty"`
}

// data types

type Frame struct {
    Length          int   `json:"length,omitempty"`
	LengthOfLength  uint8 `json:"lengthOfLength"`
    Legacy          bool  `json:"legacy,omitempty"` // packets only
    Indefinite      bool  `json:"indefinite,omitempty"` // legacy packets only
    Partial         bool  `json:"partial,omitempty"` // non-legacy packets only
    PartialExponent uint8 `json:"partialExponent,omitempty"` // 0..30
}

type VFP struct {
    Version     uint8  `json:"version"`
    Fingerprint string `json:"fingerprint"`
}

type S2KSpecifier struct {
    Type          uint8     `json:"type"`
    HashAlgorithm *Algorithm `json:"algorithm,omitempty"`
    Salt          []byte    `json:"salt,omitempty"`
    Count         uint32    `json:"count,omitempty"`    // if type==3, decoded!
    Parallel      uint8     `json:"parallel,omitempty"`
    Memory        uint32    `json:"memory,omitempty"`   // decoded!
}

type AEADSuite struct {
    SymmetricAlgorithm Algorithm `json:"symmetricAlgorithm"`
    AEADAlgorithm      Algorithm `json:"aeadAlgorithm"`
}

type TrustSig struct {
    Depth  uint8 `json:"depth"`
    Amount uint8 `json:"amount"`
}

type SigTarget struct {
    PubkeyAlgorithm Algorithm `json:"pubkeyAlgorithm"`
    HashAlgorithm   Algorithm `json:"hashAlgorithm"`
    Digest          []byte    `json:"digest"`
}

type Reason struct {
    Code   uint8  `json:"code"`
    Reason string `json:"reason,omitempty"`
}

type Notation struct {
    Class NotationClass `json:"class"`
    Name  string        `json:"name"`
    Text  string        `json:"text,omitempty"` // if human-readable
    Data  []byte        `json:"data,omitempty"` // if not human-readable
}

// as per draft-gallagher-openpgp-literal-data-metadata
type Metadata struct {
    Encoding uint8            `json:"encoding"`
    Digest   []byte           `json:"digest,omitempty"`
    Verbatim *VerbatimMetadata `json:"verbatim,omitempty"`
}

type VerbatimMetadata struct {
    Format   byte   `json:"format"`
    Filename string `json:"filename"`
    Date     string `json:"date"`
}

// as per draft-ietf-openpgp-replacementkey
type Replacement struct {
    Class   ReplacementClass `json:"class"`
    Targets []*TargetRecord  `json:"targets"`
}
type TargetRecord struct {
    Target  VFP    `json:"target"`
    Imprint []byte `json:"imprint"`
}

// as per draft-ietf-rfc4880bis-10
type KeyBlock struct {
    Class uint8       `json:"class"` // unnamed in rfc4880bis
    Cert  *PrimaryKey `json:"cert"`
}

// flag bits

type KeyserverPrefs struct {
    NoModify bool `json:"noModify" default:"false"`
}

type Flags struct {
    SigCertify   bool `json:"sigCertify" default:"false"`
    SigLiteral   bool `json:"sigLiteral" default:"false"`
    EncComms     bool `json:"encComms" default:"false"`
    EncStore     bool `json:"encStore" default:"false"`
    Split        bool `json:"split" default:"false"`
    SigAuth      bool `json:"sigAuth" default:"false"`
    Communal     bool `json:"communal" default:"false"`
    EncADSK      bool `json:"encAdsk" default:"false"` // TODO: encRestricted ?
    SigTimestamp bool `json:"sigTimestamp" default:"false"`
}

type Features struct {
    SEIPDv1  bool `json:"seipdv1" default:"false"`
    Type20   bool `json:"type20" default:"false"`
    PubkeyV5 bool `json:"pubkeyv5" default:"false"`
    SEIPDv2  bool `json:"seipdv2" default:"false"`
}

type NotationClass struct {
    HumanReadable bool `json:"humanReadable" default:"false"`
}

type ReplacementClass struct {
    Inverse bool `json:"inverse" default:"false"`
}
*/
