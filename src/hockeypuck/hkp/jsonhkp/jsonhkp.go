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
	BitLength int    `json:"bitLength"`
	Curve     string `json:"curve,omitempty"`
}

type PublicKey struct {
	Fingerprint  string       `json:"fingerprint"`
	LongKeyID    string       `json:"longKeyID"`
	ShortKeyID   string       `json:"shortKeyID"`
	Creation     string       `json:"creation,omitempty"`
	Expiration   string       `json:"expiration,omitempty"`
	NeverExpires bool         `json:"neverExpires,omitempty"`
	Version      uint8        `json:"version"`
	Algorithm    Algorithm    `json:"algorithm"`
	BitLength    int          `json:"bitLength"`
	Signatures   []*Signature `json:"signatures,omitempty"`
	Packet       *Packet      `json:"packet,omitempty"`
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

	MD5     string    `json:"md5"`
	Length  int       `json:"length"`
	SubKeys []*SubKey `json:"subKeys,omitempty"`
	UserIDs []*UserID `json:"userIDs,omitempty"`
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

type Signature struct {
	SigType      int     `json:"sigType"`
	Revocation   bool    `json:"revocation,omitempty"`
	Primary      bool    `json:"primary,omitempty"`
	IssuerKeyID  string  `json:"issuerKeyID,omitempty"`
	Creation     string  `json:"creation,omitempty"`
	Expiration   string  `json:"expiration,omitempty"`
	NeverExpires bool    `json:"neverExpires,omitempty"`
	Packet       *Packet `json:"packet,omitempty"`
	PolicyURI    string  `json:"policyURI,omitempty"`
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
