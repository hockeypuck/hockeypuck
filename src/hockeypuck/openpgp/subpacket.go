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
	"time"

	gcerrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// go-crypto does not expose subpacket serializers, so cut and paste the appropriate
// type and functions from packet.Signature. Omit the `hashed` field of outputSubpacket,
// as it adds an unnecessary extra point of failure.

// outputSubpacket represents a subpacket to be marshaled.
type outputSubpacket struct {
	subpacketType uint8
	isCritical    bool
	contents      []byte
}

// subpacketLengthLength returns the length, in bytes, of an encoded length value.
func subpacketLengthLength(length int) int {
	if length < 192 {
		return 1
	}
	if length < 16320 {
		return 2
	}
	return 5
}

// serializeSubpacketLength marshals the given length into to.
func serializeSubpacketLength(to []byte, length int) int {
	// RFC 9580, Section 4.2.1.
	if length < 192 {
		to[0] = byte(length)
		return 1
	}
	if length < 16320 {
		length -= 192
		to[0] = byte((length >> 8) + 192)
		to[1] = byte(length)
		return 2
	}
	to[0] = 255
	to[1] = byte(length >> 24)
	to[2] = byte(length >> 16)
	to[3] = byte(length >> 8)
	to[4] = byte(length)
	return 5
}

// subpacketsLength returns the serialized length, in bytes, of the given
// subpackets.
func subpacketsLength(subpackets []outputSubpacket) (length int) {
	for _, subpacket := range subpackets {
		length += subpacketLengthLength(len(subpacket.contents) + 1)
		length += 1 // type byte
		length += len(subpacket.contents)
	}
	return
}

// serializeSubpackets marshals the given subpackets into to.
func serializeSubpackets(to []byte, subpackets []outputSubpacket) {
	for _, subpacket := range subpackets {
		n := serializeSubpacketLength(to, len(subpacket.contents)+1)
		to[n] = byte(subpacket.subpacketType)
		if subpacket.isCritical {
			to[n] |= 0x80
		}
		to = to[1+n:]
		n = copy(to, subpacket.contents)
		to = to[n:]
	}
}

// end cloned serializers

// (*packet.Notation)getData is a private method, so duplicate it into a function.

func getData(notation *packet.Notation) []byte {
	nameData := []byte(notation.Name)
	nameLen := len(nameData)
	valueLen := len(notation.Value)

	data := make([]byte, 8+nameLen+valueLen)
	if notation.IsHumanReadable {
		data[0] = 0x80
	}

	data[4] = byte(nameLen >> 8)
	data[5] = byte(nameLen)
	data[6] = byte(valueLen >> 8)
	data[7] = byte(valueLen)
	copy(data[8:8+nameLen], nameData)
	copy(data[8+nameLen:], notation.Value)
	return data
}

// go-crypto does not expose a notation subpacket parser, so copy the lines we need out
// of the monster method parseSignatureSubpacket(). The caller should parse the subpacket
// area into opaque subpackets first, so we don't have to reimplement a length parser.
// (unlike parseSignatureSubpacket() which operates on the raw []byte slice)
func parseNotation(osp *packet.OpaqueSubpacket) (*packet.Notation, error) {
	subpacket := osp.Contents
	if len(subpacket) < 8 {
		return nil, gcerrors.StructuralError("notation data subpacket with bad length")
	}

	nameLength := uint32(subpacket[4])<<8 | uint32(subpacket[5])
	valueLength := uint32(subpacket[6])<<8 | uint32(subpacket[7])
	if len(subpacket) != int(nameLength)+int(valueLength)+8 {
		return nil, gcerrors.StructuralError("notation data subpacket with bad length")
	}
	isCritical := osp.SubType&0x80 == 0x80

	return &packet.Notation{
		IsHumanReadable: (subpacket[0] & 0x80) == 0x80,
		Name:            string(subpacket[8:(nameLength + 8)]),
		Value:           subpacket[(nameLength + 8):(valueLength + nameLength + 8)],
		IsCritical:      isCritical,
	}, nil
}

// parseEmbeddedSig converts an OpaqueSubpacket to an OpaquePacket and parses it as a normal signature packet
func parseEmbeddedSig(osp *packet.OpaqueSubpacket, keyCreationTime time.Time, pubkeyUUID, scopedUUID string) (*Signature, error) {
	op := &packet.OpaquePacket{
		Tag:      2, // signature
		Contents: osp.Contents,
	}
	sig, err := ParseSignature(op, keyCreationTime, pubkeyUUID, scopedUUID)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
