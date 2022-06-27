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

// Package `openpgp` provides OpenPGP packet processing for keyservers. It is
// intended to support storage, retrieval, and non-authoritative verification
// of signed key material and certifications.
//
// import "hockeypuck/openpgp"
//

package openpgp

import (
	"io"

	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

// Alternative implementations of go-crypto/openpgp's OpaquePacket serialization
// functions, modified to prefer old-format headers wherever possible.
// Note that we DO NOT implement indefinite packet length old-format headers.

// SerializeCompat marshals the packet to a writer in its original form, using
// old format for packet types < 16, otherwise delegates to go-crypto/openpgp.
// Note that since we are outside the package here, this is implemented as a
// function rather than a class method.
func SerializeCompat(w io.Writer, op *packet.OpaquePacket) (err error) {
	if op.Tag >= 16 {
		return op.Serialize(w)
	} else {
		err = serializeOldHeader(w, op.Tag, len(op.Contents))
		if err == nil {
			_, err = w.Write(op.Contents)
		}
		return
	}
}

// serializeOldHeader writes an OpenPGP packet header to w in old format.
// This is only valid for packet types < 16. See RFC 4880, section 4.2.
func serializeOldHeader(w io.Writer, ptype uint8, length int) (err error) {
	var buf [6]byte
	var n int

	if ptype >= 16 {
		return ErrInvalidPacketType
	}

	if length < 256 {
		buf[0] = 0x80 | byte(ptype<<2)
		buf[1] = byte(length)
		n = 2
	} else if length < 65536 {
		buf[0] = 0x81 | byte(ptype<<2)
		buf[1] = byte(length >> 8)
		buf[2] = byte(length)
		n = 3
	} else {
		buf[0] = 0x82 | byte(ptype<<2)
		buf[1] = byte(length >> 24)
		buf[2] = byte(length >> 16)
		buf[3] = byte(length >> 8)
		buf[4] = byte(length)
		n = 5
	}

	_, err = w.Write(buf[:n])
	return
}

// The above depend on some private members of go-crypto/openpgp.
// Cut and paste them below and hope there are no bugs; we won't get the fixes.

// readHeader
func readHeader(r io.Reader) (tag packetType, length int64, contents io.Reader, err error) {
	var buf [4]byte
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return
	}
	if buf[0]&0x80 == 0 {
		err = errors.StructuralError("tag byte does not have MSB set")
		return
	}
	if buf[0]&0x40 == 0 {
		// Old format packet
		tag = packetType((buf[0] & 0x3f) >> 2)
		lengthType := buf[0] & 3
		if lengthType == 3 {
			length = -1
			contents = r
			return
		}
		lengthBytes := 1 << lengthType
		_, err = readFull(r, buf[0:lengthBytes])
		if err != nil {
			return
		}
		for i := 0; i < lengthBytes; i++ {
			length <<= 8
			length |= int64(buf[i])
		}
		contents = &spanReader{r, length}
		return
	}

	// New format packet
	tag = packetType(buf[0] & 0x3f)
	length, isPartial, err := readLength(r)
	if err != nil {
		return
	}
	if isPartial {
		contents = &partialLengthReader{
			remaining: length,
			isPartial: true,
			r:         r,
		}
		length = -1
	} else {
		contents = &spanReader{r, length}
	}
	return
}

type packetType uint8

const (
	packetTypeEncryptedKey              packetType = 1
	packetTypeSignature                 packetType = 2
	packetTypeSymmetricKeyEncrypted     packetType = 3
	packetTypeOnePassSignature          packetType = 4
	packetTypePrivateKey                packetType = 5
	packetTypePublicKey                 packetType = 6
	packetTypePrivateSubkey             packetType = 7
	packetTypeCompressed                packetType = 8
	packetTypeSymmetricallyEncrypted    packetType = 9
	packetTypeLiteralData               packetType = 11
	packetTypeUserId                    packetType = 13
	packetTypePublicSubkey              packetType = 14
	packetTypeUserAttribute             packetType = 17
	packetTypeSymmetricallyEncryptedMDC packetType = 18
	packetTypeAEADEncrypted             packetType = 20
)

func readFull(r io.Reader, buf []byte) (n int, err error) {
	n, err = io.ReadFull(r, buf)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

func readLength(r io.Reader) (length int64, isPartial bool, err error) {
	var buf [4]byte
	_, err = readFull(r, buf[:1])
	if err != nil {
		return
	}
	switch {
	case buf[0] < 192:
		length = int64(buf[0])
	case buf[0] < 224:
		length = int64(buf[0]-192) << 8
		_, err = readFull(r, buf[0:1])
		if err != nil {
			return
		}
		length += int64(buf[0]) + 192
	case buf[0] < 255:
		length = int64(1) << (buf[0] & 0x1f)
		isPartial = true
	default:
		_, err = readFull(r, buf[0:4])
		if err != nil {
			return
		}
		length = int64(buf[0])<<24 |
			int64(buf[1])<<16 |
			int64(buf[2])<<8 |
			int64(buf[3])
	}
	return
}

type partialLengthReader struct {
	r         io.Reader
	remaining int64
	isPartial bool
}

func (r *partialLengthReader) Read(p []byte) (n int, err error) {
	for r.remaining == 0 {
		if !r.isPartial {
			return 0, io.EOF
		}
		r.remaining, r.isPartial, err = readLength(r.r)
		if err != nil {
			return 0, err
		}
	}

	toRead := int64(len(p))
	if toRead > r.remaining {
		toRead = r.remaining
	}

	n, err = r.r.Read(p[:int(toRead)])
	r.remaining -= int64(n)
	if n < int(toRead) && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

type spanReader struct {
	r io.Reader
	n int64
}

func (l *spanReader) Read(p []byte) (n int, err error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}
	n, err = l.r.Read(p)
	l.n -= int64(n)
	if l.n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}
