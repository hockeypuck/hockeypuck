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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

var ErrInvalidPacketType error = fmt.Errorf("invalid packet type")
var ErrPacketRecordState error = fmt.Errorf("packet record state has not been properly initialized")

type Packet struct {

	// UUID is a universally unique identifier string for this packet. Not
	// necessarily a standard UUID format though.
	UUID string

	// Tag indicates the OpenPGP package tag type.
	Tag uint8

	// Count indicates the number of times this packet occurs in the certificate.
	Count int

	// Data contains the raw packet bytes, including header.
	Data []byte
}

// packetNode defines a tree-like hierarchy by which OpenPGP packets can be
// usefully traversed.
type packetNode interface {
	contents() []packetNode
	packet() *Packet
	removeDuplicate(parent packetNode, target packetNode) error
	uuid() string
}

type signable interface {
	appendSignature(*Signature)

	packetNode
}

// packet implements the packetNode interface.
func (p *Packet) packet() *Packet {
	return p
}

// contents implements the packetNode interface for default unclassified packets.
func (p *Packet) contents() []packetNode {
	return []packetNode{p}
}

func (p *Packet) uuid() string {
	return p.UUID
}

func (p *Packet) removeDuplicate(parent packetNode, dup packetNode) error {
	return errors.Errorf("Default implementation of removeDuplicate() should never be called")
}

func (p *Packet) opaquePacket() (*packet.OpaquePacket, error) {
	return newOpaquePacket(p.Data)
}

func newOpaquePacket(buf []byte) (*packet.OpaquePacket, error) {
	r := packet.NewOpaqueReader(bytes.NewBuffer(buf))
	return r.Next()
}

type opaquePacketSlice []*packet.OpaquePacket

func (ps opaquePacketSlice) Len() int {
	return len(ps)
}

func (ps opaquePacketSlice) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps opaquePacketSlice) Less(i, j int) bool {
	cmp := int32(ps[i].Tag) - int32(ps[j].Tag)
	if cmp < 0 {
		return true
	} else if cmp > 0 {
		return false
	}
	return bytes.Compare(ps[i].Contents, ps[j].Contents) < 0
}

func scopedDigest(parents []string, tag string, packet []byte) string {
	h := sha256.New()
	for i := range parents {
		h.Write([]byte(parents[i]))
		h.Write([]byte(tag))
	}
	h.Write(packet)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
