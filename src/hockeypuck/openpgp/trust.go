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
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"time"

	gcerrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Trust struct {
	Packet

	Value         uint8
	Flags         uint8
	AppContext    string
	PacketContext uint8
	Notations     []*packet.Notation
	Signatures    []*Signature
}

const trustTag = "{trust}"
const trustAppContextNoisySKS = "SKS"
const trustAppContextQuietSKS = "sks"
const trustAppContextHKP = "hkp"

// contents implements the packetNode interface for default unclassified packets.
func (trust *Trust) contents() []packetNode {
	return []packetNode{trust}
}

func (trust *Trust) removeDuplicate(parent packetNode, dup packetNode) error {
	dupTrust, ok := dup.(*Trust)
	if !ok {
		return errors.Errorf("invalid packet duplicate: %+v", dup)
	}
	switch ppkt := parent.(type) {
	case *PrimaryKey:
		ppkt.Trusts = trustSlice(ppkt.Trusts).without(dupTrust)
	case *SubKey:
		ppkt.Trusts = trustSlice(ppkt.Trusts).without(dupTrust)
	case *UserID:
		ppkt.Trusts = trustSlice(ppkt.Trusts).without(dupTrust)
	case *Signature:
		ppkt.Trusts = trustSlice(ppkt.Trusts).without(dupTrust)
	}
	return nil
}

type trustSlice []*Trust

func (ss trustSlice) without(target *Trust) []*Trust {
	var result []*Trust
	for _, trust := range ss {
		if trust != target {
			result = append(result, trust)
		}
	}
	return result
}

func ParseTrust(op *packet.OpaquePacket, pubkeyUUID string, tp trustable) (*Trust, error) {
	var buf bytes.Buffer
	var err error
	var scope []string
	var expectedPacketContext uint8

	// tp may be nil, if we support detached trust packets
	if tp != nil {
		scope = []string{pubkeyUUID, tp.uuid()}
		expectedPacketContext = tp.packet().Tag
	}

	if err = op.Serialize(&buf); err != nil {
		return nil, errors.WithStack(err)
	}
	trust := &Trust{
		Packet: Packet{
			UUID: scopedDigest([]string{pubkeyUUID, scopedUUID}, trustTag, buf.Bytes()),
			Tag:  op.Tag,
			Data: buf.Bytes(),
		},
	}

	// Attempt to parse the opaque packet.
	err = trust.parse(op)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Check that the trust packet's PacketContext matches the trustable packet's tag
	if expectedPacketContext != trust.PacketContext {
		return nil, errors.Errorf("trust packet out of context: expected context %d, got %d", expectedPacketContext, trust.PacketContext)
	}
	return trust, nil
}

func (trust *Trust) parse(op *packet.OpaquePacket) error {
	p, err := op.Parse()
	if err != nil {
		return errors.WithStack(err)
	}

	switch t := p.(type) {
	case *packet.Trust:
		return trust.setTrust(t)
	}
	return errors.WithStack(ErrInvalidPacketType)
}

func (trust *Trust) setTrust(t *packet.Trust) error {
	if len(t.Contents) < 6 {
		return errors.Errorf("ignoring short trust packet")
	}
	trust.Value = uint8(t.Contents[0])
	trust.Flags = uint8(t.Contents[1])
	appContext := string(t.Contents[2:5])
	switch appContext {
	case trustAppContextNoisySKS:
		trust.AppContext = appContext
		trust.PacketContext = t.Contents[5]
	case trustAppContextQuietSKS:
		trust.AppContext = appContext
		trust.PacketContext = t.Contents[5]
	case trustAppContextHKP:
		trust.AppContext = appContext
		trust.PacketContext = t.Contents[5]
	default:
		return errors.Errorf("ignoring trust packet with unsupported app context %q", appContext)
	}

	opaqueSubpackets, err := packet.OpaqueSubpackets(t.Contents[6:])
	if err != nil {
		return err
	}

	// go-crypto does not expose subpacket parsers, so cut and paste the code
	// (with minor alterations) from (packet.Signature)parseSignatureSubpacket().
	for _, osp := range opaqueSubpackets {
		subpacket := osp.Contents
		var (
			packetType uint8
			isCritical bool
		)
		if len(subpacket) == 0 {
			return gcerrors.StructuralError("zero length subpacket")
		}
		if len(subpacket) == 0 {
			return gcerrors.StructuralError("zero length subpacket")
		}
		packetType = osp.SubType & 0x7f
		isCritical = osp.SubType&0x80 == 0x80

		switch packetType {
		case 20: // Notation
			if len(subpacket) < 8 {
				return gcerrors.StructuralError("notation data subpacket with bad length")
			}

			nameLength := uint32(subpacket[4])<<8 | uint32(subpacket[5])
			valueLength := uint32(subpacket[6])<<8 | uint32(subpacket[7])
			if len(subpacket) != int(nameLength)+int(valueLength)+8 {
				return gcerrors.StructuralError("notation data subpacket with bad length")
			}

			notation := packet.Notation{
				IsHumanReadable: (subpacket[0] & 0x80) == 0x80,
				Name:            string(subpacket[8:(nameLength + 8)]),
				Value:           subpacket[(nameLength + 8):(valueLength + nameLength + 8)],
				IsCritical:      isCritical,
			}
			trust.Notations = append(trust.Notations, &notation)
		case 32: // embedded signature
			op := packet.OpaquePacket{
				Tag:      2, // signature
				Contents: subpacket,
			}
			p, err := op.Parse()
			if err != nil {
				return err
			}
			switch s := p.(type) {
			case *packet.Signature:
				sig := new(Signature)
				if err := sig.setSignature(s, time.Unix(0, 0)); err != nil {
					return err
				}
				trust.Signatures = append(trust.Signatures, sig)
			default:
				return errors.Errorf("impossible error, sig parser returned non-sig packet")
			}
		default:
			// ignore any other kind of subpacket for now, unless it is marked as critical
			if isCritical {
				return errors.Errorf("critical trust subpacket with unsupported type")
			}
			continue
		}
	}

	return nil
}

// check whether the trust packet is a child of the given parent packet
// only defined for noisy trust packets with nonzero packet context
func (trust *Trust) isChildOf(op *packet.OpaquePacket) bool {
	if trust.AppContext != trustAppContextNoisySKS || trust.PacketContext == 0 || len(trust.Notations) == 0 {
		return false
	}
	// parent info should be stored in the first (hashed) notation
	firstNotation := trust.Notations[0]
	switch firstNotation.Name {
	case "parentMD5":
		parentMD5 := hex.EncodeToString(firstNotation.Value)
		return sksDigestOpaque([]*packet.OpaquePacket{op}, md5.New(), "") == parentMD5
	default:
		return false
	}
}

// trustPacketSKSView returns the SKS view of an opaque packet `op`.
// IFF `op` is a noisy SKS trust packet, truncate to the end of its first subpacket.
// `op` will be modified in the process. Otherwise, return nil.
func trustPacketSKSView(op *packet.OpaquePacket) *packet.OpaquePacket {
	if op.Tag != 12 {
		log.Warnf("non-trust packet passed to trustPacketSKSView")
		return nil
	}
	if len(op.Contents) < 6 {
		// legacy trust packets should throw a warning
		log.Warnf("legacy trust packet found while calculating sksDigest; ignoring")
		return nil
	}
	switch string(op.Contents[2:5]) {
	case trustAppContextNoisySKS:
		// go-crypto does not expose subpacket parsers, so cut and paste the code
		// (with minor alterations) from (packet.Signature)parseSignatureSubpacket().
		var length, lengthOfLength uint32
		switch {
		case op.Contents[6] < 192:
			length = uint32(op.Contents[6])
			lengthOfLength = 1
		case op.Contents[6] < 255:
			if len(op.Contents) < 8 {
				return nil
			}
			length = uint32(op.Contents[6]-192)<<8 + uint32(op.Contents[7]) + 192
			lengthOfLength = 2
		default:
			if len(op.Contents) < 11 {
				return nil
			}
			length = uint32(op.Contents[7])<<24 |
				uint32(op.Contents[8])<<16 |
				uint32(op.Contents[9])<<8 |
				uint32(op.Contents[10])
			lengthOfLength = 5
		}
		op.Contents = op.Contents[:length+lengthOfLength+6]
		return op
	case trustAppContextQuietSKS:
		// quiet SKS should be silently ignored
		return nil
	default:
		// any other kind of trust packet should throw a warning
		log.Warnf("unsupported trust packet found while calculating sksDigest; ignoring")
		return nil
	}
}

func (trust *Trust) trustPacket() (*packet.Trust, error) {
	op, err := trust.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s, ok := p.(*packet.Trust)
	if !ok {
		return nil, errors.Errorf("expected trust packet, got %T", p)
	}
	return s, nil
}
