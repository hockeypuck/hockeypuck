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

const trustTypeRedactedUserID = "redactedUserID"

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

func ParseTrust(op *packet.OpaquePacket, keyCreationTime time.Time, pubkeyUUID, scopedUUID string) (*Trust, error) {
	var buf bytes.Buffer
	var err error

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
	err = trust.parse(op, keyCreationTime, pubkeyUUID, scopedUUID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return trust, nil
}

func (trust *Trust) parse(op *packet.OpaquePacket, keyCreationTime time.Time, pubkeyUUID, scopedUUID string) error {
	p, err := op.Parse()
	if err != nil {
		return errors.WithStack(err)
	}

	switch t := p.(type) {
	case *packet.Trust:
		return trust.setTrust(t, keyCreationTime, pubkeyUUID, scopedUUID)
	}
	return errors.WithStack(ErrInvalidPacketType)
}

// UpdatePacket writes the current state of the trust packet into the embedded raw packet.
// This should be called after any updates are made to the trust packet's members.
func (trust *Trust) UpdatePacket() error {
	var subpackets = []outputSubpacket{}
	// Ensure the first Notation is written as the first subpacket, for noisy SKS hashing.
	for _, notation := range trust.Notations {
		subpackets = append(subpackets, outputSubpacket{contents: getData(notation), isCritical: notation.IsCritical, subpacketType: 20})
	}
	for _, sig := range trust.Signatures {
		op, _ := sig.opaquePacket()
		subpackets = append(subpackets, outputSubpacket{contents: op.Contents, subpacketType: 32})
	}
	var buf = make([]byte, 6+subpacketsLength(subpackets))
	buf[0] = trust.Value
	buf[1] = trust.Flags
	copy(buf[2:5], []byte(trust.AppContext))
	buf[5] = trust.PacketContext
	to := buf[6:]
	serializeSubpackets(to, subpackets)

	packet := packet.Trust{Contents: buf}
	packetBuf := bytes.Buffer{}
	err := packet.Serialize(&packetBuf)
	if err == nil {
		trust.Data = packetBuf.Bytes()
	}
	return err
}

func (trust *Trust) setTrust(t *packet.Trust, keyCreationTime time.Time, pubkeyUUID, scopedUUID string) error {
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
	for _, osp := range opaqueSubpackets {
		if len(osp.Contents) == 0 {
			return gcerrors.StructuralError("zero length subpacket")
		}

		switch osp.SubType & 0x7f { // zero the criticality bit
		case 20: // Notation
			notation, err := parseNotation(osp)
			if err != nil {
				return err
			}
			trust.Notations = append(trust.Notations, notation)
		case 32: // embedded signature
			sig, err := parseEmbeddedSig(osp, keyCreationTime, pubkeyUUID, scopedUUID)
			if err != nil {
				return err
			}
			trust.Signatures = append(trust.Signatures, sig)
		default:
			// ignore any other kind of subpacket for now, unless it is marked as critical
			if osp.SubType&0x80 == 0x80 { // if critical
				return errors.Errorf("critical trust subpacket with unsupported type")
			}
			continue
		}
	}

	if len(trust.Notations) == 0 {
		return errors.Errorf("No notations found in trust packet")
	}
	if trust.AppContext == trustAppContextNoisySKS && len(trust.Notations) <= 1 {
		return errors.Errorf("No unhashed notations found in noisy trust packet")
	}
	return nil
}

// A noisy trust packet's UUIDNotation is the first (hashed) notation.
func (trust *Trust) UUIDNotation() *packet.Notation {
	if trust.AppContext == trustAppContextNoisySKS && len(trust.Notations) > 1 {
		return trust.Notations[0]
	}
	return nil
}

// A trust packet's type notation is the first *unhashed* notation.
func (trust *Trust) TrustTypeNotation() *packet.Notation {
	if trust.AppContext == trustAppContextNoisySKS {
		if len(trust.Notations) < 2 {
			return nil
		}
		return trust.Notations[1]
	} else {
		if len(trust.Notations) == 0 {
			return nil
		}
		return trust.Notations[0]
	}
}

// Get a notation by its name. Only the first matching notation is returned.
func (trust *Trust) GetNotationByName(name string) *packet.Notation {
	for _, notation := range trust.Notations {
		if notation.Name == name {
			return notation
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

// CheckTrust represents the result of checking a trust.
type CheckTrust struct {
	Trust  *Trust
	UserID *UserID
	Error  error
}

// CheckTrusts holds trust packets on OpenPGP targets, which may be keys, user
// IDs, user attributes or signatures.
type CheckTrusts struct {
	RedactedUserIDs []*CheckTrust
	Errors          []*CheckTrust

	target packetNode
}

func plausifyTrust(parent trustable, trust *Trust) error {
	parentPacketType := parent.packet().Tag
	// Check that the trust packet's PacketContext matches the trustable packet's type
	if parentPacketType != trust.PacketContext {
		return errors.Errorf("misplaced trust packet, parent type %d, trust context %d", parentPacketType, trust.PacketContext)
	}
	if trust.AppContext == trustAppContextNoisySKS {
		op, err := parent.packet().opaquePacket()
		if err != nil {
			return errors.WithStack(err)
		}
		ok := trust.isChildOf(op)
		if !ok {
			return errors.Errorf("misplaced trust packet, not child of %T", op)
		}
	}
	return nil
}

// NewRedactedUserID creates a new Trust packet representing a redacted UserID packet.
// It will contain the UserID string as a notation, and the most recent valid
// self-certification as an embedded signature.
//
// TODO: check that uid.Signatures[0] always returns the correct signature
func NewRedactedUserID(uid *UserID) *Trust {
	primaryNotation := &packet.Notation{
		Name:       trustTypeRedactedUserID,
		Value:      []byte(uid.Keywords),
		IsCritical: true,
	}
	t := &Trust{
		Notations:  []*packet.Notation{primaryNotation},
		Signatures: []*Signature{uid.Signatures[0]},
	}
	t.UpdatePacket()
	return t
}
