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
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	log "github.com/sirupsen/logrus"
)

var ErrMissingSignature = fmt.Errorf("key material missing an expected signature")
var ErrBareRevocation = fmt.Errorf("bare revocation signature instead of key")

type ArmoredKeyWriter struct {
	headers map[string]string
}

type KeyWriterOption func(*ArmoredKeyWriter) error

func NewArmoredKeyWriter(options ...KeyWriterOption) (*ArmoredKeyWriter, error) {
	okw := &ArmoredKeyWriter{headers: map[string]string{}}
	for i := range options {
		err := options[i](okw)
		if err != nil {
			return nil, err
		}
	}
	return okw, nil
}

func ArmorHeaderComment(comment string) KeyWriterOption {
	return func(ow *ArmoredKeyWriter) error {
		ow.headers["Comment"] = comment
		return nil
	}
}

func ArmorHeaderVersion(version string) KeyWriterOption {
	return func(ow *ArmoredKeyWriter) error {
		ow.headers["Version"] = version
		return nil
	}
}

func WritePackets(w io.Writer, key *PrimaryKey) error {
	for _, node := range key.contents() {
		op, err := newOpaquePacket(node.packet().Data)
		if err != nil {
			return errors.WithStack(err)
		}
		err = op.Serialize(w)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func WritePacket(w io.Writer, node packetNode) error {
	op, err := newOpaquePacket(node.packet().Data)
	if err != nil {
		return errors.WithStack(err)
	}
	err = op.Serialize(w)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func WriteArmoredPackets(w io.Writer, roots []*PrimaryKey, options ...KeyWriterOption) error {
	akwr, err := NewArmoredKeyWriter(options...)
	if err != nil {
		return errors.WithStack(err)
	}
	armw, err := armor.Encode(w, openpgp.PublicKeyType, akwr.headers)
	if err != nil {
		return errors.WithStack(err)
	}
	defer armw.Close()
	fullRoots := []*PrimaryKey{}
	for _, node := range roots {
		// Write detached redacting revocations first (except for v6 keys)
		if node.Version < 6 {
			revoc, err := node.RedactingSignature()
			if err != nil {
				log.Warnf("could not redact 0x%s: %v", node.Fingerprint, err)
			}
			if revoc != nil {
				err = WritePacket(armw, revoc)
				if err != nil {
					return errors.WithStack(err)
				}
				continue
			}
		}
		// Otherwise keep hold of the key until later
		fullRoots = append(fullRoots, node)
	}
	for _, node := range fullRoots {
		// Write the remaining keys now
		err = WritePackets(armw, node)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

type OpaqueCert struct {
	Packets      []*packet.OpaquePacket
	RFingerprint string
	Md5          string
	Sha256       string
	Error        error
	Position     int64
}

func (ocert *OpaqueCert) setPosition(r io.Reader) {
	f, ok := r.(*os.File)
	if ok {
		pos, err := f.Seek(0, 1)
		if err == nil {
			ocert.Position = pos
			return
		}
	}
	ocert.Position = -1
}

func (ocert *OpaqueCert) Parse() (*PrimaryKey, error) {
	var err error
	var pubkey *PrimaryKey
	var signablePacket signable
	var trustablePacket trustable
	var keyCreationTime time.Time
	var length int
	for _, opkt := range ocert.Packets {
		if opkt.Tag == 6 { //packet.PacketTypePublicKey:
			if pubkey != nil {
				return nil, errors.Errorf("multiple primary keys in cert")
			}
			pubkey, err = ParsePrimaryKey(opkt)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid public key packet type")
			}
			signablePacket = pubkey
			trustablePacket = pubkey
			keyCreationTime = pubkey.Creation
		} else if pubkey != nil {
			switch opkt.Tag {
			case 14: //packet.PacketTypePublicSubKey:
				signablePacket = nil
				subkey, err := ParseSubKey(opkt)
				if err != nil {
					log.Warnf("unreadable subkey packet in key 0x%s: %v", pubkey.Fingerprint, err)
					continue
				} else {
					pubkey.SubKeys = append(pubkey.SubKeys, subkey)
					signablePacket = subkey
					trustablePacket = subkey
					keyCreationTime = subkey.Creation
				}
			case 13: //packet.PacketTypeUserId:
				signablePacket = nil
				uid, err := ParseUserID(opkt, pubkey.UUID)
				if err != nil {
					log.Warnf("unreadable user id packet in key 0x%s: %v", pubkey.Fingerprint, err)
					continue
				} else {
					pubkey.UserIDs = append(pubkey.UserIDs, uid)
					signablePacket = uid
					trustablePacket = uid
				}
			case 2: //packet.PacketTypeSignature:
				if signablePacket == nil {
					log.Warnf("signature out of context fp=%s", pubkey.Fingerprint)
					continue
				} else {
					sig, err := ParseSignature(opkt, keyCreationTime, pubkey.UUID, signablePacket.uuid())
					if err != nil {
						log.Warnf("unreadable signature packet in key 0x%s: %v", pubkey.Fingerprint, err)
						continue
					} else {
						signablePacket.appendSignature(sig)
						trustablePacket = sig
					}
				}
			case 12: //packet.PacketTypeTrust:
				trust, err := ParseTrust(opkt, pubkey.UUID, trustablePacket)
				if err != nil {
					log.Warnf("unreadable trust packet in key 0x%s: %v", pubkey.Fingerprint, err)
					continue
				}
				if trustablePacket == nil {
					// drop trust packets if there's nothing to attach them to
					log.Warnf("bare trust packets are not currently supported; ignoring")
					continue
				} else {
					trustablePacket.appendTrust(trust)
				}
			case 10: //packet.PacketTypeMarker:
				// drop marker packets, which can appear anywhere without altering the semantics
				log.Warnf("marker packet found in cert")
				continue
			default:
				// make sure that signatures over an unsupported packet are correctly dropped
				log.Warnf("unsupported packet type %d in certificate", opkt.Tag)
				signablePacket = nil
				trustablePacket = nil
				continue
			}

		} else if opkt.Tag == 12 { //packet.PacketTypeTrust:
			return nil, errors.Errorf("bare trust packets are not supported")
		} else if opkt.Tag == 2 { //packet.PacketTypeSignature:
			return nil, ErrBareRevocation
		}
		length += len(opkt.Contents)
	}
	if pubkey == nil {
		return nil, errors.New("primary public key not found")
	}
	pubkey.MD5, err = SksDigest(pubkey, md5.New())
	if err != nil {
		return nil, err
	}
	pubkey.Length = length
	return pubkey, nil
}

type OpaqueKeyReader struct {
	r            io.Reader
	maxKeyLen    int
	maxPacketLen int
	blacklist    map[string]bool
}

type KeyReaderOption func(*OpaqueKeyReader) error

func NewOpaqueKeyReader(r io.Reader, options ...KeyReaderOption) (*OpaqueKeyReader, error) {
	okr := &OpaqueKeyReader{r: r, blacklist: map[string]bool{}}
	for i := range options {
		err := options[i](okr)
		if err != nil {
			return nil, err
		}
	}
	return okr, nil
}

func MaxKeyLen(maxKeyLen int) KeyReaderOption {
	return func(or *OpaqueKeyReader) error {
		or.maxKeyLen = maxKeyLen
		return nil
	}
}

func MaxPacketLen(maxPacketLen int) KeyReaderOption {
	return func(or *OpaqueKeyReader) error {
		or.maxPacketLen = maxPacketLen
		return nil
	}
}

func Blacklist(blacklist []string) KeyReaderOption {
	return func(or *OpaqueKeyReader) error {
		for i := range blacklist {
			or.blacklist[strings.ToLower(blacklist[i])] = true
		}
		return nil
	}
}

func (r *OpaqueKeyReader) Read() ([]*OpaqueCert, error) {
	or := packet.NewOpaqueReader(r.r)
	var op *packet.OpaquePacket
	var err error
	var result []*OpaqueCert
	var current *OpaqueCert
	var currentKeyLen int
	var currentFingerprint string
	var initial = true // initial bare signature packet should be parsed
PARSE:
	for op, err = or.Next(); err == nil; op, err = or.Next() {
		packetLen := len(op.Contents)
		if r.maxPacketLen > 0 {
			if packetLen > r.maxPacketLen {
				log.WithFields(log.Fields{
					"length": packetLen,
					"max":    r.maxPacketLen,
					"fp":     currentFingerprint,
					"type":   op.Tag,
				}).Debug("dropped packet")
				continue
			}
		}
		switch op.Tag {
		case 6: //packet.PacketTypePublicKey:
			if current != nil {
				result = append(result, current)
			}
			current = nil
			currentKeyLen = 0
			currentFingerprint = ""
			initial = false

			pubkey, err := ParsePrimaryKey(op)
			if err != nil {
				continue PARSE
			}
			fp := pubkey.Fingerprint
			if len(r.blacklist) > 0 {
				if r.blacklist[fp] {
					log.WithFields(log.Fields{
						"fp": fp,
					}).Warn("blacklisted key")
					continue PARSE
				}
			}
			current = &OpaqueCert{}
			current.setPosition(r.r)
			currentFingerprint = fp
			current.Packets = append(current.Packets, op)
		case 2:
			//packet.PacketTypeSignature
			if current != nil {
				current.Packets = append(current.Packets, op)
			} else if initial {
				// This may be a bare revocation, put it in its own cert
				current = &OpaqueCert{}
				current.setPosition(r.r)
				currentKeyLen = 0
				currentFingerprint = ""
				current.Packets = append(current.Packets, op)
			}
		default:
			if current != nil {
				current.Packets = append(current.Packets, op)
			}
		}
		initial = false
		if current != nil {
			currentKeyLen += packetLen
			if r.maxKeyLen > 0 && currentKeyLen > r.maxKeyLen {
				log.WithFields(log.Fields{
					"length": currentKeyLen,
					"max":    r.maxKeyLen,
					"fp":     currentFingerprint,
				}).Warn("dropped key, max length exceeded")
				current = nil
				currentKeyLen = 0
				currentFingerprint = ""
				continue
			}
		}
	}
	if current != nil {
		result = append(result, current)
	}
	if err != io.EOF {
		return nil, err
	}
	return result, nil
}

func MustReadOpaqueCerts(r io.Reader, options ...KeyReaderOption) []*OpaqueCert {
	okr, err := NewOpaqueKeyReader(r, options...)
	if err != nil {
		panic(err)
	}
	ocerts, err := okr.Read()
	if err != nil {
		panic(err)
	}
	return ocerts
}

// SksDigest calculates a cumulative message digest on all OpenPGP packets for
// a given primary public key, using the same ordering as SKS, the
// Synchronizing Key Server. Use MD5 for matching digest values with SKS.
func SksDigest(key *PrimaryKey, h hash.Hash) (string, error) {
	var fail string
	var packets opaquePacketSlice
	for _, node := range key.contents() {
		op, err := newOpaquePacket(node.packet().Data)
		if err != nil {
			return fail, errors.WithStack(err)
		}
		// Trust packets require special handling
		if op.Tag == 12 {
			op = trustPacketSKSView(op)
			if op == nil {
				// the trust packet is not visible to SKS, skip
				continue
			}
		}
		packets = append(packets, op)
	}
	if len(packets) == 0 {
		return fail, errors.New("no packets found")
	}
	return sksDigestOpaque(packets, h, key.Fingerprint), nil
}

func sksDigestOpaque(packets []*packet.OpaquePacket, h hash.Hash, fp string) string {
	sort.Sort(opaquePacketSlice(packets))
	prevOpkt := &packet.OpaquePacket{}
	for _, opkt := range packets {
		if slices.Compare(opkt.Contents, prevOpkt.Contents) == 0 {
			log.WithFields(log.Fields{
				"fp":     fp,
				"length": len(opkt.Contents),
				"type":   opkt.Tag,
			}).Warn("duplicate packet found while calculating sksDigest")
		}
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
		prevOpkt = opkt
	}
	return hex.EncodeToString(h.Sum(nil))
}

type KeyReader struct {
	r       io.Reader
	options []KeyReaderOption
}

func NewKeyReader(r io.Reader, options ...KeyReaderOption) *KeyReader {
	return &KeyReader{r: r, options: options}
}

func (r *KeyReader) Read() ([]*PrimaryKey, error) {
	return r.readKeys()
}

func (r *KeyReader) readKeys() ([]*PrimaryKey, error) {
	okr, err := NewOpaqueKeyReader(r.r, r.options...)
	if err != nil {
		return nil, err
	}
	ocerts, err := okr.Read()
	if err != nil {
		return nil, err
	}
	result := make([]*PrimaryKey, len(ocerts))
	for i := range ocerts {
		result[i], err = ocerts[i].Parse()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func MustReadKeys(r io.Reader, options ...KeyReaderOption) []*PrimaryKey {
	kr := NewKeyReader(r, options...)
	keys, err := kr.Read()
	if err != nil {
		panic(err)
	}
	return keys
}

func ReadArmorKeys(r io.Reader, options ...KeyReaderOption) ([]*PrimaryKey, error) {
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	rdr := NewKeyReader(block.Body, options...)
	return rdr.Read()
}

func MustReadArmorKeys(r io.Reader, options ...KeyReaderOption) []*PrimaryKey {
	keys, err := ReadArmorKeys(r, options...)
	if err != nil {
		panic(err)
	}
	return keys
}
