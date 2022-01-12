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

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	pgperrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"

	log "hockeypuck/logrus"
)

var ErrMissingSignature = fmt.Errorf("Key material missing an expected signature")

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
		op, err := newOpaquePacket(node.packet().Packet)
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
	for _, node := range roots {
		err = WritePackets(armw, node)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

type OpaqueKeyring struct {
	Packets      []*packet.OpaquePacket
	RFingerprint string
	Md5          string
	Sha256       string
	Error        error
	Position     int64
}

func (okr *OpaqueKeyring) setPosition(r io.Reader) {
	f, ok := r.(*os.File)
	if ok {
		pos, err := f.Seek(0, 1)
		if err == nil {
			okr.Position = pos
			return
		}
	}
	okr.Position = -1
}

func (ok *OpaqueKeyring) Parse() (*PrimaryKey, error) {
	var err error
	var pubkey *PrimaryKey
	var signablePacket signable
	var keyCreationTime time.Time
	var length int
	for _, opkt := range ok.Packets {
		length += len(opkt.Contents)
		var badPacket *packet.OpaquePacket
		if opkt.Tag == 6 { //packet.PacketTypePublicKey:
			if pubkey != nil {
				return nil, errors.Errorf("multiple public keys in keyring")
			}
			pubkey, err = ParsePrimaryKey(opkt)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid public key packet type")
			}
			signablePacket = pubkey
			keyCreationTime = pubkey.Creation
		} else if pubkey != nil {
			switch opkt.Tag {
			case 14: //packet.PacketTypePublicSubKey:
				signablePacket = nil
				subkey, err := ParseSubKey(opkt)
				if err != nil {
					log.Debugf("unreadable subkey packet in key 0x%s: %v", pubkey.KeyID(), err)
					badPacket = opkt
				} else {
					pubkey.SubKeys = append(pubkey.SubKeys, subkey)
					signablePacket = subkey
					keyCreationTime = subkey.Creation
				}
			case 13: //packet.PacketTypeUserId:
				signablePacket = nil
				uid, err := ParseUserID(opkt, pubkey.UUID)
				if err != nil {
					log.Debugf("unreadable user id packet in key 0x%s: %v", pubkey.KeyID(), err)
					badPacket = opkt
				} else {
					pubkey.UserIDs = append(pubkey.UserIDs, uid)
					signablePacket = uid
				}
			case 17: //packet.PacketTypeUserAttribute:
				signablePacket = nil
				uat, err := ParseUserAttribute(opkt, pubkey.UUID)
				if err != nil {
					log.Debugf("unreadable user attribute packet in key 0x%s: %v", pubkey.KeyID(), err)
					badPacket = opkt
				} else {
					pubkey.UserAttributes = append(pubkey.UserAttributes, uat)
					signablePacket = uat
				}
			case 2: //packet.PacketTypeSignature:
				if signablePacket == nil {
					log.Debugf("signature out of context")
					badPacket = opkt
				} else {
					sig, err := ParseSignature(opkt, keyCreationTime, pubkey.UUID, signablePacket.uuid())
					if err != nil {
						log.Debugf("unreadable signature packet in key 0x%s: %v", pubkey.KeyID(), err)
						badPacket = opkt
					} else {
						signablePacket.appendSignature(sig)
					}
				}
			default:
				badPacket = opkt
			}

			if badPacket != nil {
				var badParent string
				if signablePacket != nil {
					badParent = signablePacket.uuid()
				} else {
					badParent = pubkey.uuid()
				}
				other, err := ParseOther(badPacket, badParent)
				if err != nil {
					return nil, errors.WithStack(err)
				}
				_, isStructuralError := badPacket.Reason.(pgperrors.StructuralError)
				if badPacket.Reason == io.ErrUnexpectedEOF || isStructuralError {
					log.Debugf("malformed packet in key 0x%s: %v", pubkey.KeyID(), badPacket.Reason)
					other.Malformed = true
				}
				pubkey.Others = append(pubkey.Others, other)
			}
		}
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

func (r *OpaqueKeyReader) Read() ([]*OpaqueKeyring, error) {
	or := packet.NewOpaqueReader(r.r)
	var op *packet.OpaquePacket
	var err error
	var result []*OpaqueKeyring
	var current *OpaqueKeyring
	var currentKeyLen int
	var currentFingerprint string
PARSE:
	for op, err = or.Next(); err == nil; op, err = or.Next() {
		packetLen := len(op.Contents)
		if r.maxPacketLen > 0 {
			if packetLen > r.maxPacketLen {
				log.WithFields(log.Fields{
					"length": packetLen,
					"max":    r.maxPacketLen,
				}).Warn("dropped packet")
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

			pubkey, err := ParsePrimaryKey(op)
			if err != nil {
				continue PARSE
			}
			fp := pubkey.Fingerprint()
			if len(r.blacklist) > 0 {
				if r.blacklist[fp] {
					log.WithFields(log.Fields{
						"fp": fp,
					}).Warn("blacklisted key")
					continue PARSE
				}
			}
			current = &OpaqueKeyring{}
			current.setPosition(r.r)
			currentKeyLen = 0
			currentFingerprint = fp
			fallthrough
		case 2, 13, 14, 17:
			//packet.PacketTypeUserId,
			//packet.PacketTypeUserAttribute,
			//packet.PacketTypePublicSubKey,
			//packet.PacketTypeSignature
			if current != nil {
				current.Packets = append(current.Packets, op)
			}
		}
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

func MustReadOpaqueKeys(r io.Reader, options ...KeyReaderOption) []*OpaqueKeyring {
	or, err := NewOpaqueKeyReader(r, options...)
	if err != nil {
		panic(err)
	}
	opkrs, err := or.Read()
	if err != nil {
		panic(err)
	}
	return opkrs
}

// SksDigest calculates a cumulative message digest on all OpenPGP packets for
// a given primary public key, using the same ordering as SKS, the
// Synchronizing Key Server. Use MD5 for matching digest values with SKS.
func SksDigest(key *PrimaryKey, h hash.Hash) (string, error) {
	var fail string
	var packets opaquePacketSlice
	for _, node := range key.contents() {
		op, err := newOpaquePacket(node.packet().Packet)
		if err != nil {
			return fail, errors.WithStack(err)
		}
		packets = append(packets, op)
	}
	if len(packets) == 0 {
		return fail, errors.New("no packets found")
	}
	return sksDigestOpaque(packets, h), nil
}

func sksDigestOpaque(packets []*packet.OpaquePacket, h hash.Hash) string {
	sort.Sort(opaquePacketSlice(packets))
	for _, opkt := range packets {
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
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
	opkrs, err := okr.Read()
	if err != nil {
		return nil, err
	}
	result := make([]*PrimaryKey, len(opkrs))
	for i := range opkrs {
		result[i], err = opkrs[i].Parse()
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
