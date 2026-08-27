/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2026 Casey Marshall and the Hockeypuck Contributors

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
	"fmt"
	"strings"
	"time"

	gocrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// A tombstone is a certificate consisting of a single trust packet, stored
// under the fingerprint of a key this server refuses to hold. It replaces the
// key material rather than sitting alongside it, so a blocked fingerprint's row
// is occupied and an incoming copy of the key collides with it on insert.
//
// The trust packet uses the noisy SKS app context, which means its SKS digest
// covers only its first subpacket (see trustPacketSKSView). The first notation
// is therefore the whole of a tombstone's reconciliation identity: two operators
// who block the same key agree on its digest however much their annotations
// differ, so reconciliation converges instead of churning. Everything after the
// first notation - origin, reason, the signature binding them - rides along
// outside the SKS digest and is covered by the trust digest instead.
const (
	// trustTypeBlockedKey marks a trust packet as a tombstone. Like
	// trustTypeRedactedUserID it is carried as the trust packet's type notation,
	// which for a noisy packet is the second notation.
	trustTypeBlockedKey = "blockedKey"

	// tombstoneVersion is the value of the type notation. It exists so the
	// format can be revised without another flag day.
	tombstoneVersion = "1"

	// tombstoneFingerprintNotation carries the blocked key's fingerprint and
	// MUST be the first notation; see the note above on reconciliation identity.
	tombstoneFingerprintNotation = "blockedFingerprint"

	// tombstoneOriginNotation names the operator who issued the block. A peer
	// decides whether to accept a tombstone by checking this against its
	// configured trusted origins, and the signature is what makes it mean
	// anything.
	tombstoneOriginNotation = "blocklistOrigin"

	// tombstoneReasonNotation carries a short reason code. It deliberately does
	// not carry free text: a tombstone is published to every peer, so anything
	// written here is disclosed to all of them.
	tombstoneReasonNotation = "blocklistReason"
)

// ErrNotTombstone is returned when a certificate is not a blocklist tombstone.
var ErrNotTombstone = fmt.Errorf("not a blocklist tombstone")

// Tombstone describes a blocked key.
type Tombstone struct {
	// Fingerprint is the blocked key's fingerprint, lowercase hex.
	Fingerprint string
	// Origin names the operator who issued the block, e.g. a hostname.
	Origin string
	// Reason is an optional short code. It MUST NOT be free text; see
	// tombstoneReasonNotation.
	Reason string
}

// Validate checks that a Tombstone can be safely serialised and signed.
func (ts Tombstone) Validate() error {
	fp := strings.ToLower(ts.Fingerprint)
	switch len(fp) {
	case 32, 40, 64: // v3, v4, v6 fingerprints
	default:
		return errors.Errorf("%q is not a fingerprint (expected 32, 40 or 64 hex digits, got %d)",
			ts.Fingerprint, len(ts.Fingerprint))
	}
	for _, r := range fp {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return errors.Errorf("%q is not hexadecimal", ts.Fingerprint)
		}
	}
	if ts.Origin == "" {
		return errors.New("tombstone origin is required")
	}
	// The signing message is newline delimited, so a newline in a field would
	// let one field impersonate another.
	for _, field := range []string{ts.Origin, ts.Reason} {
		if strings.ContainsAny(field, "\n\r") {
			return errors.Errorf("tombstone fields must not contain newlines: %q", field)
		}
	}
	return nil
}

// normalise returns a copy with the fingerprint folded to lowercase.
func (ts Tombstone) normalise() Tombstone {
	ts.Fingerprint = strings.ToLower(ts.Fingerprint)
	return ts
}

// SigningMessage returns the canonical bytes an origin signs to bind its name to
// this block. It covers every field the tombstone asserts, so a peer that
// verifies the signature knows the origin really did issue this block for this
// fingerprint, and not merely that some node passed it along.
func (ts Tombstone) SigningMessage() []byte {
	ts = ts.normalise()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s=%s\n", tombstoneFingerprintNotation, ts.Fingerprint)
	fmt.Fprintf(&buf, "%s=%s\n", tombstoneOriginNotation, ts.Origin)
	if ts.Reason != "" {
		fmt.Fprintf(&buf, "%s=%s\n", tombstoneReasonNotation, ts.Reason)
	}
	return buf.Bytes()
}

func (ts Tombstone) String() string {
	if ts.Reason != "" {
		return fmt.Sprintf("0x%s blocked by %s (%s)", ts.Fingerprint, ts.Origin, ts.Reason)
	}
	return fmt.Sprintf("0x%s blocked by %s", ts.Fingerprint, ts.Origin)
}

// notations renders the tombstone as an ordered notation set. The order is
// load-bearing: the fingerprint must come first so that it alone determines the
// SKS digest, and the type notation must come second because that is where
// Trust.TrustTypeNotation looks for it.
func (ts Tombstone) notations() []*packet.Notation {
	ts = ts.normalise()
	ns := []*packet.Notation{
		{Name: tombstoneFingerprintNotation, Value: []byte(ts.Fingerprint), IsCritical: true},
		{Name: trustTypeBlockedKey, Value: []byte(tombstoneVersion), IsCritical: true},
		{Name: tombstoneOriginNotation, Value: []byte(ts.Origin)},
	}
	if ts.Reason != "" {
		ns = append(ns, &packet.Notation{Name: tombstoneReasonNotation, Value: []byte(ts.Reason)})
	}
	return ns
}

// NewTombstone builds the certificate that stands in for a blocked key. The
// supplied signatures should be over ts.SigningMessage(); a tombstone with none
// is only ever acceptable from a local operator, never from a peer.
func NewTombstone(ts Tombstone, sigs ...*Signature) (*PrimaryKey, error) {
	if err := ts.Validate(); err != nil {
		return nil, errors.WithStack(err)
	}
	ts = ts.normalise()

	trust := &Trust{
		AppContext: trustAppContextNoisySKS,
		// A tombstone has no parent packet, so it is nobody's child.
		PacketContext: 0,
		Notations:     ts.notations(),
		Signatures:    sigs,
	}
	if err := trust.UpdatePacket(); err != nil {
		return nil, errors.WithStack(err)
	}

	pubkey := &PrimaryKey{
		PublicKey: PublicKey{
			Fingerprint: ts.Fingerprint,
			Packet: Packet{
				UUID: ts.Fingerprint,
				Tag:  trust.Tag,
				Data: trust.Data,
			},
		},
	}
	var err error
	pubkey.MD5, pubkey.TrustMD5, err = SksDigest(pubkey, md5.New(), md5.New())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pubkey.Length = len(trust.Data)
	return pubkey, nil
}

// IsTombstone reports whether a certificate stands in for a blocked key rather
// than carrying real key material. Real certificates are rooted at a public key
// packet (tag 6); only a tombstone is rooted at a trust packet.
func IsTombstone(pubkey *PrimaryKey) bool {
	return pubkey != nil && pubkey.Tag == 12
}

// TombstoneOf returns what a tombstone certificate asserts, along with the
// signatures offered in support of it. It returns ErrNotTombstone if pubkey is
// ordinary key material.
func TombstoneOf(pubkey *PrimaryKey) (*Tombstone, []*Signature, error) {
	if !IsTombstone(pubkey) {
		return nil, nil, errors.WithStack(ErrNotTombstone)
	}
	op, err := newOpaquePacket(pubkey.Data)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	trust, err := ParseTrust(op, pubkey.Creation, pubkey.UUID, pubkey.UUID)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return tombstoneOfTrust(trust)
}

func tombstoneOfTrust(trust *Trust) (*Tombstone, []*Signature, error) {
	typeNotation := trust.TrustTypeNotation()
	if typeNotation == nil || typeNotation.Name != trustTypeBlockedKey {
		return nil, nil, errors.WithStack(ErrNotTombstone)
	}
	if version := string(typeNotation.Value); version != tombstoneVersion {
		return nil, nil, errors.Errorf("unsupported tombstone version %q", version)
	}
	// The fingerprint must be the FIRST notation, not merely present: its
	// position is what fixes the SKS digest, so accepting it elsewhere would
	// accept a tombstone whose identity does not match its digest.
	if len(trust.Notations) == 0 || trust.Notations[0].Name != tombstoneFingerprintNotation {
		return nil, nil, errors.Errorf("tombstone does not lead with %s", tombstoneFingerprintNotation)
	}
	ts := &Tombstone{Fingerprint: string(trust.Notations[0].Value)}
	if n := trust.GetNotationByName(tombstoneOriginNotation); n != nil {
		ts.Origin = string(n.Value)
	}
	if n := trust.GetNotationByName(tombstoneReasonNotation); n != nil {
		ts.Reason = string(n.Value)
	}
	if err := ts.Validate(); err != nil {
		return nil, nil, errors.WithStack(err)
	}
	*ts = ts.normalise()
	return ts, trust.Signatures, nil
}

// isTombstonePacket cheaply reports whether an opaque trust packet is a bare
// tombstone rather than an annotation attached to the key material before it.
// The reader needs to tell the two apart without parsing, so that a tombstone in
// the middle of a keydump starts its own certificate instead of being attached
// to whatever key happened to precede it.
func isTombstonePacket(op *packet.OpaquePacket) bool {
	if op.Tag != 12 || len(op.Contents) < 6 {
		return false
	}
	// An attached trust packet names the packet type it annotates; a tombstone
	// annotates nothing.
	if op.Contents[5] != 0 {
		return false
	}
	if string(op.Contents[2:5]) != trustAppContextNoisySKS {
		return false
	}
	subpackets, err := packet.OpaqueSubpackets(op.Contents[6:])
	if err != nil || len(subpackets) == 0 {
		return false
	}
	if subpackets[0].SubType&0x7f != 20 { // notation
		return false
	}
	notation, err := parseNotation(subpackets[0])
	if err != nil {
		return false
	}
	return notation.Name == tombstoneFingerprintNotation
}

// parseTombstoneCert builds the certificate for a bare trust packet found where
// a public key packet would otherwise start a certificate.
func parseTombstoneCert(op *packet.OpaquePacket) (*PrimaryKey, error) {
	trust, err := ParseTrust(op, time.Time{}, "", "")
	if err != nil {
		return nil, errors.Wrap(err, "unreadable tombstone trust packet")
	}
	ts, sigs, err := tombstoneOfTrust(trust)
	if err != nil {
		return nil, err
	}
	// Rebuild rather than adopting the incoming bytes, so that a tombstone is
	// stored in exactly one canonical form however a peer chose to serialise it.
	pubkey, err := NewTombstone(*ts, sigs...)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

// ErrTombstoneUnverifiable reports that this server could not check a tombstone
// rather than that it found it bad. A caller sweeping stored blocks must tell
// the two apart: a block it cannot judge has to be kept, or a trusted key that
// is merely unreadable here would silently withdraw the blocks it signed.
var ErrTombstoneUnverifiable = errors.New("tombstone could not be checked")

// trustedKeyring re-reads the keys trusted for an origin as go-crypto entities,
// so that a tombstone signature can be checked by the high-level detached
// signature path rather than by raw signature maths.
//
// This is the same round trip the admin key check makes in hkp.Handler:
// hockeypuck holds a key as its own packet tree, and go-crypto wants an Entity.
func trustedKeyring(trusted []*PrimaryKey) gocrypto.EntityList {
	var keyring gocrypto.EntityList
	for _, key := range trusted {
		if key == nil {
			continue
		}
		var buf bytes.Buffer
		if err := WritePackets(&buf, key); err != nil {
			log.Warnf("cannot serialize trusted blocklist key 0x%s: %v", key.Fingerprint, err)
			continue
		}
		entity, err := gocrypto.ReadEntity(packet.NewReader(&buf))
		if err != nil {
			log.Warnf("cannot read trusted blocklist key 0x%s: %v", key.Fingerprint, err)
			continue
		}
		keyring = append(keyring, entity)
	}
	return keyring
}

// VerifyTombstone reports the fingerprint of the trusted key that vouches for a
// tombstone, or an error if none does.
//
// This is what makes the origin notation mean anything. Without it a tombstone
// asserts an origin that any node could have written, and a peer accepting on
// the strength of that name alone would take a block from anyone willing to
// type it. With it, accepting a tombstone means the named origin really did
// issue this block for this fingerprint, whoever passed it along.
//
// The caller supplies the keys it trusts for the tombstone's origin; deciding
// which those are is configuration, not cryptography.
func VerifyTombstone(ts Tombstone, sigs []*Signature, trusted []*PrimaryKey) (string, error) {
	if err := ts.Validate(); err != nil {
		return "", errors.WithStack(err)
	}
	if len(sigs) == 0 {
		return "", errors.Errorf("tombstone for 0x%s carries no signature", ts.Fingerprint)
	}
	if len(trusted) == 0 {
		return "", errors.Wrapf(ErrTombstoneUnverifiable, "no keys are trusted for origin %q", ts.Origin)
	}
	keyring := trustedKeyring(trusted)
	if len(keyring) == 0 {
		// The keys are here but none of them could be read, so this server
		// cannot judge the block. "Not signed by a trusted key" would be a
		// different claim, and acting on it would delete blocks over a parsing
		// failure in the key that vouches for them.
		return "", errors.Wrapf(ErrTombstoneUnverifiable,
			"none of the keys trusted for origin %q could be read", ts.Origin)
	}
	message := ts.SigningMessage()

	var lastErr error
	for _, sig := range sigs {
		// The signing message is a bare byte string, so only a binary document
		// signature can be over it. Accepting other types would let a signature
		// made for some other purpose be replayed as a block; a text signature
		// in particular attests to a line-ending-canonicalised form of its
		// input rather than to these bytes.
		if sig.SigType != packet.SigTypeBinary {
			lastErr = errors.Errorf("tombstone signature has type %d, want a binary document signature", sig.SigType)
			continue
		}
		// The high-level path rather than a bare VerifySignature: as well as the
		// signature maths it enforces that the issuing key is allowed to sign,
		// and that neither it, its primary, its primary identity, nor the
		// signature itself is revoked or expired. Checking the maths alone would
		// let a revoked, expired or encryption-only subkey of a trusted primary
		// authorise new blocks.
		//
		// Note that this also refuses a signature dated in the future, because
		// SigExpired counts that as expired. An operator whose clock runs fast
		// therefore issues blocks their peers refuse, and that a peer which had
		// already stored one unverified will drop at its next sweep. Nothing is
		// lost permanently - reconciliation offers the block again once the
		// clocks agree - but it is a reason to keep an issuing node's clock
		// honest. Tolerating a skew window here would mean stepping outside this
		// path, which is where all the other validity checks live.
		signer, err := gocrypto.CheckDetachedSignature(keyring,
			bytes.NewReader(message), bytes.NewReader(sig.Data), nil)
		if err != nil {
			lastErr = err
			continue
		}
		return hex.EncodeToString(signer.PrimaryKey.Fingerprint[:]), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no trusted key matched")
	}
	return "", errors.Wrapf(lastErr, "no trusted signature on tombstone for 0x%s claiming origin %q",
		ts.Fingerprint, ts.Origin)
}

// SignTombstone signs a tombstone with the given key, binding that key's origin
// to this block. The signature is over ts.SigningMessage(), so it covers every
// field the tombstone asserts and cannot be moved to another block.
//
// The signer must hold a private key; on a keyserver that means this is done by
// an operator's tooling rather than by the server itself.
func SignTombstone(ts Tombstone, signer *gocrypto.Entity) (*Signature, error) {
	if err := ts.Validate(); err != nil {
		return nil, errors.WithStack(err)
	}
	if signer == nil || signer.PrivateKey == nil {
		return nil, errors.New("signing a tombstone requires a private key")
	}
	var buf bytes.Buffer
	if err := gocrypto.DetachSign(&buf, signer, bytes.NewReader(ts.SigningMessage()), nil); err != nil {
		return nil, errors.Wrap(err, "cannot sign tombstone")
	}
	op, err := newOpaquePacket(buf.Bytes())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sig, err := ParseSignature(op, time.Time{}, "", "")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sig, nil
}
