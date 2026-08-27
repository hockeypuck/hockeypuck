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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

var ErrKeyEvaporated = errors.Errorf("no valid self-signatures")

// Policy determines which optional OpenPGP features are enabled by the calling code.
// This permits fine-grained control over how validation is performed at depth.
type Policy struct {
	enumDomains map[string]bool
	// blocklistOrigin names this node on the tombstones it issues.
	blocklistOrigin string
	// trustedOrigins maps a blocklist origin to the key fingerprints allowed
	// to sign for it. Nothing is trusted unless an operator says so.
	trustedOrigins map[string][]string
}

func NewPolicy(options ...PolicyOption) (*Policy, error) {
	p := &Policy{
		enumDomains:    map[string]bool{},
		trustedOrigins: map[string][]string{},
	}
	for _, option := range options {
		err := option(p)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return p, nil
}

type PolicyOption func(p *Policy) error

func EnumerableDomains(enumDomains []string) PolicyOption {
	return func(p *Policy) error {
		for _, domain := range enumDomains {
			p.enumDomains[domain] = true
		}
		return nil
	}
}

// BlocklistOrigin sets the name this node stamps on tombstones it issues.
func BlocklistOrigin(origin string) PolicyOption {
	return func(p *Policy) error {
		p.blocklistOrigin = strings.ToLower(strings.TrimSpace(origin))
		return nil
	}
}

// TrustBlocklistOrigin declares which keys may sign for a blocklist origin.
func TrustBlocklistOrigin(origin string, fingerprints []string) PolicyOption {
	return func(p *Policy) error {
		origin = strings.ToLower(strings.TrimSpace(origin))
		if origin == "" {
			return errors.New("cannot trust an empty blocklist origin")
		}
		for _, fp := range fingerprints {
			// Fold to the bare lowercase hex that lookups use. Operators paste
			// fingerprints from gpg output and from `list`, so tolerate the 0x
			// form and the spacing and punctuation those carry; storing them
			// verbatim would mean the entry never matched anything.
			fp = NormalizeFingerprint(fp)
			if fp == "" {
				continue
			}
			p.trustedOrigins[origin] = append(p.trustedOrigins[origin], fp)
		}
		return nil
	}
}

// BlocklistOrigin returns the name this node stamps on tombstones it issues.
func (p *Policy) BlocklistOrigin() string { return p.blocklistOrigin }

// TrustedBlocklistKeys returns the fingerprints allowed to sign for a blocklist
// origin. An empty result means tombstones from that origin are not honoured.
func (p *Policy) TrustedBlocklistKeys(origin string) []string {
	return p.trustedOrigins[strings.ToLower(strings.TrimSpace(origin))]
}

// NormalizeFingerprint folds a fingerprint as an operator is likely to have
// written it into the bare lowercase hex used for lookups, tolerating a leading
// 0x and the spacing, colons and hyphens that appear in copy-pasted output.
func NormalizeFingerprint(fp string) string {
	fp = strings.ToLower(strings.TrimSpace(fp))
	fp = strings.NewReplacer(" ", "", "\t", "", ":", "", "-", "").Replace(fp)
	return strings.TrimPrefix(fp, "0x")
}

func (p Policy) IsPersistable(uid *UserID) bool {
	_, _, domainPart, _ := uid.IdentityInfo(map[string]bool{})
	log.Debugf("uid %q contains domainPart %q", uid.Keywords, domainPart)
	return domainPart != "" && p.enumDomains[domainPart]
}

// ValidSelfSigned normalizes a key by removing cryptographically invalid self-signatures.
// If there are no valid self-signatures over a component signable packet, that packet is also removed.
// If there are no valid self-signatures left, it throws ErrKeyEvaporated and the caller SHOULD discard the key.
//
// NB: this is a misnomer, as it also enforces the structural correctness ("plausibility") of third-party sigs and trust packets,
// and updates the Expiration, IsRevoked and ValidSince fields of each component.
func (policy *Policy) ValidSelfSigned(key *PrimaryKey, selfSignedOnly bool) error {
	if IsTombstone(key) {
		// A tombstone asserts that a key is blocked; it carries no key material
		// and so has no self-signatures to validate. What vouches for it is the
		// origin signature, checked by the caller against its trusted origins.
		return nil
	}

	// Process direct signatures first
	ss, others := key.SigInfo()
	var certs []*Signature
	keepUIDs := true
	for _, checkSig := range ss.Errors {
		log.Debugf("Dropped direct sig because %s", checkSig.Error)
	}
	for _, checkSig := range ss.Revocations {
		if checkSig.Error == nil {
			certs = append(certs, checkSig.Signature)
			key.IsRevoked = true
			// RevocationReasons of nil, NoReason and KeyCompromised are considered hard,
			// i.e. they render a key retrospectively unusable. (HIP-5)
			// TODO: include the soft reason UIDNoLongerValid after we implement HIP-4
			reason := checkSig.Signature.RevocationReason
			if reason == nil || *reason == packet.KeyCompromised || *reason == packet.NoReason {
				// Denote nil with -1 to distinguish it from 0
				code := -1
				if reason != nil {
					code = int(*reason)
				}
				log.Debugf("Dropping UIDs and third-party sigs on %s due to direct hard revocation (%d)", key.KeyID, code)
				keepUIDs = false
				selfSignedOnly = true
			}
		} else {
			log.Debugf("Dropped direct revocation sig because %s", checkSig.Error.Error())
		}
	}
certloop:
	for _, checkSig := range ss.Certifications {
		if checkSig.Error == nil {
			certs = append(certs, checkSig.Signature)
			switch checkSig.Signature.Algorithm {
			case packet.PubKeyAlgoSlhdsaShake128s, packet.PubKeyAlgoSlhdsaShake128f, packet.PubKeyAlgoSlhdsaShake256s:
				// Only keep the most recent signature, because these are *monsters*
				// See https://mailarchive.ietf.org/arch/msg/openpgp/kA4YtiP3j8LJUift1_D0mWIHVV0/
				log.Debugf("Dropping older direct signatures using large algorithms")
				break certloop
			}
		} else {
			log.Debugf("Dropped direct sig because %s", checkSig.Error.Error())
		}
	}
	key.Signatures = certs
	if !selfSignedOnly {
		key.Signatures = append(key.Signatures, others...)
	}

	var userIDs []*UserID
	var subKeys []*SubKey
	if keepUIDs {
		for _, uid := range key.UserIDs {
			if uid.Valid(key, selfSignedOnly) {
				userIDs = append(userIDs, uid)
			}
		}
	} else {
		for _, uid := range key.UserIDs {
			if policy.IsPersistable(uid) {
				log.Debugf("adding %q to redacted userids on fp=%s", uid.Keywords, key.Fingerprint)
				ruid, err := NewRedactedUserID(uid)
				if err != nil {
					return errors.WithStack(err)
				}
				key.Trusts = append(key.Trusts, ruid)
			}
		}
	}
	for _, subKey := range key.SubKeys {
		if subKey.Valid(key, selfSignedOnly) {
			subKeys = append(subKeys, subKey)
		}
	}
	key.UserIDs = userIDs
	key.SubKeys = subKeys
	if len(key.SubKeys) == 0 && len(key.UserIDs) == 0 && len(certs) == 0 {
		log.Debugf("no valid self-signatures left on (fp=%s)", key.Fingerprint)
		return ErrKeyEvaporated
	}

	// finally check any Trust packets - we currently throw away any unknown trusts
	tt, _ := key.TrustInfo()
	var trusts []*Trust
	var redactedUIDs []*UserID
	for _, trust := range tt.Errors {
		log.Debugf("Dropped trust packet because %s", trust.Error)
	}
	// A redacted UID is minted and appended to key.Trusts above whenever a hard revocation
	// drops a persistable UserID. Merge dedups its inputs *before* calling ValidSelfSigned,
	// so this freshly minted packet is never run through dedup. On a merge of an on-disk
	// copy that is already revoked and redacted with an incoming copy that still carries the
	// live UserID packet, that yields two redacted-UID trust packets for the same uidstring.
	// Deduplicate by uidstring here so a redacted identity is emitted at most once; otherwise
	// it reaches storage twice and violates the userids (rfingerprint, uidstring) primary key.
	// See https://github.com/hockeypuck/hockeypuck/issues/453
	seenRedacted := make(map[string]bool)
	for _, trust := range tt.RedactedUserIDs {
		if trust.Error != nil {
			log.Debugf("Dropped trust packet because %s", trust.Error.Error())
		} else if !policy.IsPersistable(trust.UserID) {
			log.Debugf("Dropped non-persistable RedactedUserID trust packet")
		} else if seenRedacted[trust.UserID.Keywords] {
			log.Debugf("Dropped duplicate RedactedUserID trust packet for %q on fp=%s", trust.UserID.Keywords, key.Fingerprint)
		} else {
			seenRedacted[trust.UserID.Keywords] = true
			redactedUIDs = append(redactedUIDs, trust.UserID)
			trusts = append(trusts, trust.Trust)
		}
	}
	key.Trusts = trusts
	key.RedactedUserIDs = redactedUIDs
	// record expiry date after dropping userIDs, to emulate the client's viewpoint
	key.Expiration, _ = ss.ExpiresAt()

	return key.updateMD5()
}

func (uid *UserID) Valid(key *PrimaryKey, selfSignedOnly bool) (ok bool) {
	// check Trust packets - we currently throw away any unknown trusts
	tt, _ := uid.TrustInfo()
	var trusts []*Trust
	for _, trust := range tt.Errors {
		log.Debugf("Dropped trust packet because %s", trust.Error)
	}
	uid.Trusts = trusts

	ss, others := uid.SigInfo(key)
	uid.ValidSince, _ = ss.ValidSince()
	uid.Expiration, _ = ss.ExpiresAt()
	var certs []*Signature
	for _, checkSig := range ss.Revocations {
		if checkSig.Error == nil {
			certs = append(certs, checkSig.Signature)
			uid.IsRevoked = true
		} else {
			log.Debugf("Dropped revocation sig on uid '%s' because %s", uid.Keywords, checkSig.Error.Error())
		}
	}
certloop:
	for _, checkSig := range ss.Certifications {
		if checkSig.Error == nil {
			certs = append(certs, checkSig.Signature)
			switch checkSig.Signature.Algorithm {
			case packet.PubKeyAlgoSlhdsaShake128s, packet.PubKeyAlgoSlhdsaShake128f, packet.PubKeyAlgoSlhdsaShake256s:
				// Only keep the most recent signature, because these are *monsters*
				// See https://mailarchive.ietf.org/arch/msg/openpgp/kA4YtiP3j8LJUift1_D0mWIHVV0/
				log.Debugf("Dropping older self-certs using large algorithms")
				break certloop
			}
		} else {
			log.Debugf("Dropped self-cert on uid '%s' because %s", uid.Keywords, checkSig.Error.Error())
		}
	}
	if len(certs) > 0 {
		uid.Signatures = certs
		if !selfSignedOnly {
			uid.Signatures = append(uid.Signatures, others...)
		}
		return true
	} else {
		log.Debugf("Dropped uid '%s' because no valid self-sigs", uid.Keywords)
	}
	return false
}

func (subKey *SubKey) Valid(key *PrimaryKey, selfSignedOnly bool) (ok bool) {
	// check Trust packets - we currently throw away any unknown trusts
	tt, _ := subKey.TrustInfo()
	var trusts []*Trust
	for _, trust := range tt.Errors {
		log.Debugf("Dropped trust packet because %s", trust.Error)
	}
	subKey.Trusts = trusts

	ss, others := subKey.SigInfo(key)
	subKey.Expiration, _ = ss.ExpiresAt()
	var certs []*Signature
	for _, checkSig := range ss.Revocations {
		if checkSig.Error == nil {
			certs = append(certs, checkSig.Signature)
			subKey.IsRevoked = true
		} else {
			log.Debugf("Dropped revocation sig on subkey %s because %s", subKey.KeyID, checkSig.Error.Error())
		}
	}
certloop:
	for _, checkSig := range ss.Certifications {
		if checkSig.Error == nil {
			certs = append(certs, checkSig.Signature)
			switch checkSig.Signature.Algorithm {
			case packet.PubKeyAlgoSlhdsaShake128s, packet.PubKeyAlgoSlhdsaShake128f, packet.PubKeyAlgoSlhdsaShake256s:
				// Only keep the most recent signature, because these are *monsters*
				// See https://mailarchive.ietf.org/arch/msg/openpgp/kA4YtiP3j8LJUift1_D0mWIHVV0/
				log.Errorf("GOT HERE")
				log.Debugf("Dropping older binding sigs using large algorithms")
				break certloop
			}
		} else {
			log.Debugf("Dropped binding sig on subkey %s because %s", subKey.KeyID, checkSig.Error.Error())
		}
	}
	if len(certs) > 0 {
		subKey.Signatures = certs
		if !selfSignedOnly {
			subKey.Signatures = append(subKey.Signatures, others...)
		}
		return true
	} else {
		log.Debugf("Dropped subkey %s because no valid self-sigs", subKey.KeyID)
	}
	return false
}

func CollectDuplicates(key *PrimaryKey) error {
	err := dedup(key, func(primary, _ packetNode) {
		primary.packet().Count++
	})
	if err != nil {
		return errors.WithStack(err)
	}
	return key.updateMD5()
}

func (policy *Policy) Merge(dst, src *PrimaryKey) error {
	dst.UserIDs = append(dst.UserIDs, src.UserIDs...)
	dst.SubKeys = append(dst.SubKeys, src.SubKeys...)
	dst.Signatures = append(dst.Signatures, src.Signatures...)
	dst.Trusts = append(dst.Trusts, src.Trusts...)

	err := dedup(dst, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	return policy.ValidSelfSigned(dst, false)
}

func (policy *Policy) MergeRevocationSig(dst *PrimaryKey, src *Signature) error {
	dst.Signatures = append(dst.Signatures, src)

	err := dedup(dst, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	return policy.ValidSelfSigned(dst, false)
}

func dedup(root packetNode, handleDuplicate func(primary, duplicate packetNode)) error {
	nodes := map[string]packetNode{}

	for _, node := range root.contents() {
		uuid := node.uuid()
		primary, ok := nodes[uuid]
		if ok {
			err := primary.removeDuplicate(root, node)
			if err != nil {
				return errors.WithStack(err)
			}

			err = dedup(primary, nil)
			if err != nil {
				return errors.WithStack(err)
			}

			if handleDuplicate != nil {
				handleDuplicate(primary, node)
			}
		} else {
			nodes[uuid] = node
		}
	}
	return nil
}

// SanitizeHKP cleans unsanitized keyrings for transfer via the HKP interface.
// It should be called from the Handler immediately before writing output.
func (policy *Policy) SanitizeHKP(keys []*PrimaryKey) error {
	for _, pk := range keys {
		err := policy.RemoveTrusts(pk)
		if err != nil {
			return err
		}
	}
	return nil
}

// SanitizeIndex cleans unsanitized keyrings for rendering indexes in the HKP interface.
// It should be called from the Handler immediately before writing output.
func (policy *Policy) SanitizeIndex(keys []*PrimaryKey) error {
	for _, pk := range keys {
		err := policy.RemoveTrusts(pk)
		if err != nil {
			return err
		}
		err = policy.RemoveData(pk)
		if err != nil {
			return err
		}
	}
	return nil
}

// RemoveTrusts performs a deep deletion of all trust packets from a certificate.
func (policy *Policy) RemoveTrusts(key *PrimaryKey) error {
	key.Trusts = nil
	for _, sig := range key.Signatures {
		sig.Trusts = nil
	}
	for _, uid := range key.UserIDs {
		uid.Trusts = nil
		for _, sig := range uid.Signatures {
			sig.Trusts = nil
		}
	}
	for _, sk := range key.SubKeys {
		sk.Trusts = nil
		for _, sig := range sk.Signatures {
			sig.Trusts = nil
		}
	}
	return nil
}

// RemoveData performs a deep deletion of all Data fields from a certificate.
func (policy *Policy) RemoveData(key *PrimaryKey) error {
	key.Data = nil
	for _, sig := range key.Signatures {
		sig.Data = nil
	}
	for _, uid := range key.UserIDs {
		uid.Data = nil
		for _, sig := range uid.Signatures {
			sig.Data = nil
		}
	}
	for _, sk := range key.SubKeys {
		sk.Data = nil
		for _, sig := range sk.Signatures {
			sig.Data = nil
		}
	}
	return nil
}
