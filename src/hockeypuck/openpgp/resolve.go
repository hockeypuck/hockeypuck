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
	log "github.com/sirupsen/logrus"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

var ErrKeyEvaporated = errors.Errorf("no valid self-signatures")

// ValidSelfSigned normalizes a key by removing cryptographically invalid self-signatures.
// If there are no valid self-signatures over a component signable packet, that packet is also removed.
// If there are no valid self-signatures left, it throws ErrKeyEvaporated and the caller SHOULD discard the key.
//
// NB: this is a misnomer, as it also enforces the structural correctness ("plausibility") of third-party sigs and trust packets.
func ValidSelfSigned(key *PrimaryKey, selfSignedOnly bool) error {
	// Process direct signatures first
	ss, others := key.SigInfo()
	var certs []*Signature
	keepUIDs := true
	for _, cert := range ss.Errors {
		log.Debugf("Dropped direct sig because %s", cert.Error)
	}
	for _, cert := range ss.Revocations {
		if cert.Error == nil {
			certs = append(certs, cert.Signature)
			// RevocationReasons of nil, NoReason and KeyCompromised are considered hard,
			// i.e. they render a key retrospectively unusable. (HIP-5)
			// TODO: include the soft reason UIDNoLongerValid after we implement HIP-4
			reason := cert.Signature.RevocationReason
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
			log.Debugf("Dropped direct revocation sig because %s", cert.Error.Error())
		}
	}
	for _, cert := range ss.Certifications {
		if cert.Error == nil {
			certs = append(certs, cert.Signature)
		} else {
			log.Debugf("Dropped direct certification sig because %s", cert.Error.Error())
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
	for _, trust := range tt.RedactedUserIDs {
		if trust.Error == nil {
			redactedUIDs = append(redactedUIDs, trust.UserID)
			trusts = append(trusts, trust.Trust)
		} else {
			log.Debugf("Dropped trust packet because %s", trust.Error.Error())
		}
	}
	key.Trusts = trusts
	key.RedactedUserIDs = redactedUIDs

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
	var certs []*Signature
	for _, cert := range ss.Revocations {
		if cert.Error == nil {
			certs = append(certs, cert.Signature)
		} else {
			log.Debugf("Dropped revocation sig on uid '%s' because %s", uid.Keywords, cert.Error.Error())
		}
	}
	for _, cert := range ss.Certifications {
		if cert.Error == nil {
			certs = append(certs, cert.Signature)
		} else {
			log.Debugf("Dropped certification sig on uid '%s' because %s", uid.Keywords, cert.Error.Error())
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
	var certs []*Signature
	for _, cert := range ss.Revocations {
		if cert.Error == nil {
			certs = append(certs, cert.Signature)
		} else {
			log.Debugf("Dropped revocation sig on subkey %s because %s", subKey.KeyID, cert.Error.Error())
		}
	}
	for _, cert := range ss.Certifications {
		if cert.Error == nil {
			certs = append(certs, cert.Signature)
		} else {
			log.Debugf("Dropped certification sig on subkey %s because %s", subKey.KeyID, cert.Error.Error())
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

func Merge(dst, src *PrimaryKey) error {
	dst.UserIDs = append(dst.UserIDs, src.UserIDs...)
	dst.SubKeys = append(dst.SubKeys, src.SubKeys...)
	dst.Signatures = append(dst.Signatures, src.Signatures...)
	dst.Trusts = append(dst.Trusts, src.Trusts...)

	err := dedup(dst, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	return ValidSelfSigned(dst, false)
}

func MergeRevocationSig(dst *PrimaryKey, src *Signature) error {
	dst.Signatures = append(dst.Signatures, src)

	err := dedup(dst, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	return ValidSelfSigned(dst, false)
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
