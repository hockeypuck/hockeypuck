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
	"sort"
	"time"
)

var now = time.Now

// CheckSig represents the result of checking a self-signature.
type CheckSig struct {
	PrimaryKey *PrimaryKey
	Signature  *Signature
	Error      error
}

// SelfSigs holds self-signatures on OpenPGP targets, which may be keys, user
// IDs, or user attributes.
type SelfSigs struct {
	Revocations    []*CheckSig
	Certifications []*CheckSig
	Primaries      []*CheckSig
	Errors         []*CheckSig

	target packetNode
}

type checkSigCreationAsc []*CheckSig

func (s checkSigCreationAsc) Len() int { return len(s) }

func (s checkSigCreationAsc) Less(i, j int) bool {
	return s[i].Signature.Creation.Unix() < s[j].Signature.Creation.Unix()
}

func (s checkSigCreationAsc) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type checkSigCreationDesc []*CheckSig

func (s checkSigCreationDesc) Len() int { return len(s) }

func (s checkSigCreationDesc) Less(i, j int) bool {
	return s[j].Signature.Creation.Unix() < s[i].Signature.Creation.Unix()
}

func (s checkSigCreationDesc) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type checkSigExpirationDesc []*CheckSig

func (s checkSigExpirationDesc) Len() int { return len(s) }

func (s checkSigExpirationDesc) Less(i, j int) bool {
	return s[j].Signature.Expiration.Unix() < s[i].Signature.Expiration.Unix()
}

func (s checkSigExpirationDesc) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *SelfSigs) resolve() {
	// Sort signatures
	sort.Sort(checkSigCreationAsc(s.Revocations))
	sort.Sort(checkSigCreationDesc(s.Certifications))
	sort.Sort(checkSigCreationDesc(s.Primaries))
}

var zeroTime time.Time

func (s *SelfSigs) RevokedSince() (time.Time, bool) {
	if len(s.Revocations) > 0 {
		return s.Revocations[0].Signature.Creation, true
	}
	return zeroTime, false
}

func (s *SelfSigs) ExpiresAt() (time.Time, bool) {
	if len(s.Certifications) > 0 {
		expiration := s.Certifications[0].Signature.Expiration
		if expiration.IsZero() {
			return zeroTime, false
		}
		return expiration, true
	}
	if pubkey, ok := s.target.(*PrimaryKey); ok {
		primaryUserIDSig, _ := pubkey.PrimaryUserIDSig()
		if primaryUserIDSig != nil && !primaryUserIDSig.Expiration.IsZero() {
			return primaryUserIDSig.Expiration, true
		}
	}
	return zeroTime, false
}

func (s *SelfSigs) Valid() bool {
	validSince, okValid := s.ValidSince()
	return (okValid && !validSince.IsZero())
}

// ValidSince() returns:
// - (if possible) the date that it first became valid, whether it is currently valid or not, and
// - whether the target of the signature is *currently* valid
func (s *SelfSigs) ValidSince() (time.Time, bool) {
	isValid := true
	if len(s.Revocations) > 0 {
		isValid = false
	}
	if pubkey, ok := s.target.(*PrimaryKey); ok {
		return pubkey.Creation, isValid
	}
	for _, checkSig := range s.Certifications {
		// Return the first non-expired self-signature creation time.
		expiresAt := checkSig.Signature.Expiration
		if expiresAt.IsZero() || expiresAt.After(now()) {
			return checkSig.Signature.Creation, isValid
		}
	}
	return zeroTime, false
}

// The date of the most recent unexpired signature that marked this UID as primary, or zero.
func (s *SelfSigs) PrimarySince() (time.Time, bool) {
	if len(s.Revocations) > 0 {
		return zeroTime, false
	}
	for _, checkSig := range s.Primaries {
		expiresAt := checkSig.Signature.Expiration
		if expiresAt.IsZero() || expiresAt.Unix() > now().Unix() {
			return checkSig.Signature.Creation, true
		}
	}
	return zeroTime, false
}
