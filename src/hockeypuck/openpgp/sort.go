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

import "sort"

func lessSelfSigs(i, j *SelfSigs) (bool, bool) {
	iValid := i.Valid()
	jValid := j.Valid()
	if iValid != jValid {
		// Valid comes before invalid
		return iValid, true
	}
	if !iValid {
		_, iRevokedOk := i.RevokedSince()
		_, jRevokedOk := j.RevokedSince()
		if iRevokedOk != jRevokedOk {
			// Non-revoked comes before revoked
			return !iRevokedOk, true
		}
	}

	iPrimarySince, iPrimaryOk := i.PrimarySince()
	jPrimarySince, jPrimaryOk := j.PrimarySince()
	if iPrimaryOk != jPrimaryOk {
		// Primary comes before non-primary
		return iPrimaryOk, true
	}
	if iPrimaryOk {
		// Most recent primary certification comes first
		return jPrimarySince.Unix() < iPrimarySince.Unix(), true
	}

	iValidSince, iValidOk := i.ValidSince()
	jValidSince, jValidOk := j.ValidSince()
	if iValidOk != jValidOk {
		// Self-certified comes before non-self-certified
		return iValidOk, true
	}
	if iValidOk {
		// Most recently certified comes first
		return jValidSince.Unix() < iValidSince.Unix(), true
	}

	return false, false
}

type uidSorter struct {
	*PrimaryKey
}

func (s *uidSorter) Len() int { return len(s.UserIDs) }

func (s *uidSorter) Less(i, j int) bool {
	iss, _ := s.UserIDs[i].SigInfo(s.PrimaryKey)
	jss, _ := s.UserIDs[j].SigInfo(s.PrimaryKey)
	less, ok := lessSelfSigs(iss, jss)
	if ok {
		return less
	}
	return s.UserIDs[i].Keywords < s.UserIDs[j].Keywords
}

func (s *uidSorter) Swap(i, j int) {
	s.UserIDs[i], s.UserIDs[j] = s.UserIDs[j], s.UserIDs[i]
}

type subkeySorter struct {
	*PrimaryKey
}

func (s *subkeySorter) Len() int { return len(s.SubKeys) }

func (s *subkeySorter) Less(i, j int) bool {
	iss, _ := s.SubKeys[i].SigInfo(s.PrimaryKey)
	jss, _ := s.SubKeys[j].SigInfo(s.PrimaryKey)
	less, ok := lessSelfSigs(iss, jss)
	if ok {
		return less
	}
	return s.SubKeys[i].Creation.Unix() < s.SubKeys[j].Creation.Unix()
}

func (s *subkeySorter) Swap(i, j int) {
	s.SubKeys[i], s.SubKeys[j] = s.SubKeys[j], s.SubKeys[i]
}

type sigSorter struct {
	sigs []*Signature
}

func (s *sigSorter) Len() int { return len(s.sigs) }

func (s *sigSorter) Less(i, j int) bool {
	return s.sigs[i].Creation.Unix() < s.sigs[j].Creation.Unix()
}

func (s *sigSorter) Swap(i, j int) {
	s.sigs[i], s.sigs[j] = s.sigs[j], s.sigs[i]
}

// Sort reorders the key material based on precedence rules.
func Sort(pubkey *PrimaryKey) {
	for _, node := range pubkey.contents() {
		switch p := node.(type) {
		case *PrimaryKey:
			sort.Sort(&sigSorter{p.Signatures})
			sort.Sort(&uidSorter{p})
			sort.Sort(&subkeySorter{p})
		case *SubKey:
			sort.Sort(&sigSorter{p.Signatures})
		case *UserID:
			sort.Sort(&sigSorter{p.Signatures})
		}
	}
}
