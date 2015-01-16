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
	"github.com/jmoiron/sqlx"
)

type updater interface {
	UpdatePubkey(p *Pubkey) error
	UpdateSubkey(s *Subkey) error
	UpdateUserId(u *UserId) error
	UpdateUserAttribute(u *UserAttribute) error
	UpdateSignature(s *Signature) error
	UpdatePubkeyRevsig(p *Pubkey, s *Signature) error
	UpdateSubkeyRevsig(sk *Subkey, s *Signature) error
	UpdateUidRevsig(u *UserId, s *Signature) error
	UpdateUatRevsig(u *UserAttribute, s *Signature) error
	UpdatePrimaryUid(p *Pubkey, u *UserId) error
	UpdatePrimaryUat(p *Pubkey, u *UserAttribute) error
}

type postgresUpdater struct {
	*sqlx.Tx
}

func newPostgresUpdater(tx *sqlx.Tx) updater {
	return &postgresUpdater{Tx: tx}
}

func (pq postgresUpdater) UpdatePubkey(p *Pubkey) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_pubkey SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	ctime = $6, mtime = $7,	md5 = $8, sha256 = $9,
	algorithm = $10, bit_len = $11, unsupp = $12
WHERE uuid = $1`, p.RFingerprint,
		p.Creation, p.Expiration, p.State, p.Packet,
		p.Ctime, p.Mtime, p.Md5, p.Sha256,
		p.Algorithm, p.BitLen, p.Unsupported)
	return err
}

func (pq postgresUpdater) UpdateSubkey(s *Subkey) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_subkey SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	algorithm = $6, bit_len = $7
WHERE uuid = $1`,
		s.RFingerprint,
		s.Creation, s.Expiration, s.State, s.Packet,
		s.Algorithm, s.BitLen)
	return err
}

func (pq postgresUpdater) UpdateUserId(u *UserId) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_uid SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	keywords = $6
WHERE uuid = $1`,
		u.ScopedDigest,
		u.Creation, u.Expiration, u.State, u.Packet,
		u.Keywords)
	return err
}

func (pq postgresUpdater) UpdateUserAttribute(u *UserAttribute) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_uat SET
	creation = $2, expiration = $3, state = $4, packet = $5
WHERE uuid = $1`,
		u.ScopedDigest,
		u.Creation, u.Expiration, u.State, u.Packet)
	return err
}

func (pq postgresUpdater) UpdateSignature(s *Signature) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_sig SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	sig_type = $6, signer = $7
WHERE uuid = $1`,
		s.ScopedDigest,
		s.Creation, s.Expiration, s.State, s.Packet,
		s.SigType, s.RIssuerKeyId)
	return err
}

func (pq postgresUpdater) UpdatePubkeyRevsig(p *Pubkey, s *Signature) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_pubkey SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, p.RFingerprint);
	return err
}

func (pq postgresUpdater) UpdateSubkeyRevsig(sk *Subkey, s *Signature) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_subkey SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, sk.RFingerprint);
	return err
}

func (pq postgresUpdater) UpdateUidRevsig(u *UserId, s *Signature) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_uid SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, u.ScopedDigest)
	return err
}

func (pq postgresUpdater) UpdateUatRevsig(u *UserAttribute, s *Signature) error {
	_, err :=  Execv(pq.Tx, `
UPDATE openpgp_uat SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, u.ScopedDigest)
	return err
}

func (pq postgresUpdater) UpdatePrimaryUid(p *Pubkey, u *UserId) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
			u.ScopedDigest, p.RFingerprint)
	return err
}

func (pq postgresUpdater) UpdatePrimaryUat(p *Pubkey, u *UserAttribute) error {
	_, err := Execv(pq.Tx, `
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
			u.ScopedDigest, p.RFingerprint)
	return err
}
