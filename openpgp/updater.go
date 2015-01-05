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
	"database/sql"

	"github.com/jmoiron/sqlx"
)

type updater interface {
	UpdatePubkey(e sqlx.Execer, p *Pubkey) (sql.Result, error)
	UpdateSubkey(e sqlx.Execer, s *Subkey) (sql.Result, error)
	UpdateUserId(e sqlx.Execer, u *UserId) (sql.Result, error)
	UpdateUserAttribute(e sqlx.Execer, u *UserAttribute) (sql.Result, error)
	UpdateSignature(e sqlx.Execer, s *Signature) (sql.Result, error)
	UpdatePubkeyRevsig(e sqlx.Execer, p *Pubkey, s *Signature) (sql.Result, error)
	UpdateSubkeyRevsig(e sqlx.Execer, sk *Subkey, s *Signature) (sql.Result, error)
	UpdateUidRevsig(e sqlx.Execer, u *UserId, s *Signature) (sql.Result, error)
	UpdateUatRevsig(e sqlx.Execer, u *UserAttribute, s *Signature) (sql.Result, error)
	UpdatePrimaryUid(e sqlx.Execer, p *Pubkey, u *UserId) (sql.Result, error)
	UpdatePrimaryUat(e sqlx.Execer, p *Pubkey, u *UserAttribute) (sql.Result, error)
}

type postgresUpdater struct {}

func Updater() updater {
	return postgresUpdater{}
}

func (pq postgresQuery) UpdatePubkey(e sqlx.Execer, p *Pubkey) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_pubkey SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	ctime = $6, mtime = $7,	md5 = $8, sha256 = $9,
	algorithm = $10, bit_len = $11, unsupp = $12
WHERE uuid = $1`, p.RFingerprint,
		p.Creation, p.Expiration, p.State, p.Packet,
		p.Ctime, p.Mtime, p.Md5, p.Sha256,
		p.Algorithm, p.BitLen, p.Unsupported)
}

func (pq postgresQuery) UpdateSubkey(e sqlx.Execer, s *Subkey) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_subkey SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	algorithm = $6, bit_len = $7
WHERE uuid = $1`,
		s.RFingerprint,
		s.Creation, s.Expiration, s.State, s.Packet,
		s.Algorithm, s.BitLen)
}

func (pq postgresQuery) UpdateUserId(e sqlx.Execer, u *UserId) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_uid SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	keywords = $6
WHERE uuid = $1`,
		u.ScopedDigest,
		u.Creation, u.Expiration, u.State, u.Packet,
		u.Keywords)
}

func (pq postgresQuery) UpdateUserAttribute(e sqlx.Execer, u *UserAttribute) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_uat SET
	creation = $2, expiration = $3, state = $4, packet = $5
WHERE uuid = $1`,
		u.ScopedDigest,
		u.Creation, u.Expiration, u.State, u.Packet)
}

func (pq postgresQuery) UpdateSignature(e sqlx.Execer, s *Signature) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_sig SET
	creation = $2, expiration = $3, state = $4, packet = $5,
	sig_type = $6, signer = $7
WHERE uuid = $1`,
		s.ScopedDigest,
		s.Creation, s.Expiration, s.State, s.Packet,
		s.SigType, s.RIssuerKeyId)
}

func (pq postgresQuery) UpdatePubkeyRevsig(e sqlx.Execer, p *Pubkey, s *Signature) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_pubkey SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, p.RFingerprint);
}

func (pq postgresQuery) UpdateSubkeyRevsig(e sqlx.Execer, sk *Subkey, s *Signature) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_subkey SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, sk.RFingerprint);
}

func (pq postgresQuery) UpdateUidRevsig(e sqlx.Execer, u *UserId, s *Signature) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_uid SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, u.ScopedDigest)
}

func (pq postgresQuery) UpdateUatRevsig(e sqlx.Execer, u *UserAttribute, s *Signature) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_uat SET revsig_uuid = $1 WHERE uuid = $2`,
		s.ScopedDigest, u.ScopedDigest)
}

func (pq postgresQuery) UpdatePrimaryUid(e sqlx.Execer, p *Pubkey, u *UserId) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
			u.ScopedDigest, p.RFingerprint)
}

func (pq postgresQuery) UpdatePrimaryUat(e sqlx.Execer, p *Pubkey, u *UserAttribute) (sql.Result, error) {
	return Execv(e, `
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
			u.ScopedDigest, p.RFingerprint)
}
