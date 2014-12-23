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

type query interface {
	UpdatePubkey(e sqlx.Execer, p *Pubkey) (sql.Result, error)
	UpdateSubkey(e sqlx.Execer, s *Subkey) (sql.Result, error)
	UpdateUserId(e sqlx.Execer, u *UserId) (sql.Result, error)
	UpdateUserAttribute(e sqlx.Execer, u *UserAttribute) (sql.Result, error)
}

type postgresQuery struct {}

func Query() query {
	return postgresQuery{}
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
