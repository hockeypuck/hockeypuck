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

package types

import (
	"encoding/json"

	gc "gopkg.in/check.v1"

	"hockeypuck/hkp/jsonhkp"
	"hockeypuck/openpgp"
)

type TombstoneStorageSuite struct{}

var _ = gc.Suite(&TombstoneStorageSuite{})

const tombstoneFp = "10fe8cf1b483f7525039aa2a361bc1f023e0dcca"

// TestDocumentRoundTrip walks a tombstone through exactly the path storage
// uses: jsonhkp document out, JSON in the doc column, and back through
// ReadOneKey. A tombstone carries no public key packet, so nothing here can be
// taken for granted.
func (s *TombstoneStorageSuite) TestDocumentRoundTrip(c *gc.C) {
	original, err := openpgp.NewTombstone(openpgp.Tombstone{
		Fingerprint: tombstoneFp,
		Origin:      "pgpkeys.eu",
		Reason:      "abuse",
	})
	c.Assert(err, gc.IsNil)

	// Out to the doc column.
	doc, err := json.Marshal(jsonhkp.NewPrimaryKey(original))
	c.Assert(err, gc.IsNil)

	// ...and back.
	var stored jsonhkp.PrimaryKey
	c.Assert(json.Unmarshal(doc, &stored), gc.IsNil)
	c.Check(stored.Fingerprint, gc.Equals, tombstoneFp,
		gc.Commentf("the doc must carry the blocked fingerprint, since the row is keyed on it"))

	got, err := ReadOneKey(stored.Bytes(), tombstoneFp)
	c.Assert(err, gc.IsNil)
	c.Assert(got, gc.NotNil)

	c.Check(openpgp.IsTombstone(got), gc.Equals, true)
	c.Check(got.Fingerprint, gc.Equals, tombstoneFp)
	c.Check(got.MD5, gc.Equals, original.MD5,
		gc.Commentf("the SKS digest must survive storage, or the prefix tree and the DB disagree"))
	c.Check(got.TrustMD5, gc.Equals, original.TrustMD5)

	ts, _, err := openpgp.TombstoneOf(got)
	c.Assert(err, gc.IsNil)
	c.Check(ts.Fingerprint, gc.Equals, tombstoneFp)
	c.Check(ts.Origin, gc.Equals, "pgpkeys.eu")
	c.Check(ts.Reason, gc.Equals, "abuse")
}

// TestKeywordsTSVector checks that a tombstone contributes nothing to the
// keyword index. It has no user IDs, and it must not become findable by
// keyword search.
func (s *TombstoneStorageSuite) TestKeywordsTSVector(c *gc.C) {
	tombstone, err := openpgp.NewTombstone(openpgp.Tombstone{
		Fingerprint: tombstoneFp,
		Origin:      "pgpkeys.eu",
	})
	c.Assert(err, gc.IsNil)

	tsv, uiddocs := KeywordsTSVector(tombstone)
	c.Check(tsv, gc.Equals, "")
	c.Check(uiddocs, gc.HasLen, 0)
}
