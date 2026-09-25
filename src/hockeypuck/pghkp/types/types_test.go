/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

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
	"bytes"
	"hockeypuck/openpgp"
	"hockeypuck/testing"
	"io"
	stdtesting "testing"

	"golang.org/x/exp/slices"
	gc "gopkg.in/check.v1"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type S struct {
	policy *openpgp.Policy
}

var _ = gc.Suite(&S{})

func (s *S) TestTSVectorParsing(c *gc.C) {
	// Roundtrip some keywords containing characters special to TSVectors
	kw := []string{
		`didn't, wouldn't, can't`,
		`test`,
		`two\tlines\n`,
	}
	tsv := `'didn''t, wouldn''t, can''t' 'test' 'two\\tlines\\n'`
	kw2 := keywordsFromTSVector(tsv)
	slices.Sort(kw2)
	c.Assert(kw2, gc.DeepEquals, kw)
	tsv2, err := keywordsToTSVector(kw, " ")
	c.Assert(err, gc.IsNil)
	c.Assert(tsv2, gc.Equals, tsv)
}

func (s *S) TestKeywordsFromKey(c *gc.C) {
	keytext, err := io.ReadAll(testing.MustInput("e68e311d.asc"))
	c.Assert(err, gc.IsNil)
	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(keytext))
	comment := gc.Commentf("check Casey's key for sanity")
	c.Assert(keys, gc.HasLen, 1, comment)
	c.Assert(keys[0].UserIDs, gc.HasLen, 2, comment)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>", comment)
	c.Assert(keys[0].UserIDs[1].Keywords, gc.Equals, "Casey Marshall <cmars@cmarstech.com>", comment)

	keywords, keydocs := keywordsFromKey(keys[0], s.policy)
	comment = gc.Commentf("check extraction of keywords from Casey's key")
	slices.Sort(keywords)
	tsvector, err := keywordsToTSVector(keywords, " ")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(tsvector, gc.Equals, "'canonical.com' 'casey' 'casey marshall <casey.marshall@canonical.com>' 'casey marshall <cmars@cmarstech.com>' 'casey.marshall' 'casey.marshall@canonical.com' 'cmars' 'cmars@cmarstech.com' 'cmarstech.com' 'marshall'", comment)
	c.Assert(keydocs, gc.HasLen, 2)
	c.Assert(keydocs[0].UidString, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>")
	c.Assert(keydocs[0].Identity, gc.Equals, "casey.marshall@canonical.com")
	c.Assert(keydocs[1].UidString, gc.Equals, "Casey Marshall <cmars@cmarstech.com>")
	c.Assert(keydocs[1].Identity, gc.Equals, "cmars@cmarstech.com")
}

// TestKeywordsFromKeyDedupesUids is a regression test for
// https://github.com/hockeypuck/hockeypuck/issues/453: keywordsFromKey must not
// emit two uiddocs with the same uidstring, otherwise inserting them violates the
// (rfingerprint, uidstring) primary key. This happens because the uidstring is the
// CleanUtf8'd packet text while openpgp.dedup keys UserID packets on their raw bytes,
// so two packets that differ only in characters CleanUtf8 normalizes away survive
// dedup as distinct UserIDs yet collapse to the same uidstring here.
func (s *S) TestKeywordsFromKeyDedupesUids(c *gc.C) {
	key := &openpgp.PrimaryKey{
		PublicKey: openpgp.PublicKey{
			Packet: openpgp.Packet{UUID: "deadbeef"},
		},
		UserIDs: []*openpgp.UserID{
			{Keywords: "Alice <alice@example.com>"},
			// identical uidstring; on the wire this was a distinct packet (e.g. it
			// carried a stripped control char) that survived dedup as a separate UserID
			{Keywords: "Alice <alice@example.com>"},
			{Keywords: "Bob <bob@example.com>"},
		},
	}

	_, keydocs := keywordsFromKey(key, s.policy)
	c.Assert(keydocs, gc.HasLen, 2)

	seen := make(map[string]bool)
	for _, doc := range keydocs {
		c.Assert(seen[doc.UidString], gc.Equals, false,
			gc.Commentf("duplicate uidstring emitted: %q", doc.UidString))
		seen[doc.UidString] = true
	}
	c.Assert(seen["Alice <alice@example.com>"], gc.Equals, true)
	c.Assert(seen["Bob <bob@example.com>"], gc.Equals, true)
}
