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

type S struct{}

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

	keywords, keydocs := keywordsFromKey(keys[0])
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
