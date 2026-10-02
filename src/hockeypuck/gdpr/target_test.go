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

package gdpr

import (
	"strings"
	"testing"

	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type TargetSuite struct{}

var _ = gc.Suite(&TargetSuite{})

const (
	v4fp = "0123456789abcdef0123456789abcdef01234567"
	v6fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func (s *TargetSuite) TestClassification(c *gc.C) {
	for i, test := range []struct {
		term  string
		kind  Kind
		value string
	}{
		{v4fp, KindFingerprint, v4fp},
		{"0x" + strings.ToUpper(v4fp), KindFingerprint, v4fp},
		{"0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567", KindFingerprint, v4fp},
		{v6fp, KindFingerprint, v6fp},
		{strings.Repeat("ab", 16), KindFingerprint, strings.Repeat("ab", 16)},
		{"0x89ABCDEF01234567", KindKeyID, "89abcdef01234567"},
		{"89ABCDEF", KindKeyID, "89abcdef"},
		{"Alice@Example.COM", KindEmail, "alice@example.com"},
		{"Alice Example <Alice@Example.com>", KindEmail, "alice@example.com"},
		{"alice example", KindKeyword, "alice example"},
		// Hex that is not an identifier length falls back to a keyword.
		{"cafe", KindKeyword, "cafe"},
		// Explicit overrides.
		{"keyword:" + v4fp, KindKeyword, v4fp},
		{"fp:" + v4fp, KindFingerprint, v4fp},
		{"email:alice@example.com", KindEmail, "alice@example.com"},
		// A keyid: override for a fingerprint-length term still resolves as a
		// fingerprint, since the two queries are equivalent.
		{"keyid:" + v4fp, KindFingerprint, v4fp},
	} {
		c.Logf("test %d: %s", i, test.term)
		target, err := ParseTarget(test.term)
		c.Assert(err, gc.IsNil)
		c.Check(target.Kind, gc.Equals, test.kind)
		c.Check(target.Value, gc.Equals, test.value)
		c.Check(target.Raw, gc.Equals, strings.TrimSpace(test.term))
	}
}

func (s *TargetSuite) TestParseErrors(c *gc.C) {
	for _, term := range []string{
		"",
		"   ",
		"fp:nothexatall",
		"fp:abcd",
		"keyid:zzzz",
		"email:not-an-address",
		"email:two@at@signs.com",
		"keyword:",
	} {
		_, err := ParseTarget(term)
		c.Check(err, gc.NotNil, gc.Commentf("term %q should not parse", term))
	}
}

func (s *TargetSuite) TestParseTargetsDeduplicates(c *gc.C) {
	targets, err := ParseTargets([]string{v4fp, "0x" + strings.ToUpper(v4fp), "alice@example.com", "ALICE@example.com"})
	c.Assert(err, gc.IsNil)
	c.Assert(targets, gc.HasLen, 2)
}

func (s *TargetSuite) TestParseTargetsReportsEveryProblem(c *gc.C) {
	_, err := ParseTargets([]string{"fp:abcd", v4fp, "email:nope"})
	c.Assert(err, gc.NotNil)
	c.Check(strings.Count(err.Error(), "\n"), gc.Equals, 1)
}

func (s *TargetSuite) TestSortTargetsPutsExactIdentifiersFirst(c *gc.C) {
	targets, err := ParseTargets([]string{"alice example", "alice@example.com", v4fp, "0x89abcdef01234567"})
	c.Assert(err, gc.IsNil)
	SortTargets(targets)
	c.Check(targets[0].Kind, gc.Equals, KindFingerprint)
	c.Check(targets[1].Kind, gc.Equals, KindKeyID)
	c.Check(targets[2].Kind, gc.Equals, KindEmail)
	c.Check(targets[3].Kind, gc.Equals, KindKeyword)
}

func (s *TargetSuite) TestReadTermsSkipsBlanksAndComments(c *gc.C) {
	terms, err := ReadTerms(strings.NewReader("# a comment\n\n  " + v4fp + "  \nalice@example.com\n"))
	c.Assert(err, gc.IsNil)
	c.Check(terms, gc.DeepEquals, []string{v4fp, "alice@example.com"})
}
