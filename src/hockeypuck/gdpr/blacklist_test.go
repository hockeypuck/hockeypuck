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
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	gc "gopkg.in/check.v1"
)

type BlacklistSuite struct{}

var _ = gc.Suite(&BlacklistSuite{})

func (s *BlacklistSuite) TestNormalizeFingerprints(c *gc.C) {
	c.Check(NormalizeFingerprints([]string{
		strings.ToUpper(v6fp), "  " + v4fp + "  ", v4fp, "", "   ",
	}), gc.DeepEquals, []string{v4fp, v6fp})
}

func (s *BlacklistSuite) TestMissingFromBlacklistIgnoresCase(c *gc.C) {
	c.Check(MissingFromBlacklist([]string{strings.ToUpper(v4fp)}, []string{v4fp, v6fp}),
		gc.DeepEquals, []string{v6fp})
	c.Check(MissingFromBlacklist([]string{v4fp, v6fp}, []string{v4fp}), gc.IsNil)
}

// TestBlacklistTOMLParsesAsConfig checks that the generated fragment really can
// be pasted into hockeypuck.conf, which is the whole point of it.
func (s *BlacklistSuite) TestBlacklistTOMLParsesAsConfig(c *gc.C) {
	var doc blacklistDoc
	_, err := toml.Decode(BlacklistTOML([]string{v6fp, v4fp}), &doc)
	c.Assert(err, gc.IsNil)
	c.Check(doc.Hockeypuck.OpenPGP.Blacklist, gc.DeepEquals, []string{v4fp, v6fp})
}

func (s *BlacklistSuite) TestMergeFileIsIdempotent(c *gc.C) {
	path := filepath.Join(c.MkDir(), "nested", "blacklist.toml")

	added, all, err := MergeBlacklistFile(path, []string{v4fp})
	c.Assert(err, gc.IsNil)
	c.Check(added, gc.DeepEquals, []string{v4fp})
	c.Check(all, gc.DeepEquals, []string{v4fp})

	// Re-running the same case must not duplicate or rewrite anything.
	added, all, err = MergeBlacklistFile(path, []string{strings.ToUpper(v4fp)})
	c.Assert(err, gc.IsNil)
	c.Check(added, gc.IsNil)
	c.Check(all, gc.DeepEquals, []string{v4fp})

	added, all, err = MergeBlacklistFile(path, []string{v6fp})
	c.Assert(err, gc.IsNil)
	c.Check(added, gc.DeepEquals, []string{v6fp})
	c.Check(all, gc.DeepEquals, []string{v4fp, v6fp})

	onDisk, err := ReadBlacklistFile(path)
	c.Assert(err, gc.IsNil)
	c.Check(onDisk, gc.DeepEquals, []string{v4fp, v6fp})
}

// TestReadBareFragment covers a file hand-written as a bare "blacklist = [...]"
// array rather than the nested form this package emits.
func (s *BlacklistSuite) TestReadBareFragment(c *gc.C) {
	path := filepath.Join(c.MkDir(), "bare.toml")
	c.Assert(os.WriteFile(path, []byte("blacklist = [\""+v4fp+"\"]\n"), 0o600), gc.IsNil)
	fps, err := ReadBlacklistFile(path)
	c.Assert(err, gc.IsNil)
	c.Check(fps, gc.DeepEquals, []string{v4fp})
}

func (s *BlacklistSuite) TestReadMissingFileIsEmpty(c *gc.C) {
	fps, err := ReadBlacklistFile(filepath.Join(c.MkDir(), "absent.toml"))
	c.Assert(err, gc.IsNil)
	c.Check(fps, gc.HasLen, 0)
}

func (s *BlacklistSuite) TestReadCorruptFileFails(c *gc.C) {
	path := filepath.Join(c.MkDir(), "corrupt.toml")
	c.Assert(os.WriteFile(path, []byte("blacklist = [oops\n"), 0o600), gc.IsNil)
	_, err := ReadBlacklistFile(path)
	c.Assert(err, gc.ErrorMatches, ".*cannot parse blacklist.*")
}
