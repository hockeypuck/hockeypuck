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

package sks

import (
	"testing"
	"time"

	gc "gopkg.in/check.v1"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp/storage"
	"hockeypuck/hkp/storage/mock"
	"hockeypuck/openpgp"
)

func Test(t *testing.T) { gc.TestingT(t) }

type SksSuite struct {
	peer *Peer
}

var _ = gc.Suite(&SksSuite{})

var _ storage.Storage = (*mock.Storage)(nil)

func (s *SksSuite) SetUpTest(c *gc.C) {
	path := c.MkDir()
	var err error
	policy, err := openpgp.NewPolicy()
	c.Assert(err, gc.IsNil)
	s.peer, err = NewPeer(mock.NewStorage(), path, recon.DefaultSettings(), nil, "", nil, policy)
	c.Assert(err, gc.IsNil)
}

func (s *SksSuite) TestPeerStats(c *gc.C) {
	s.peer.Start()
	s.peer.updateDigests(storage.KeyAdded{Digest: "decafbad"})
	s.peer.Stop()
	// TODO: patchable time.Now to test boundaries.
	thisHour := time.Now().UTC().Truncate(time.Hour)
	thisDay := time.Now().UTC().Truncate(24 * time.Hour)
	c.Assert(s.peer.stats.Total, gc.Equals, 1)
	c.Assert(s.peer.stats.Hourly, gc.HasLen, 1)
	c.Assert(s.peer.stats.Daily, gc.HasLen, 1)
	c.Assert(s.peer.stats.Hourly[thisHour].Inserted, gc.Equals, 1)
	c.Assert(s.peer.stats.Hourly[thisHour].Updated, gc.Equals, 0)
	c.Assert(s.peer.stats.Daily[thisDay].Inserted, gc.Equals, 1)
	c.Assert(s.peer.stats.Daily[thisDay].Updated, gc.Equals, 0)

	s.peer.updateDigests(storage.KeyReplaced{OldDigest: "decafbad", NewDigest: "cafebabe"})
	c.Assert(s.peer.stats.Total, gc.Equals, 1)
	c.Assert(s.peer.stats.Hourly[thisHour].Inserted, gc.Equals, 1)
	c.Assert(s.peer.stats.Hourly[thisHour].Updated, gc.Equals, 1)
	c.Assert(s.peer.stats.Daily[thisDay].Inserted, gc.Equals, 1)
	c.Assert(s.peer.stats.Daily[thisDay].Updated, gc.Equals, 1)
}
