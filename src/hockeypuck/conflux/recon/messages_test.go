/*
   conflux - Distributed database synchronization library
	Based on the algorithm described in
		"Set Reconciliation with Nearly Optimal	Communication Complexity",
			Yaron Minsky, Ari Trachtenberg, and Richard Zippel, 2004.

   Copyright (c) 2012-2015  Casey Marshall <cmars@cmarstech.com>

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

package recon

import (
	"bytes"

	gc "gopkg.in/check.v1"
)

type MessagesSuite struct{}

var _ = gc.Suite(&MessagesSuite{})

func (s *MessagesSuite) TestConfigRoundTrip(c *gc.C) {
	conf := &Config{
		Version:    "3.1415",
		HTTPPort:   11371,
		BitQuantum: 2,
		MBar:       5,
		Filters:    "testing"}
	var buf bytes.Buffer
	err := conf.marshal(&buf)
	c.Assert(err, gc.IsNil)
	c.Logf("config=%x", &buf)
	conf2 := &Config{}
	err = conf2.unmarshal(bytes.NewBuffer(buf.Bytes()))
	c.Assert(err, gc.IsNil)
	c.Assert(conf.Version, gc.Equals, conf2.Version)
	c.Assert(conf.HTTPPort, gc.Equals, conf2.HTTPPort)
	c.Assert(conf.BitQuantum, gc.Equals, conf2.BitQuantum)
	c.Assert(conf.MBar, gc.Equals, conf2.MBar)
	c.Assert(conf.Filters, gc.Equals, conf2.Filters)
}

func (s *MessagesSuite) TestConfigMsgRoundTrip(c *gc.C) {
	conf := &Config{
		Version:    "3.1415",
		HTTPPort:   11371,
		BitQuantum: 2,
		MBar:       5,
		Filters:    "testing"}
	buf := bytes.NewBuffer(nil)
	err := WriteMsg(buf, conf)
	c.Assert(err, gc.IsNil)
	msg, err := ReadMsg(bytes.NewBuffer(buf.Bytes()))
	c.Assert(err, gc.IsNil)
	conf2 := msg.(*Config)
	c.Assert(conf.Version, gc.Equals, conf2.Version)
	c.Assert(conf.HTTPPort, gc.Equals, conf2.HTTPPort)
	c.Assert(conf.BitQuantum, gc.Equals, conf2.BitQuantum)
	c.Assert(conf.MBar, gc.Equals, conf2.MBar)
	c.Assert(conf.Filters, gc.Equals, conf2.Filters)
}
