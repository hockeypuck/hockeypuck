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
	"net"
	"testing"

	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type SettingsSuite struct{}

var _ = gc.Suite(&SettingsSuite{})

func (s *SettingsSuite) TestParse(c *gc.C) {
	testCases := []struct {
		desc     string
		toml     string
		settings *Settings
		err      string
	}{{
		"empty string",
		``,
		DefaultSettings(),
		"",
	}, {
		"field setting with some defaults",
		`
[conflux.recon]
version="2.3.4"
logname="blammo"
filters=["something","else"]
`,
		&Settings{
			PTreeConfig:                 defaultPTreeConfig,
			Version:                     "2.3.4",
			LogName:                     "blammo",
			Filters:                     []string{"something", "else"},
			HTTPAddr:                    ":11371",
			ReconAddr:                   ":11370",
			Partners:                    PartnerMap{},
			SeenCacheSize:               DefaultSeenCacheSize,
			GossipIntervalSecs:          DefaultGossipIntervalSecs,
			MaxOutstandingReconRequests: DefaultMaxOutstandingReconRequests,
		},
		"",
	}, {
		"field setting override some defaults",
		`
[conflux.recon]
version="2.3.4"
logname="blammo"
httpAddr="12.23.34.45:11371"
seenCacheSize=4092
reconAddr="[2001:db8:85a3::8a2e:370:7334]:11370"
filters=["something","else"]
`,
		&Settings{
			PTreeConfig:                 defaultPTreeConfig,
			Version:                     "2.3.4",
			LogName:                     "blammo",
			HTTPAddr:                    "12.23.34.45:11371",
			ReconAddr:                   "[2001:db8:85a3::8a2e:370:7334]:11370",
			Filters:                     []string{"something", "else"},
			Partners:                    PartnerMap{},
			SeenCacheSize:               4092,
			GossipIntervalSecs:          DefaultGossipIntervalSecs,
			MaxOutstandingReconRequests: DefaultMaxOutstandingReconRequests,
		},
		"",
	}, {
		"invalid toml",
		`nope`,
		nil,
		`.*unexpected EOF; expected key separator.*`,
	}, {
		"invalid http net",
		`
[conflux.recon]
httpNet="ansible"
`,
		nil,
		`.*don't know how to resolve network \"ansible\" address.*`,
	}, {
		"invalid http net",
		`
[conflux.recon]
httpNet="tcp"
httpAddr="/dev/null"
`,
		nil,
		`.*missing port in address.*`,
	}, {
		"invalid recon net",
		`
[conflux.recon]
httpNet="tcp"
httpAddr="1.2.3.4:8080"
reconNet="floo"
reconAddr="flarb"
`,
		nil,
		`.*don't know how to resolve network \"floo\" address \"flarb\".*`,
	}, {
		"invalid recon addr",
		`
[conflux.recon]
httpNet="tcp"
httpAddr="1.2.3.4:8080"
reconNet="tcp"
reconAddr=":-1"
`,
		nil,
		`.*invalid port.*`,
	}, {
		"new-style recon partners",
		`
[conflux.recon]
httpAddr=":11371"
reconAddr=":11370"

[conflux.recon.partner.alice]
httpAddr="1.2.3.4:11371"
reconAddr="5.6.7.8:11370"

[conflux.recon.partner.bob]
httpAddr="4.3.2.1:11371"
reconAddr="8.7.6.5:11370"
`,
		&Settings{
			PTreeConfig:                 defaultPTreeConfig,
			Version:                     DefaultVersion,
			LogName:                     DefaultLogName,
			HTTPAddr:                    DefaultHTTPAddr,
			ReconAddr:                   DefaultReconAddr,
			Filters:                     defaultFilters,
			GossipIntervalSecs:          DefaultGossipIntervalSecs,
			MaxOutstandingReconRequests: DefaultMaxOutstandingReconRequests,
			SeenCacheSize:               DefaultSeenCacheSize,
			Partners: map[string]Partner{
				"alice": Partner{
					HTTPAddr:  "1.2.3.4:11371",
					ReconAddr: "5.6.7.8:11370",
				},
				"bob": Partner{
					HTTPAddr:  "4.3.2.1:11371",
					ReconAddr: "8.7.6.5:11370",
				},
			},
		},
		"",
	}, {
		"compat-style config",
		`
[conflux.recon]
httpPort=11371
reconPort=11370
partners=["1.2.3.4:11370","5.6.7.8:11370"]
`,
		&Settings{
			PTreeConfig:                 defaultPTreeConfig,
			Version:                     DefaultVersion,
			LogName:                     DefaultLogName,
			HTTPAddr:                    ":11371",
			ReconAddr:                   ":11370",
			Filters:                     defaultFilters,
			CompatHTTPPort:              11371,
			CompatReconPort:             11370,
			GossipIntervalSecs:          DefaultGossipIntervalSecs,
			MaxOutstandingReconRequests: DefaultMaxOutstandingReconRequests,
			SeenCacheSize:               DefaultSeenCacheSize,
			Partners: map[string]Partner{
				"1.2.3.4": Partner{
					HTTPAddr:  "1.2.3.4:11371",
					ReconAddr: "1.2.3.4:11370",
				},
				"5.6.7.8": Partner{
					HTTPAddr:  "5.6.7.8:11371",
					ReconAddr: "5.6.7.8:11370",
				},
			},
			CompatPartnerAddrs: []string{"1.2.3.4:11370", "5.6.7.8:11370"},
		},
		"",
	}}
	for i, testCase := range testCases {
		c.Logf("test#%d: %s", i, testCase.desc)
		settings, err := ParseSettings(testCase.toml)
		if err != nil {
			c.Check(err, gc.ErrorMatches, testCase.err)
		} else {
			c.Check(settings, gc.DeepEquals, testCase.settings)
		}
	}
}

func (s *SettingsSuite) TestMatcher(c *gc.C) {
	settings := &Settings{
		AllowCIDRs: []string{"192.168.1.0/24", "10.0.0.0/8", "20.21.22.23/32"},
		Partners: map[string]Partner{
			"foo": Partner{
				HTTPAddr:  "1.2.3.4:11371",
				ReconAddr: "4.3.2.1:11370",
			},
			"bar": Partner{
				HTTPAddr:  "5.6.7.8:11371",
				ReconAddr: "5.6.7.8:11370",
			},
		},
	}

	matcher, err := settings.Matcher()
	c.Assert(err, gc.IsNil)
	testCases := []struct {
		addr   string
		expect bool
	}{
		{"10.0.0.14", true},
		{"10.1.0.14", true},
		{"11.1.0.14", false},

		{"1.2.3.4", true},
		{"1.2.3.5", false},
		{"1.3.3.5", false},
		{"4.3.2.1", true},

		{"5.6.7.8", true},
		{"5.6.7.9", false},
		{"5.7.7.8", false},

		{"20.21.22.23", true},
		{"20.21.22.11", false},

		{"147.26.10.11", false},
		{"2.2.3.4", false},
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.addr)
		c.Assert(err, gc.IsNil)
		result := matcher.Match(ip)
		c.Check(result, gc.Equals, tc.expect, gc.Commentf("addr=%q", tc.addr))
	}
}

func (s *SettingsSuite) TestMatchAll(c *gc.C) {
	settings := &Settings{
		AllowCIDRs: []string{"0.0.0.0/0"},
	}
	matcher, err := settings.Matcher()
	c.Assert(err, gc.IsNil)
	testCases := []struct {
		addr   string
		expect bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.14", true},
		{"127.0.0.1", true},
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.addr)
		c.Assert(err, gc.IsNil)
		result := matcher.Match(ip)
		c.Check(result, gc.Equals, tc.expect, gc.Commentf("addr=%q", tc.addr))
	}
}
