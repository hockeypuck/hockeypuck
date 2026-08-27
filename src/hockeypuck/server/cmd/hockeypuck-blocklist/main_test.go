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

package main

import (
	"errors"
	stdtesting "testing"

	gc "gopkg.in/check.v1"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type ConfigSuite struct{}

var _ = gc.Suite(&ConfigSuite{})

// present and missing stand in for os.Stat over a fixed set of paths.
func present(paths ...string) func(string) error {
	set := map[string]bool{}
	for _, path := range paths {
		set[path] = true
	}
	return func(candidate string) error {
		if set[candidate] {
			return nil
		}
		return errors.New("no such file or directory")
	}
}

// TestConfigPath: this tool blocks and unblocks keys, so picking the wrong
// keyserver is not a inconvenience but a wrong answer to a deletion request.
// A set HOCKEYPUCK_CONFIG is therefore authoritative: a typo in it has to fail
// rather than quietly fall back to the packaged instance.
func (s *ConfigSuite) TestConfigPath(c *gc.C) {
	for _, test := range []struct {
		name      string
		flagValue string
		env       string
		readable  func(string) error
		want      string
		wantErr   string
	}{{
		name:      "an explicit -config is left alone",
		flagValue: "/given/on/the/command/line.conf",
		env:       "/from/the/environment.conf",
		readable:  present(),
		want:      "",
	}, {
		name:     "the environment is used when it resolves",
		env:      "/from/the/environment.conf",
		readable: present("/from/the/environment.conf", defaultConfigPath),
		want:     "/from/the/environment.conf",
	}, {
		name:     "a broken environment setting fails rather than falling back",
		env:      "/typo/in/the/environment.conf",
		readable: present(defaultConfigPath),
		wantErr:  `HOCKEYPUCK_CONFIG is set to "/typo/in/the/environment.conf", which cannot be read.*`,
	}, {
		name:     "the packaged default is used when nothing else is set",
		readable: present(defaultConfigPath),
		want:     defaultConfigPath,
	}, {
		name:     "nothing set and nothing packaged is an error",
		readable: present(),
		wantErr:  "no configuration file found at .*; pass -config PATH or set HOCKEYPUCK_CONFIG",
	}} {
		c.Logf("test: %s", test.name)
		got, err := configPath(test.flagValue, test.env, test.readable)
		if test.wantErr != "" {
			c.Check(err, gc.ErrorMatches, test.wantErr)
			c.Check(got, gc.Equals, "")
			continue
		}
		c.Check(err, gc.IsNil)
		c.Check(got, gc.Equals, test.want)
	}
}
