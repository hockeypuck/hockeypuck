/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Hockeypuck Contributors

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

package server

import (
	"hockeypuck/hkp/storage"
	"strings"
	"testing"

	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type ServerSuite struct{}

var _ = gc.Suite(&ServerSuite{})

func (s *ServerSuite) TestDefaultSettings(c *gc.C) {
	settings := DefaultSettings()
	// Test behavior: defaults should be non-empty and reasonable
	c.Assert(settings.HKP.Bind, gc.Not(gc.Equals), "")
	c.Assert(strings.Contains(settings.HKP.Bind, ":"), gc.Equals, true)
	c.Assert(settings.Software, gc.Not(gc.Equals), "")
	c.Assert(settings.Version, gc.Not(gc.Equals), "")

	// Test reasonable defaults for numeric values
	c.Assert(settings.ReconStaleSecs > 0, gc.Equals, true)
	c.Assert(settings.MaxResponseLen > 0, gc.Equals, true)

	// Test OpenPGP defaults are reasonable
	c.Assert(settings.OpenPGP.MaxKeyLength > 0, gc.Equals, true)
	c.Assert(settings.OpenPGP.MaxPacketLength > 0, gc.Equals, true)
	c.Assert(settings.OpenPGP.NWorkers > 0, gc.Equals, true)

	// Test rate limiting is enabled by default
	c.Assert(settings.RateLimit.Enabled, gc.Equals, true)

	// Blacklist should be empty by default
	c.Assert(settings.OpenPGP.Blacklist, gc.HasLen, 0)
}

func (s *ServerSuite) TestParseSettingsBackwardsCompat(c *gc.C) {
	tomlData1 := `
logLevel = "DEBUG"
hostname = "test.example.com"

[hkp]
bind = ":8080"
logRequestDetails = false

[openpgp]
maxKeyLength = 2048
nWorkers = 16
`

	settings1, err := ParseSettings(tomlData1)
	c.Assert(err, gc.IsNil)

	tomlData2 := `
[hockeypuck]
logLevel = "DEBUG"
hostname = "test.example.com"

[hockeypuck.hkp]
bind = ":8080"
logRequestDetails = false

[hockeypuck.openpgp]
maxKeyLength = 2048
nWorkers = 16
`

	settings2, err := ParseSettings(tomlData2)
	c.Assert(err, gc.IsNil)

	c.Assert(settings1, gc.DeepEquals, settings2)
}

func (s *ServerSuite) TestParseSettingsBasic(c *gc.C) {
	tomlData := `
logLevel = "DEBUG"
hostname = "test.example.com"

[hkp]
bind = ":8080"
logRequestDetails = false

[openpgp]
maxKeyLength = 2048
nWorkers = 16
`

	settings, err := ParseSettings(tomlData)
	c.Assert(err, gc.IsNil)
	c.Assert(settings.HKP.Bind, gc.Equals, ":8080")
	c.Assert(settings.HKP.LogRequestDetails, gc.Equals, false)
	c.Assert(settings.OpenPGP.MaxKeyLength, gc.Equals, 2048)
	c.Assert(settings.OpenPGP.NWorkers, gc.Equals, 16)
	c.Assert(settings.LogLevel, gc.Equals, "DEBUG")
	c.Assert(settings.Hostname, gc.Equals, "test.example.com")
}

func (s *ServerSuite) TestParseSettingsWithRateLimit(c *gc.C) {
	tomlData := `
[rateLimit]
enabled = true
maxConcurrentConnections = 100
httpRequestRate = 50

[rateLimit.backend]
type = "redis"

[rateLimit.backend.redis]
addr = "localhost:6379"
keyPrefix = "test:"
`

	settings, err := ParseSettings(tomlData)
	c.Assert(err, gc.IsNil)
	c.Assert(settings.RateLimit, gc.NotNil)
	c.Assert(settings.RateLimit.Enabled, gc.Equals, true)
	c.Assert(settings.RateLimit.MaxConcurrentConnections, gc.Equals, 100)
	c.Assert(settings.RateLimit.HTTPRequestRate, gc.Equals, 50)
	c.Assert(settings.RateLimit.Backend, gc.NotNil)
	c.Assert(settings.RateLimit.Backend.Type, gc.Equals, "redis")
	c.Assert(settings.RateLimit.Backend.Redis.Addr, gc.Equals, "localhost:6379")
	c.Assert(settings.RateLimit.Backend.Redis.KeyPrefix, gc.Equals, "test:")
}

func (s *ServerSuite) TestParseSettingsWithHTTPS(c *gc.C) {
	tomlData := `
[hkps]
bind = ":8443"
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
logRequestDetails = true
`

	settings, err := ParseSettings(tomlData)
	c.Assert(err, gc.IsNil)
	c.Assert(settings.HKPS, gc.NotNil)
	c.Assert(settings.HKPS.Bind, gc.Equals, ":8443")
	c.Assert(settings.HKPS.Cert, gc.Equals, "/path/to/cert.pem")
	c.Assert(settings.HKPS.Key, gc.Equals, "/path/to/key.pem")
	c.Assert(settings.HKPS.LogRequestDetails, gc.Equals, true)
}

func TestParseSettingsWithTemplateVariables(t *testing.T) {
	// Set an environment variable for testing
	t.Setenv("TEST_HOSTNAME", "env.example.com")

	tomlData := `
hostname = "{{ env "TEST_HOSTNAME" }}"
contact = "admin@{{ env "TEST_HOSTNAME" }}"
`

	settings, err := ParseSettings(tomlData)
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if settings.Hostname != "env.example.com" {
		t.Errorf("Expected hostname env.example.com, got %s", settings.Hostname)
	}

	if settings.Contact != "admin@env.example.com" {
		t.Errorf("Expected contact admin@env.example.com, got %s", settings.Contact)
	}
}

func (s *ServerSuite) TestParseSettingsInvalidTOML(c *gc.C) {
	invalidData := `
[hkp
bind = ":8080"
`

	_, err := ParseSettings(invalidData)
	c.Assert(err, gc.NotNil)
}

func (s *ServerSuite) TestKeyWriterOptions(c *gc.C) {
	settings := &Settings{
		OpenPGP: OpenPGPConfig{
			Headers: OpenPGPArmorHeaders{
				Comment: "Test Comment",
				Version: "Test Version",
			},
		},
		Hostname: "test.example.com",
		Software: "TestSoft",
		Version:  "1.0.0",
	}

	opts := KeyWriterOptions(settings)
	c.Assert(opts, gc.HasLen, 2)

	// Test with empty headers (should use defaults)
	settings.OpenPGP.Headers.Comment = ""
	settings.OpenPGP.Headers.Version = ""
	opts = KeyWriterOptions(settings)
	c.Assert(opts, gc.HasLen, 2)
}

func (s *ServerSuite) TestKeyReaderOptions(c *gc.C) {
	settings := &Settings{
		OpenPGP: OpenPGPConfig{
			MaxKeyLength:    1024,
			MaxPacketLength: 512,
			Blacklist:       []string{"badkey1", "badkey2"},
		},
	}

	opts := KeyReaderOptions(settings)
	c.Assert(opts, gc.HasLen, 3)

	// Test with zero limits (should not add those options)
	settings.OpenPGP.MaxKeyLength = 0
	settings.OpenPGP.MaxPacketLength = 0
	opts = KeyReaderOptions(settings)
	c.Assert(opts, gc.HasLen, 1)

	// Test with empty blacklist
	settings.OpenPGP.Blacklist = nil
	opts = KeyReaderOptions(settings)
	c.Assert(opts, gc.HasLen, 0)
}

func (s *ServerSuite) TestSMTPConfigBehavior(c *gc.C) {
	// Test that SMTP defaults are reasonable
	c.Assert(DefaultSMTPHost, gc.Not(gc.Equals), "")
	c.Assert(strings.Contains(DefaultSMTPHost, ":"), gc.Not(gc.Equals), false)
}

func (s *ServerSuite) TestDBConfigBehavior(c *gc.C) {
	// Test that DB defaults are reasonable
	c.Assert(storage.DefaultDBDriver, gc.Not(gc.Equals), "")
	c.Assert(storage.DefaultDBDSN, gc.Not(gc.Equals), "")
	c.Assert(strings.Contains(storage.DefaultDBDSN, "database="), gc.Not(gc.Equals), false)
}

func (s *ServerSuite) TestOpenPGPConfigReasonableness(c *gc.C) {
	// Test that OpenPGP defaults are reasonable, not specific values
	c.Assert(DefaultMaxKeyLength > 1024, gc.Equals, true)
	c.Assert(DefaultMaxPacketLength, gc.Not(gc.Equals), 0)
	c.Assert(DefaultStatsRefreshHours, gc.Not(gc.Equals), 0)
	c.Assert(DefaultNWorkers, gc.Not(gc.Equals), 0)
	c.Assert(DefaultNWorkers < 100, gc.Equals, true)
}

func (s *ServerSuite) TestQueryConfigDefaults(c *gc.C) {
	settings := DefaultSettings()
	c.Assert(settings.HKP.Queries.SelfSignedOnly, gc.Equals, false)
	c.Assert(settings.HKP.Queries.FingerprintOnly, gc.Equals, false)
}

func (s *ServerSuite) TestParseSettingsWithQueryConfig(c *gc.C) {
	tomlData := `
[hkp.queries]
selfSignedOnly = true
keywordSearchDisabled = true
`

	settings, err := ParseSettings(tomlData)
	c.Assert(err, gc.IsNil)
	c.Assert(settings.HKP, gc.NotNil)
	c.Assert(settings.HKP.Queries, gc.NotNil)
	c.Assert(settings.HKP.Queries.SelfSignedOnly, gc.Equals, true)
	c.Assert(settings.HKP.Queries.FingerprintOnly, gc.Equals, true)
}

func (s *ServerSuite) TestParseSettingsWithConflux(c *gc.C) {
	tomlData := `
[conflux.recon]
httpAddr = ":11370"
reconAddr = ":11372"
threshMult = 10
bitQuantum = 3
mBar = 6

[conflux.recon.leveldb]
path = "/tmp/test.db"
`

	settings, err := ParseSettings(tomlData)
	c.Assert(err, gc.IsNil)
	c.Assert(settings.Conflux, gc.NotNil)
	c.Assert(settings.Conflux.Recon, gc.NotNil)
	c.Assert(settings.Conflux.Recon.HTTPAddr, gc.Equals, ":11370")
	c.Assert(settings.Conflux.Recon.ReconAddr, gc.Equals, ":11372")
	c.Assert(settings.Conflux.Recon.ThreshMult, gc.Equals, 10)
	c.Assert(settings.Conflux.Recon.LevelDB, gc.NotNil)
	c.Assert(settings.Conflux.Recon.LevelDB.Path, gc.Equals, "/tmp/test.db")
}

func (s *ServerSuite) TestParseSettingsWithPKS(c *gc.C) {
	tomlData := `
[hkp]
bind = ":11371"

[pks]
from = "example@example.com"
to = [
	"test1",
	"test2",
]

[pks.smtp]
host = "example.com"
`

	settings, err := ParseSettings(tomlData)
	c.Assert(err, gc.IsNil)
	// check that other settings are not interfered with
	c.Assert(settings.HKP.Bind, gc.Equals, ":11371")
	c.Assert(settings.PKS, gc.NotNil)
	c.Assert(settings.PKS.From, gc.Equals, "example@example.com")
	c.Assert(settings.PKS.To, gc.HasLen, 2)
	c.Assert(settings.PKS.SMTP, gc.NotNil)
	c.Assert(settings.PKS.SMTP.Host, gc.Equals, "example.com")
}

func (s *ServerSuite) TestDataDirConfiguration(c *gc.C) {
	// Test default behavior
	config1 := `
loglevel="DEBUG"
`
	comment := gc.Commentf("config 1")
	settings, err := ParseSettings(config1)
	c.Assert(err, gc.IsNil, comment)
	// Should use default DataDir and update Tor cache path
	c.Assert(settings.DataDir, gc.Equals, DefaultDataDir, comment)
	c.Assert(settings.RateLimit.Tor.CacheFilePath, gc.Equals, "/var/lib/hockeypuck/tor_exit_nodes.cache", comment)

	// Test custom DataDir
	config2 := `
loglevel="DEBUG"
dataDir="/custom/data"
`
	comment = gc.Commentf("config 2")
	settings, err = ParseSettings(config2)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(settings.DataDir, gc.Equals, "/custom/data", comment)
	c.Assert(settings.RateLimit.Tor.CacheFilePath, gc.Equals, "/custom/data/tor_exit_nodes.cache", comment)

	// Test explicit cache path (should not be overridden by DataDir)
	config3 := `
loglevel="DEBUG"
dataDir="/custom/data"

[rateLimit.tor]
cacheFilePath="/explicit/path/tor_cache.json"
`
	comment = gc.Commentf("config 3")
	settings, err = ParseSettings(config3)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(settings.DataDir, gc.Equals, "/custom/data", comment)
	c.Assert(settings.RateLimit.Tor.CacheFilePath, gc.Equals, "/explicit/path/tor_cache.json", comment)

	// Test custom relative cache file name with DataDir
	config4 := `
loglevel="DEBUG"
dataDir="/opt/hockeypuck"

[rateLimit.tor]
cacheFilePath="custom_tor_exits.json"
`
	comment = gc.Commentf("config 4")
	settings, err = ParseSettings(config4)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(settings.DataDir, gc.Equals, "/opt/hockeypuck", comment)
	c.Assert(settings.RateLimit.Tor.CacheFilePath, gc.Equals, "/opt/hockeypuck/custom_tor_exits.json", comment)

	// Test subdirectory in relative path
	config5 := `
dataDir="/var/lib/hockeypuck"

[rateLimit.tor]
cacheFilePath="cache/tor/exits.cache"
`
	comment = gc.Commentf("config 5")
	settings, err = ParseSettings(config5)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(settings.RateLimit.Tor.CacheFilePath, gc.Equals, "/var/lib/hockeypuck/cache/tor/exits.cache", comment)
}

func (s *ServerSuite) TestEnvFuncMap(c *gc.C) {
	funcMap := envFuncMap()
	c.Assert(funcMap, gc.NotNil)

	// Check that the "osenv" function exists
	_, exists := funcMap["osenv"]
	c.Assert(exists, gc.Equals, true, gc.Commentf("envFuncMap should contain 'osenv' function"))
}
