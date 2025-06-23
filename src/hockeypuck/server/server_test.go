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
	"strings"
	"testing"
)

func TestDefaultSettings(t *testing.T) {
	settings := DefaultSettings()

	// Test basic defaults
	if settings.HKP.Bind != DefaultHKPBind {
		t.Errorf("Expected default HKP bind %s, got %s", DefaultHKPBind, settings.HKP.Bind)
	}

	if settings.HKP.LogRequestDetails != DefaultLogRequestDetails {
		t.Errorf("Expected default log request details %v, got %v", DefaultLogRequestDetails, settings.HKP.LogRequestDetails)
	}

	if settings.LogLevel != DefaultLogLevel {
		t.Errorf("Expected default log level %s, got %s", DefaultLogLevel, settings.LogLevel)
	}

	if settings.ReconStaleSecs != DefaultReconStaleSecs {
		t.Errorf("Expected default recon stale secs %d, got %d", DefaultReconStaleSecs, settings.ReconStaleSecs)
	}

	if settings.MaxResponseLen != DefaultMaxResponseLen {
		t.Errorf("Expected default max response len %d, got %d", DefaultMaxResponseLen, settings.MaxResponseLen)
	}

	// Test software info
	if settings.Software == "" {
		t.Error("Software should not be empty")
	}

	if settings.Version == "" {
		t.Error("Version should not be empty")
	}

	// Test OpenPGP defaults
	openpgp := settings.OpenPGP
	if openpgp.MaxKeyLength != DefaultMaxKeyLength {
		t.Errorf("Expected default max key length %d, got %d", DefaultMaxKeyLength, openpgp.MaxKeyLength)
	}

	if openpgp.MaxPacketLength != DefaultMaxPacketLength {
		t.Errorf("Expected default max packet length %d, got %d", DefaultMaxPacketLength, openpgp.MaxPacketLength)
	}

	// Test rate limiting defaults
	if !settings.RateLimit.Enabled {
		t.Error("Rate limiting should be enabled by default")
	}
}

func TestDefaultOpenPGP(t *testing.T) {
	config := DefaultOpenPGP()

	if config.MaxKeyLength != DefaultMaxKeyLength {
		t.Errorf("Expected max key length %d, got %d", DefaultMaxKeyLength, config.MaxKeyLength)
	}

	if config.MaxPacketLength != DefaultMaxPacketLength {
		t.Errorf("Expected max packet length %d, got %d", DefaultMaxPacketLength, config.MaxPacketLength)
	}

	if config.NWorkers != DefaultNWorkers {
		t.Errorf("Expected n workers %d, got %d", DefaultNWorkers, config.NWorkers)
	}

	// Blacklist should be empty by default
	if len(config.Blacklist) != 0 {
		t.Errorf("Expected empty blacklist, got %d items", len(config.Blacklist))
	}
}

func TestParseSettingsBasic(t *testing.T) {
	tomlData := `
[hkp]
bind = ":8080"
logRequestDetails = false

[openpgp]
maxKeyLength = 2048
nWorkers = 16

logLevel = "DEBUG"
hostname = "test.example.com"
`

	settings, err := ParseSettings(tomlData)
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if settings.HKP.Bind != ":8080" {
		t.Errorf("Expected HKP bind :8080, got %s", settings.HKP.Bind)
	}

	if settings.HKP.LogRequestDetails {
		t.Error("Expected LogRequestDetails to be false")
	}

	if settings.OpenPGP.MaxKeyLength != 2048 {
		t.Errorf("Expected max key length 2048, got %d", settings.OpenPGP.MaxKeyLength)
	}

	if settings.OpenPGP.NWorkers != 16 {
		t.Errorf("Expected n workers 16, got %d", settings.OpenPGP.NWorkers)
	}

	if settings.LogLevel != "DEBUG" {
		t.Errorf("Expected log level DEBUG, got %s", settings.LogLevel)
	}

	if settings.Hostname != "test.example.com" {
		t.Errorf("Expected hostname test.example.com, got %s", settings.Hostname)
	}
}

func TestParseSettingsWithRateLimit(t *testing.T) {
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
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if !settings.RateLimit.Enabled {
		t.Error("Rate limiting should be enabled")
	}

	if settings.RateLimit.MaxConcurrentConnections != 100 {
		t.Errorf("Expected max concurrent connections 100, got %d", settings.RateLimit.MaxConcurrentConnections)
	}

	if settings.RateLimit.HTTPRequestRate != 50 {
		t.Errorf("Expected HTTP request rate 50, got %d", settings.RateLimit.HTTPRequestRate)
	}

	if settings.RateLimit.Backend.Type != "redis" {
		t.Errorf("Expected backend type redis, got %s", settings.RateLimit.Backend.Type)
	}

	if settings.RateLimit.Backend.Redis.Addr != "localhost:6379" {
		t.Errorf("Expected Redis addr localhost:6379, got %s", settings.RateLimit.Backend.Redis.Addr)
	}

	if settings.RateLimit.Backend.Redis.KeyPrefix != "test:" {
		t.Errorf("Expected Redis key prefix test:, got %s", settings.RateLimit.Backend.Redis.KeyPrefix)
	}
}

func TestParseSettingsWithHTTPS(t *testing.T) {
	tomlData := `
[hkps]
bind = ":8443"
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
logRequestDetails = true
`

	settings, err := ParseSettings(tomlData)
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if settings.HKPS == nil {
		t.Fatal("HKPS config should not be nil")
	}

	if settings.HKPS.Bind != ":8443" {
		t.Errorf("Expected HKPS bind :8443, got %s", settings.HKPS.Bind)
	}

	if settings.HKPS.Cert != "/path/to/cert.pem" {
		t.Errorf("Expected HKPS cert /path/to/cert.pem, got %s", settings.HKPS.Cert)
	}

	if settings.HKPS.Key != "/path/to/key.pem" {
		t.Errorf("Expected HKPS key /path/to/key.pem, got %s", settings.HKPS.Key)
	}

	if !settings.HKPS.LogRequestDetails {
		t.Error("Expected HKPS LogRequestDetails to be true")
	}
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

func TestParseSettingsInvalidTOML(t *testing.T) {
	invalidData := `
[hkp
bind = ":8080"
`

	_, err := ParseSettings(invalidData)
	if err == nil {
		t.Error("Expected error for invalid TOML")
	}
}

func TestKeyWriterOptions(t *testing.T) {
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
	if len(opts) != 2 {
		t.Errorf("Expected 2 options, got %d", len(opts))
	}

	// Test with empty headers (should use defaults)
	settings.OpenPGP.Headers.Comment = ""
	settings.OpenPGP.Headers.Version = ""

	opts = KeyWriterOptions(settings)
	if len(opts) != 2 {
		t.Errorf("Expected 2 options with defaults, got %d", len(opts))
	}
}

func TestKeyReaderOptions(t *testing.T) {
	settings := &Settings{
		OpenPGP: OpenPGPConfig{
			MaxKeyLength:    1024,
			MaxPacketLength: 512,
			Blacklist:       []string{"badkey1", "badkey2"},
		},
	}

	opts := KeyReaderOptions(settings)
	if len(opts) != 3 {
		t.Errorf("Expected 3 options, got %d", len(opts))
	}

	// Test with zero limits (should not add those options)
	settings.OpenPGP.MaxKeyLength = 0
	settings.OpenPGP.MaxPacketLength = 0

	opts = KeyReaderOptions(settings)
	if len(opts) != 1 { // Only blacklist
		t.Errorf("Expected 1 option (blacklist only), got %d", len(opts))
	}

	// Test with empty blacklist
	settings.OpenPGP.Blacklist = nil

	opts = KeyReaderOptions(settings)
	if len(opts) != 0 {
		t.Errorf("Expected 0 options, got %d", len(opts))
	}
}

func TestSMTPConfigDefaults(t *testing.T) {
	if DefaultSMTPHost != "localhost:25" {
		t.Errorf("Expected default SMTP host localhost:25, got %s", DefaultSMTPHost)
	}
}

func TestDBConfigDefaults(t *testing.T) {
	if DefaultDBDriver != "postgres-jsonb" {
		t.Errorf("Expected default DB driver postgres-jsonb, got %s", DefaultDBDriver)
	}

	if !strings.Contains(DefaultDBDSN, "database=hockeypuck") {
		t.Errorf("Expected default DB DSN to contain database=hockeypuck, got %s", DefaultDBDSN)
	}
}

func TestOpenPGPConfigConstants(t *testing.T) {
	if DefaultMaxKeyLength != 1048576 {
		t.Errorf("Expected default max key length 1048576, got %d", DefaultMaxKeyLength)
	}

	if DefaultMaxPacketLength != 8192 {
		t.Errorf("Expected default max packet length 8192, got %d", DefaultMaxPacketLength)
	}

	if DefaultStatsRefreshHours != 4 {
		t.Errorf("Expected default stats refresh hours 4, got %d", DefaultStatsRefreshHours)
	}

	if DefaultNWorkers != 8 {
		t.Errorf("Expected default n workers 8, got %d", DefaultNWorkers)
	}
}

func TestQueryConfigDefaults(t *testing.T) {
	settings := DefaultSettings()

	// Test default query config
	if settings.HKP.Queries.SelfSignedOnly {
		t.Error("SelfSignedOnly should be false by default")
	}

	if settings.HKP.Queries.FingerprintOnly {
		t.Error("FingerprintOnly should be false by default")
	}
}

func TestParseSettingsWithQueryConfig(t *testing.T) {
	tomlData := `
[hkp.queries]
selfSignedOnly = true
keywordSearchDisabled = true
`

	settings, err := ParseSettings(tomlData)
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if !settings.HKP.Queries.SelfSignedOnly {
		t.Error("SelfSignedOnly should be true")
	}

	if !settings.HKP.Queries.FingerprintOnly {
		t.Error("FingerprintOnly should be true")
	}
}

func TestParseSettingsWithConflux(t *testing.T) {
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
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if settings.Conflux.Recon.HTTPAddr != ":11370" {
		t.Errorf("Expected recon HTTP addr :11370, got %s", settings.Conflux.Recon.HTTPAddr)
	}

	if settings.Conflux.Recon.ReconAddr != ":11372" {
		t.Errorf("Expected recon addr :11372, got %s", settings.Conflux.Recon.ReconAddr)
	}

	if settings.Conflux.Recon.ThreshMult != 10 {
		t.Errorf("Expected thresh mult 10, got %d", settings.Conflux.Recon.ThreshMult)
	}

	if settings.Conflux.Recon.LevelDB.Path != "/tmp/test.db" {
		t.Errorf("Expected LevelDB path /tmp/test.db, got %s", settings.Conflux.Recon.LevelDB.Path)
	}
}

func TestParseSettingsWithPKS(t *testing.T) {
	tomlData := `
[hkp]
bind = ":11371"

# PKS configuration would go here if it were used
# This test verifies that other configs don't interfere
`

	settings, err := ParseSettings(tomlData)
	if err != nil {
		t.Fatalf("ParseSettings failed: %v", err)
	}

	if settings.HKP.Bind != ":11371" {
		t.Errorf("Expected HKP bind :11371, got %s", settings.HKP.Bind)
	}
}

func TestEnvFuncMap(t *testing.T) {
	funcMap := envFuncMap()
	if funcMap == nil {
		t.Error("envFuncMap should not return nil")
	}

	// Check that the "osenv" function exists
	if _, exists := funcMap["osenv"]; !exists {
		t.Error("envFuncMap should contain 'osenv' function")
	}
}
