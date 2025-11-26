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

package server

import (
	"bytes"
	"os"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/sprig/v3"
	"github.com/pkg/errors"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp/pks"
	"hockeypuck/metrics"
)

type confluxConfig struct {
	Recon reconConfig `toml:"recon"`
}

type levelDB struct {
	Path string `toml:"path"`
}

type reconConfig struct {
	recon.Settings
	LevelDB levelDB `toml:"leveldb"`
}

type HKPConfig struct {
	Bind              string `toml:"bind"`
	AdvBind           string `toml:"advertisedBind,omitempty"`
	LogRequestDetails bool   `toml:"logRequestDetails"`

	Queries queryConfig `toml:"queries"`
}

type queryConfig struct {
	// Only respond with verified self-signed key material in queries
	SelfSignedOnly bool `toml:"selfSignedOnly"`
	// Only allow fingerprint / key ID queries; no UID keyword searching allowed
	FingerprintOnly bool `toml:"keywordSearchDisabled"`
}

type HKPSConfig struct {
	Bind              string `toml:"bind"`
	LogRequestDetails bool   `toml:"logRequestDetails"`
	Cert              string `toml:"cert"`
	Key               string `toml:"key"`
}

const (
	DefaultSMTPHost = "localhost:25"
)

type SMTPConfig struct {
	Host string `toml:"host"`
	// ID is the user to act on behalf of, if not the authenticated user. Should normally be empty.
	ID       string `toml:"id"`
	User     string `toml:"user"`
	Password string `toml:"pass"`
}

const (
	DefaultDBDriver                  = "postgres-jsonb"
	DefaultDBDSN                     = "database=hockeypuck host=/var/run/postgresql port=5432 sslmode=disable"
	DefaultMaxKeyLength              = 1048576
	DefaultMaxPacketLength           = 8192
	DefaultDBReindexOnStartup        = true
	DefaultDBReindexStartupDelaySecs = 60 * 5
	DefaultDBReindexLoadDelaySecs    = 60 * 60 * 24
	DefaultDBReindexIntervalSecs     = 60 * 60 * 24 * 7
)

type DBConfig struct {
	Driver                  string `toml:"driver"`
	DSN                     string `toml:"dsn"`
	ReindexOnStartup        bool   `toml:"reindexOnStartup"`
	ReindexStartupDelaySecs int    `toml:"reindexStartupDelaySecs"`
	ReindexLoadDelaySecs    int    `toml:"reindexLoadDelaySecs"`
	ReindexIntervalSecs     int    `toml:"reindexIntervalSecs"`
}

const (
	DefaultStatsRefreshHours = 4
	DefaultNWorkers          = 8
)

type OpenPGPArmorHeaders struct {
	Comment string `toml:"comment"`
	Version string `toml:"version"`
}

const (
	DefaultArmorHeaderComment = ""
	DefaultArmorHeaderVersion = ""
)

type OpenPGPConfig struct {
	NWorkers int                 `toml:"nworkers"`
	DB       DBConfig            `toml:"db"`
	Headers  OpenPGPArmorHeaders `toml:"headers"`

	// NOTE: The following options will probably prevent your keyserver from
	// perfectly reconciling with other keyservers that do not share the same
	// policy, as key hashes will differ. This is still fine; perfect
	// reconciliation should not be necessary in order to receive and propagate
	// updates to keys.

	// MaxKeyLength limits the total length of key material when inserting,
	// updating or looking up key material. There is certainly an upper bound
	// on the total length of a key that should be allowed.
	//
	// While a max limit on key length works as a stopgap measure to prevent
	// propagation of hostile key material and it wasting resources, this
	// option leaves individual keys susceptible to a denial-of-service attack.
	// An attacker can add signatures to a target key until it crosses the
	// limit threshold, which would then block legitimate signatures from being
	// added past that point. So if you use this option, you should also
	// monitor the keys that are affected by it carefully.
	MaxKeyLength int `toml:"maxKeyLength"`

	// MaxPacketLength limits the size of an OpenPGP packet. Packets above this
	// size are just discarded. A reasonable upper bound might be 8-32k.
	// Limiting 4k and below may drop legitimate keys and signatures.
	//
	// This isn't a perfect solution to key spam, but it requires an attacker
	// to do more work by creating more keys or signing more packets, and
	// blocks casually malicious content.
	MaxPacketLength int `toml:"maxPacketLength"`

	// Blacklist contains a list of public key fingerprints that are not
	// allowed on this server at all. These keys are silently dropped from
	// inserts, updates, and lookups.
	Blacklist []string `toml:"blacklist"`
}

func DefaultOpenPGP() OpenPGPConfig {
	return OpenPGPConfig{
		NWorkers: DefaultNWorkers,
		Headers: OpenPGPArmorHeaders{
			Comment: DefaultArmorHeaderComment,
			Version: DefaultArmorHeaderVersion,
		},
		DB: DBConfig{
			Driver:                  DefaultDBDriver,
			DSN:                     DefaultDBDSN,
			ReindexOnStartup:        DefaultDBReindexOnStartup,
			ReindexStartupDelaySecs: DefaultDBReindexStartupDelaySecs,
			ReindexLoadDelaySecs:    DefaultDBReindexLoadDelaySecs,
			ReindexIntervalSecs:     DefaultDBReindexIntervalSecs,
		},
		MaxKeyLength:    DefaultMaxKeyLength,
		MaxPacketLength: DefaultMaxPacketLength,
	}
}

type Settings struct {
	Conflux confluxConfig `toml:"conflux"`

	IndexTemplate  string `toml:"indexTemplate"`
	VIndexTemplate string `toml:"vindexTemplate"`
	StatsTemplate  string `toml:"statsTemplate"`

	// HKPSConfig is a pointer so it can default to nil
	HKP  HKPConfig   `toml:"hkp"`
	HKPS *HKPSConfig `toml:"hkps"`

	PKS     *pks.Settings     `toml:"pks"`
	Metrics *metrics.Settings `toml:"metrics"`

	OpenPGP OpenPGPConfig `toml:"openpgp"`

	LogFile  string `toml:"logfile"`
	LogLevel string `toml:"loglevel"`

	Webroot string `toml:"webroot"`

	Contact      string `toml:"contact"`
	Hostname     string `toml:"hostname"`
	Nodename     string `toml:"nodename"`
	EnableVHosts bool   `toml:"enableVHosts"`
	Software     string
	Version      string
	BuiltAt      string

	ReconStaleSecs int      `toml:"reconStaleSecs"`
	MaxResponseLen int      `toml:"maxResponseLen"`
	AdminKeys      []string `toml:"adminKeys"`
}

const (
	DefaultLevelDBPath       = "recon.db"
	DefaultHKPBind           = ":11371"
	DefaultLogRequestDetails = true
	DefaultLogLevel          = "INFO"
	DefaultReconStaleSecs    = 86400
	DefaultMaxResponseLen    = 268435456
)

var (
	Software = "Hockeypuck"
	Version  = "~unreleased"
	BuiltAt  string
)

func DefaultSettings() Settings {
	metricsSettings := metrics.DefaultSettings()
	reconSettings := recon.DefaultSettings()
	pksSettings := pks.DefaultSettings()
	return Settings{
		Conflux: confluxConfig{
			Recon: reconConfig{
				Settings: *reconSettings,
				LevelDB: levelDB{
					Path: DefaultLevelDBPath,
				},
			},
		},
		PKS: pksSettings,
		HKP: HKPConfig{
			Bind:              DefaultHKPBind,
			LogRequestDetails: DefaultLogRequestDetails,
		},
		Metrics:        metricsSettings,
		OpenPGP:        DefaultOpenPGP(),
		LogLevel:       DefaultLogLevel,
		Software:       Software,
		Version:        Version,
		BuiltAt:        BuiltAt,
		ReconStaleSecs: DefaultReconStaleSecs,
		MaxResponseLen: DefaultMaxResponseLen,
		AdminKeys:      []string{},
	}
}

func ParseSettings(data string) (*Settings, error) {
	// Parse the configuration file as a template first
	tmpl, err := template.New("config").Funcs(sprig.TxtFuncMap()).Funcs(envFuncMap()).Parse(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Initialize a writer to render the template
	w := &bytes.Buffer{}

	// Render the template
	err = tmpl.Execute(w, readEnv())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var doc struct {
		Hockeypuck Settings `toml:"hockeypuck"`
	}
	doc.Hockeypuck = DefaultSettings()
	_, err = toml.Decode(w.String(), &doc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = doc.Hockeypuck.Conflux.Recon.Settings.Resolve()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &doc.Hockeypuck, nil
}

// EnvFuncMap returns a map of functions that can be used in a template
func envFuncMap() template.FuncMap {
	return template.FuncMap(
		map[string]interface{}{
			"osenv": func(prefix string) map[string]string {
				env := make(map[string]string)
				for _, e := range os.Environ() {
					pair := strings.SplitN(e, "=", 2)
					// if the environment variable starts with the prefix, add it to the map
					if strings.HasPrefix(pair[0], prefix) {
						env[pair[0]] = pair[1]
					}
				}
				return env
			},
		},
	)
}

// ReadEnv returns a map of environment variables
func readEnv() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		env[pair[0]] = pair[1]
	}
	return env
}
