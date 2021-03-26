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

package server

import (
	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"

	"hockeypuck/conflux/recon"
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

const (
	DefaultHKPBind = ":11371"
)

type HKPConfig struct {
	Bind string `toml:"bind"`

	Queries queryConfig `toml:"queries"`
}

type queryConfig struct {
	// Only respond with verified self-signed key material in queries
	SelfSignedOnly bool `toml:"selfSignedOnly"`
	// Only allow fingerprint / key ID queries; no UID keyword searching allowed
	FingerprintOnly bool `toml:"keywordSearchDisabled"`
}

type HKPSConfig struct {
	Bind string `toml:"bind"`
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type PKSConfig struct {
	From string     `toml:"from"`
	To   []string   `toml:"to"`
	SMTP SMTPConfig `toml:"smtp"`
}

const (
	DefaultSMTPHost = "localhost:25"
)

type SMTPConfig struct {
	Host     string `toml:"host"`
	ID       string `toml:"id"`
	User     string `toml:"user"`
	Password string `toml:"pass"`
}

const (
	DefaultDBDriver        = "postgres-jsonb"
	DefaultDBDSN           = "database=hockeypuck host=/var/run/postgresql port=5432 sslmode=disable"
	DefaultMaxKeyLength    = 1048576
	DefaultMaxPacketLength = 8192
)

type DBConfig struct {
	Driver string `toml:"driver"`
	DSN    string `toml:"dsn"`
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
	PKS      *PKSConfig          `toml:"pks"`
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
			Driver: DefaultDBDriver,
			DSN:    DefaultDBDSN,
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

	HKP  HKPConfig   `toml:"hkp"`
	HKPS *HKPSConfig `toml:"hkps"`

	Metrics *metrics.Settings `toml:"metrics"`

	OpenPGP OpenPGPConfig `toml:"openpgp"`

	LogFile  string `toml:"logfile"`
	LogLevel string `toml:"loglevel"`

	Webroot string `toml:"webroot"`

	Contact  string `toml:"contact"`
	Hostname string `toml:"hostname"`
	Software string `toml:"software"`
	Version  string `toml:"version"`

	SksCompat bool `toml:"sksCompat"`
}

const (
	DefaultLogLevel    = "INFO"
	DefaultLevelDBPath = "recon.db"
)

func DefaultSettings() Settings {
	metricsSettings := metrics.DefaultSettings()
	reconSettings := recon.DefaultSettings()
	return Settings{
		Conflux: confluxConfig{
			Recon: reconConfig{
				Settings: *reconSettings,
				LevelDB: levelDB{
					Path: DefaultLevelDBPath,
				},
			},
		},
		HKP: HKPConfig{
			Bind: DefaultHKPBind,
		},
		Metrics:   metricsSettings,
		OpenPGP:   DefaultOpenPGP(),
		LogLevel:  DefaultLogLevel,
		Software:  "Hockeypuck",
		Version:   "~unreleased",
		SksCompat: false,
	}
}

func ParseSettings(data string) (*Settings, error) {
	var doc struct {
		Hockeypuck Settings `toml:"hockeypuck"`
	}
	doc.Hockeypuck = DefaultSettings()
	_, err := toml.Decode(data, &doc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = doc.Hockeypuck.Conflux.Recon.Settings.Resolve()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &doc.Hockeypuck, nil
}
