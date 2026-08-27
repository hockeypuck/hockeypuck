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

// hockeypuck-blocklist issues and inspects blocklist tombstones: certificates
// that stand in for key material this server refuses to hold.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"hockeypuck/server"
	"hockeypuck/server/cmd"
)

const (
	defaultConfigPath = "/etc/hockeypuck/hockeypuck.conf"
	configEnv         = "HOCKEYPUCK_CONFIG"
	passphraseEnv     = "HOCKEYPUCK_BLOCKLIST_PASSPHRASE"
)

type command struct {
	name        string
	args        string
	summary     string
	description string
	setup       func(fs *flag.FlagSet)
	run         func(settings *server.Settings, args []string) error
}

var commands = []*command{blockCommand, unblockCommand, migrateCommand, listCommand, showCommand}

func lookupCommand(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}
	name := os.Args[1]
	switch name {
	case "-h", "-help", "--help", "help":
		printUsage(os.Stdout)
		os.Exit(0)
	}
	c := lookupCommand(name)
	if c == nil {
		fmt.Fprintf(os.Stderr, "hockeypuck-blocklist: unknown command %q\n\n", name)
		printUsage(os.Stderr)
		os.Exit(2)
	}

	// Splice the subcommand out so the flag package, and the -config/-log flags
	// registered by hockeypuck/server/cmd, see only what is meant for them.
	os.Args = append(os.Args[:1:1], os.Args[2:]...)
	flag.CommandLine.Usage = func() { commandUsage(os.Stderr, c, name) }
	if c.setup != nil {
		c.setup(flag.CommandLine)
	}
	flag.Parse()

	resolveConfigFlag()
	settings := cmd.Init(false)
	cmd.HandleSignals()

	err := c.run(settings, flag.Args())
	var reportable cliError
	if errors.As(err, &reportable) {
		fmt.Fprintf(os.Stderr, "hockeypuck-blocklist %s: %v\n", name, reportable)
		if reportable.code == exitUsage {
			fmt.Fprintf(os.Stderr, "Run \"hockeypuck-blocklist %s -h\" for usage.\n", name)
		}
		os.Exit(reportable.code)
	}
	cmd.Die(err)
}

// resolveConfigFlag fills in -config from the environment or the packaged
// location, so the common case needs no flag.
func resolveConfigFlag() {
	f := flag.Lookup("config")
	if f == nil {
		return
	}
	path, err := configPath(f.Value.String(), os.Getenv(configEnv), func(candidate string) error {
		_, statErr := os.Stat(candidate)
		return statErr
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hockeypuck-blocklist: %v\n", err)
		os.Exit(2)
	}
	if path == "" {
		return
	}
	if err := f.Value.Set(path); err != nil {
		fmt.Fprintf(os.Stderr, "hockeypuck-blocklist: cannot use configuration file %q: %v\n", path, err)
		os.Exit(2)
	}
}

// configPath decides which configuration file to work through. It returns the
// empty string when -config was given and should be left as it is.
//
// A set HOCKEYPUCK_CONFIG is authoritative, and unreadable is an error rather
// than a reason to look elsewhere. Falling through to the packaged path would
// let a typo in the variable point block, unblock or migrate at the default
// instance - silently operating on the wrong keyserver, which for this tool
// means blocking the wrong keys.
func configPath(flagValue, env string, readable func(string) error) (string, error) {
	if flagValue != "" {
		return "", nil
	}
	if env != "" {
		if err := readable(env); err != nil {
			return "", fmt.Errorf("%s is set to %q, which cannot be read: %v", configEnv, env, err)
		}
		return env, nil
	}
	if err := readable(defaultConfigPath); err == nil {
		return defaultConfigPath, nil
	}
	return "", fmt.Errorf("no configuration file found at %s; pass -config PATH or set %s",
		defaultConfigPath, configEnv)
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `hockeypuck-blocklist issues and inspects blocklist tombstones: certificates
that stand in for key material this server refuses to hold.

Usage:
  hockeypuck-blocklist <command> [flags] [arguments]

Commands:
`)
	names := append([]*command(nil), commands...)
	sort.Slice(names, func(i, j int) bool { return names[i].name < names[j].name })
	width := 0
	for _, c := range names {
		width = max(width, len(c.name))
	}
	for _, c := range names {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}
	fmt.Fprintf(w, `
Run "hockeypuck-blocklist <command> -h" for the flags of a single command.

A block is only honoured by a server that trusts the origin that signed it, so
before issuing any, set an origin and trust its key in hockeypuck.conf:

  [hockeypuck.openpgp.blocklist]
  origin = "keys.example.com"

  [hockeypuck.openpgp.blocklist.trustedOrigins]
  "keys.example.com" = ["<fingerprint of the signing key>"]

The signing key's public half must also be present in the keyserver, as admin
keys are. Its private half is only needed by this tool, never by the server.
`)
}

func commandUsage(w *os.File, c *command, invokedAs string) {
	fmt.Fprintf(w, "Usage: hockeypuck-blocklist %s [flags] %s\n\n%s\n\nFlags:\n",
		invokedAs, c.args, strings.TrimSpace(c.description))
	flag.CommandLine.SetOutput(w)
	flag.PrintDefaults()
}
