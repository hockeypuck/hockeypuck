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

// hockeypuck-gdpr services data subject erasure requests ("right to be
// forgotten", GDPR Art. 17) against a running Hockeypuck deployment. It reads
// the ordinary hockeypuck.conf, so it talks to the same database, prefix tree
// and blacklist as the server itself.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"hockeypuck/server"
	"hockeypuck/server/cmd"
)

const (
	// defaultConfigPath is where the Debian and snap packages install the
	// server configuration.
	defaultConfigPath = "/etc/hockeypuck/hockeypuck.conf"
	// configEnv overrides defaultConfigPath without a -config flag.
	configEnv = "HOCKEYPUCK_CONFIG"
	// auditEnv overrides where the audit trail is kept.
	auditEnv = "HOCKEYPUCK_GDPR_AUDIT"
	// auditBasename is the audit trail's name under the state directory.
	auditBasename = "gdpr-audit.jsonl"
)

// command is one subcommand of hockeypuck-gdpr.
type command struct {
	name string
	// aliases are additional names the subcommand answers to, so that the verb
	// an operator reaches for first works without them having to look it up.
	aliases []string
	args    string
	summary string
	// description is printed above the flag list by -h.
	description string
	// setup registers the subcommand's own flags before parsing.
	setup func(fs *flag.FlagSet)
	run   func(settings *server.Settings, args []string) error
}

var commands = []*command{
	searchCommand,
	exportCommand,
	eraseCommand,
	verifyCommand,
	blacklistCommand,
	auditCommand,
}

func lookupCommand(name string) *command {
	for _, c := range commands {
		if c.name == name || slices.Contains(c.aliases, name) {
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
		fmt.Fprintf(os.Stderr, "hockeypuck-gdpr: unknown command %q\n\n", name)
		printUsage(os.Stderr)
		os.Exit(2)
	}

	// Splice the subcommand out of the argument list so that the standard flag
	// package, and the -config/-log flags that hockeypuck/server/cmd registers
	// on flag.CommandLine, see only the flags meant for them.
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
		fmt.Fprintf(os.Stderr, "hockeypuck-gdpr %s: %v\n", name, reportable)
		if reportable.code == exitUsage {
			fmt.Fprintf(os.Stderr, "Run \"hockeypuck-gdpr %s -h\" for usage.\n", name)
		}
		os.Exit(reportable.code)
	}
	// Anything else is a genuine fault, and cmd.Die's stack trace earns its keep.
	cmd.Die(err)
}

// resolveConfigFlag fills in -config from the environment or the packaged
// location, so that the common case needs no flag at all. cmd.Init would
// otherwise fail obscurely on an empty path.
func resolveConfigFlag() {
	f := flag.Lookup("config")
	if f == nil {
		return
	}
	if f.Value.String() != "" {
		return
	}
	for _, candidate := range []string{os.Getenv(configEnv), defaultConfigPath} {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		if err := f.Value.Set(candidate); err != nil {
			fmt.Fprintf(os.Stderr, "hockeypuck-gdpr: cannot use configuration file %q: %v\n", candidate, err)
			os.Exit(2)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "hockeypuck-gdpr: no configuration file found at %s.\n"+
		"Pass -config PATH or set %s.\n", defaultConfigPath, configEnv)
	os.Exit(2)
}

// defaultAuditPath resolves where the audit trail lives when -audit is not
// given. It sits alongside the reconciliation prefix tree, which is already the
// server's writable state directory.
func defaultAuditPath(settings *server.Settings) string {
	if fromEnv := os.Getenv(auditEnv); fromEnv != "" {
		return fromEnv
	}
	dir := filepath.Dir(settings.Conflux.Recon.LevelDB.Path)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, auditBasename)
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `hockeypuck-gdpr services data subject erasure requests against a Hockeypuck
keyserver, using the same configuration file as the server itself.

Usage:
  hockeypuck-gdpr <command> [flags] [arguments]

Commands:
`)
	names := make([]*command, len(commands))
	copy(names, commands)
	sort.Slice(names, func(i, j int) bool { return names[i].name < names[j].name })
	width := 0
	for _, c := range names {
		width = max(width, len(c.name))
	}
	for _, c := range names {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
		if len(c.aliases) > 0 {
			fmt.Fprintf(w, "  %-*s  (also: %s)\n", width, "", strings.Join(c.aliases, ", "))
		}
	}
	fmt.Fprintf(w, `
Run "hockeypuck-gdpr <command> -h" for the flags of a single command.

The configuration file is taken from -config, else $%s, else
%s. A typical request is worked through as:

  hockeypuck-gdpr search alice@example.com
  hockeypuck-gdpr export -case GDPR-2026-001 -o ./evidence alice@example.com
  hockeypuck-gdpr erase  -case GDPR-2026-001 -dry-run alice@example.com
  hockeypuck-gdpr erase  -case GDPR-2026-001 -blacklist-out /etc/hockeypuck/gdpr-blacklist.toml alice@example.com
  hockeypuck-gdpr verify -case GDPR-2026-001

Erasing key material also requires blacklisting it, otherwise reconciliation
partners re-offer the key and it returns within hours. See the "blacklist"
command.
`, configEnv, defaultConfigPath)
}

// commandUsage describes one subcommand. invokedAs is the name the operator
// actually typed, which may be one of the subcommand's aliases.
func commandUsage(w *os.File, c *command, invokedAs string) {
	fmt.Fprintf(w, "Usage: hockeypuck-gdpr %s [flags] %s\n\n%s\n\nFlags:\n",
		invokedAs, c.args, strings.TrimSpace(c.description))
	flag.CommandLine.SetOutput(w)
	flag.PrintDefaults()
}
