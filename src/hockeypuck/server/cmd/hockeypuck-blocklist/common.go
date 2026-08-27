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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	gocrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
)

// cliError is a failure to report as a plain message rather than a stack trace:
// a problem with what was asked for, or a finding the command exists to report.
type cliError struct {
	code  int
	cause error
}

func (e cliError) Error() string { return e.cause.Error() }
func (e cliError) Unwrap() error { return e.cause }

const exitUsage = 2

func usagef(format string, args ...any) error {
	return cliError{code: exitUsage, cause: fmt.Errorf(format, args...)}
}

func preconditionf(format string, args ...any) error {
	return cliError{code: exitUsage, cause: fmt.Errorf(format, args...)}
}

func findingf(format string, args ...any) error {
	return cliError{code: 1, cause: fmt.Errorf(format, args...)}
}

// session holds the storage handles a subcommand works through.
type session struct {
	settings *server.Settings
	storage  storage.Storage
	policy   *openpgp.Policy
	// peer is an sks.Peer instantiated but never started, so that it receives
	// KeyChange notifications and keeps the reconciliation prefix tree in step.
	// It is nil for read-only work.
	peer *sks.Peer
}

func openSession(settings *server.Settings, writable bool) (*session, error) {
	policy, err := openpgp.NewPolicy(server.PolicyOptions(settings)...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	st, err := server.DialStorage(settings, policy)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s := &session{settings: settings, storage: st, policy: policy}
	if writable {
		peer, err := sks.NewPeer(st, settings.Conflux.Recon.LevelDB.Path,
			&settings.Conflux.Recon.Settings, nil, "", nil, policy)
		if err != nil {
			st.Close()
			return nil, preconditionf(
				"cannot open the reconciliation prefix tree at %q: %v\n"+
					"The prefix tree is locked for as long as hockeypuck is running. Stop the\n"+
					"server and re-run, or submit the tombstone to the running server over HKP\n"+
					"instead, which needs no downtime.",
				settings.Conflux.Recon.LevelDB.Path, err)
		}
		peer.Idle()
		s.peer = peer
	}
	return s, nil
}

func (s *session) Close() {
	if s.peer != nil {
		s.peer.Stop()
	}
	if s.storage != nil {
		if err := s.storage.Close(); err != nil {
			log.Errorf("error closing storage: %v", err)
		}
	}
}

// normaliseFingerprints folds operator input into the lowercase bare hex the
// rest of the system uses, tolerating the "0x" prefix and the spacing that
// appears in copy-pasted gpg output.
func normaliseFingerprints(args []string) ([]string, error) {
	var fps []string
	var bad []string
	seen := map[string]bool{}
	for _, arg := range args {
		fp := openpgp.NormalizeFingerprint(arg)
		switch len(fp) {
		case 32, 40, 64:
		default:
			bad = append(bad, arg)
			continue
		}
		if strings.TrimLeft(fp, "0123456789abcdef") != "" {
			bad = append(bad, arg)
			continue
		}
		if !seen[fp] {
			seen[fp] = true
			fps = append(fps, fp)
		}
	}
	if len(bad) > 0 {
		return nil, usagef("not full fingerprints: %s", strings.Join(bad, ", "))
	}
	if len(fps) == 0 {
		return nil, usagef("no fingerprints given")
	}
	return fps, nil
}

// readSigningKey loads the private key that binds this node's origin to the
// blocks it issues. The server never needs this key; only this tool does.
func readSigningKey(path string) (*gocrypto.Entity, error) {
	if path == "" {
		return nil, usagef("a signing key is required: pass -sign-key PATH")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, usagef("cannot read signing key: %v", err)
	}
	defer f.Close()

	entities, err := gocrypto.ReadArmoredKeyRing(f)
	if err != nil {
		// Fall back to a binary keyring, so either form of export works.
		if _, seekErr := f.Seek(0, 0); seekErr != nil {
			return nil, errors.WithStack(err)
		}
		entities, err = gocrypto.ReadKeyRing(f)
		if err != nil {
			return nil, usagef("cannot parse signing key %q: %v", path, err)
		}
	}
	for _, entity := range entities {
		if entity.PrivateKey == nil {
			continue
		}
		if entity.PrivateKey.Encrypted {
			passphrase := os.Getenv(passphraseEnv)
			if passphrase == "" {
				return nil, usagef("signing key %q is passphrase protected; set %s",
					path, passphraseEnv)
			}
			if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return nil, usagef("cannot decrypt signing key %q: %v", path, err)
			}
			for _, sub := range entity.Subkeys {
				if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
					// A failure here is not fatal: the primary may be the signer.
					_ = sub.PrivateKey.Decrypt([]byte(passphrase))
				}
			}
		}
		return entity, nil
	}
	return nil, usagef("%q contains no private key", path)
}

// describeTombstone renders a block for an operator reading a list.
func describeTombstone(record *storage.Record) string {
	ts, sigs, err := openpgp.TombstoneOf(record.PrimaryKey)
	if err != nil {
		return fmt.Sprintf("0x%s  <unreadable tombstone: %v>", record.Fingerprint, err)
	}
	out := fmt.Sprintf("0x%s  origin %s", ts.Fingerprint, ts.Origin)
	if ts.Reason != "" {
		out += "  reason " + ts.Reason
	}
	out += fmt.Sprintf("  %s", plural(len(sigs), "signature", "signatures"))
	return out
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

// submitTombstones posts tombstones to a running server's HKP submission
// endpoint. A tombstone is an ordinary certificate on the wire, so this needs no
// new endpoint, and it avoids taking the prefix tree lock: the running server
// owns that, and updates it as it stores each block.
func submitTombstones(baseURL string, settings *server.Settings, tombstones []*openpgp.PrimaryKey) error {
	endpoint, err := submissionURL(baseURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}

	var submitted int
	for _, tombstone := range tombstones {
		var armored bytes.Buffer
		if err := openpgp.WriteArmoredPackets(&armored, []*openpgp.PrimaryKey{tombstone},
			false, server.KeyWriterOptions(settings)...); err != nil {
			return err
		}
		resp, err := client.PostForm(endpoint, url.Values{"keytext": {armored.String()}})
		if err != nil {
			return usagef("cannot reach %s: %v", endpoint, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Errorf("0x%s refused by %s: HTTP %d %s",
				tombstone.Fingerprint, endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
			continue
		}
		submitted++
		log.Debugf("submitted 0x%s to %s", tombstone.Fingerprint, endpoint)
	}
	fmt.Fprintf(os.Stderr, "submitted %s to %s\n", plural(submitted, "block", "blocks"), endpoint)
	if submitted < len(tombstones) {
		return findingf("%d of %d blocks were refused by the server",
			len(tombstones)-submitted, len(tombstones))
	}
	return nil
}

// submissionURL turns what an operator is likely to type into the submission
// endpoint, accepting a bare host, a base URL, or the full path.
func submissionURL(raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", usagef("cannot parse server address %q: %v", raw, err)
	}
	if parsed.Host == "" {
		return "", usagef("no host in server address %q", raw)
	}
	if !strings.HasSuffix(parsed.Path, "/pks/add") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/pks/add"
	}
	return parsed.String(), nil
}
