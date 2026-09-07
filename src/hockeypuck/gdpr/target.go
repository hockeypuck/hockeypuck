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

// Package gdpr provides the primitives used by hockeypuck-gdpr to service data
// subject erasure requests ("right to be forgotten", GDPR Art. 17): parsing the
// identifiers a data subject supplies, keeping an append-only audit trail of
// what was erased, and maintaining the blacklist that stops erased key material
// returning via reconciliation.
package gdpr

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// Kind classifies a Target so the caller knows which storage query resolves it.
type Kind string

const (
	KindFingerprint Kind = "fingerprint"
	KindKeyID       Kind = "keyid"
	KindEmail       Kind = "email"
	KindKeyword     Kind = "keyword"
)

// Target is a single normalised identifier to look up in storage.
type Target struct {
	// Kind determines which storage query resolves this Target.
	Kind Kind
	// Value is the normalised identifier: lowercase bare hex for fingerprints
	// and key IDs, a lowercase address for emails, verbatim for keywords.
	Value string
	// Raw is the identifier exactly as the operator supplied it.
	Raw string
}

func (t Target) String() string {
	return string(t.Kind) + ":" + t.Value
}

// kindPrefixes are the explicit "kind:value" overrides an operator can use when
// the heuristics below would guess wrong, e.g. a keyword that looks like hex.
var kindPrefixes = map[string]Kind{
	"fingerprint": KindFingerprint,
	"fp":          KindFingerprint,
	"keyid":       KindKeyID,
	"email":       KindEmail,
	"uid":         KindEmail,
	"keyword":     KindKeyword,
}

// ParseTarget normalises and classifies one operator-supplied identifier.
//
// An explicit "kind:value" prefix always wins. Otherwise a hex string of a
// plausible key ID or fingerprint length is treated as such (a leading "0x" and
// the spaces, colons and dashes that appear in copy-pasted gpg output are all
// tolerated), an address or a "Name <address>" form is treated as an email
// identity, and anything else is free text to match against key words.
func ParseTarget(s string) (Target, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Target{}, errors.New("empty search term")
	}

	if kind, rest, ok := splitKind(raw); ok {
		return parseAs(kind, rest, raw)
	}

	if hex, ok := normalizeHex(raw); ok {
		if kind, ok := classifyHex(hex); ok {
			return Target{Kind: kind, Value: hex, Raw: raw}, nil
		}
	}
	if addr, ok := parseEmail(raw); ok {
		return Target{Kind: KindEmail, Value: addr, Raw: raw}, nil
	}
	return Target{Kind: KindKeyword, Value: raw, Raw: raw}, nil
}

// parseAs normalises rest according to an explicitly requested Kind, so that a
// bad "fp:" or "email:" term is reported rather than silently mis-queried.
func parseAs(kind Kind, rest, raw string) (Target, error) {
	switch kind {
	case KindFingerprint, KindKeyID:
		hex, ok := normalizeHex(rest)
		if !ok {
			return Target{}, errors.Errorf("%q is not a hexadecimal %s", rest, kind)
		}
		got, ok := classifyHex(hex)
		if !ok {
			return Target{}, errors.Errorf("%q is %d hex digits, which is not a key ID (8 or 16) or fingerprint (32, 40 or 64) length", rest, len(hex))
		}
		// Honour the operator's intent where it is satisfiable: a key ID query
		// and a fingerprint query resolve identically, by prefix.
		if got != kind {
			kind = got
		}
		return Target{Kind: kind, Value: hex, Raw: raw}, nil
	case KindEmail:
		addr, ok := parseEmail(rest)
		if !ok {
			return Target{}, errors.Errorf("%q is not an email address", rest)
		}
		return Target{Kind: KindEmail, Value: addr, Raw: raw}, nil
	default:
		if strings.TrimSpace(rest) == "" {
			return Target{}, errors.New("empty keyword")
		}
		return Target{Kind: KindKeyword, Value: strings.TrimSpace(rest), Raw: raw}, nil
	}
}

// splitKind recognises a leading "kind:" override. It deliberately only fires
// on the known prefixes, so that colons elsewhere stay part of the term.
func splitKind(s string) (Kind, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	kind, ok := kindPrefixes[strings.ToLower(s[:i])]
	if !ok {
		return "", "", false
	}
	return kind, s[i+1:], true
}

// normalizeHex strips the punctuation found in copy-pasted key identifiers and
// folds the result to lowercase, reporting whether what remains is all hex.
func normalizeHex(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == ' ', r == '\t', r == ':', r == '-':
			continue
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		default:
			return "", false
		}
	}
	out := b.String()
	return out, out != ""
}

// classifyHex maps a bare hex string to the identifier it can only be, by
// length: v4 short and long key IDs, and v3, v4 and v6 fingerprints.
func classifyHex(hex string) (Kind, bool) {
	switch len(hex) {
	case 8, 16:
		return KindKeyID, true
	case 32, 40, 64:
		return KindFingerprint, true
	}
	return "", false
}

// parseEmail extracts the address from a bare address or a "Name <address>"
// user ID, matching how the storage layer derives the identity column it is
// looked up against.
func parseEmail(s string) (string, bool) {
	if lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">"); lbr != -1 && rbr > lbr {
		s = s[lbr+1 : rbr]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.ContainsAny(s, " \t<>") || strings.Count(s, "@") != 1 {
		return "", false
	}
	at := strings.Index(s, "@")
	if at <= 0 || at == len(s)-1 {
		return "", false
	}
	return s, true
}

// ParseTargets normalises a batch of terms, reporting every bad one at once so
// that an operator working from a long request does not have to fix them singly.
func ParseTargets(terms []string) ([]Target, error) {
	var targets []Target
	var problems []string
	seen := make(map[string]bool)
	for _, term := range terms {
		target, err := ParseTarget(term)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if seen[target.String()] {
			continue
		}
		seen[target.String()] = true
		targets = append(targets, target)
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "\n"))
	}
	return targets, nil
}

// ReadTerms reads one search term per line, ignoring blank lines and comments,
// so that the identifiers quoted in an erasure request can be piped in as-is.
func ReadTerms(r io.Reader) ([]string, error) {
	var terms []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		terms = append(terms, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	return terms, nil
}

// SortTargets orders targets so that runs are reproducible and so that cheap,
// exact identifier lookups are resolved before broad keyword scans.
func SortTargets(targets []Target) {
	rank := map[Kind]int{KindFingerprint: 0, KindKeyID: 1, KindEmail: 2, KindKeyword: 3}
	sort.SliceStable(targets, func(i, j int) bool {
		if rank[targets[i].Kind] != rank[targets[j].Kind] {
			return rank[targets[i].Kind] < rank[targets[j].Kind]
		}
		return targets[i].Value < targets[j].Value
	})
}
