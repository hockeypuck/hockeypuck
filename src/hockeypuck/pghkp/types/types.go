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

package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"hockeypuck/hkp/jsonhkp"
	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"
)

// keyDoc is a nearly-raw copy of a row in the PostgreSQL `keys` table.
type KeyDoc struct {
	RFingerprint string
	VFingerprint string
	KeyID        string
	CTime        time.Time
	MTime        time.Time
	IdxTime      time.Time
	MD5          string
	Doc          string
	Keywords     string
}

func ReadOneKey(b []byte, rfingerprint string) (*openpgp.PrimaryKey, error) {
	kr := openpgp.NewKeyReader(bytes.NewBuffer(b))
	keys, err := kr.Read()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(keys) == 0 {
		return nil, nil
	} else if len(keys) > 1 {
		return nil, errors.Errorf("multiple keys in record: %v, %v", keys[0].Fingerprint(), keys[1].Fingerprint())
	}
	if keys[0].RFingerprint != rfingerprint {
		return nil, errors.Errorf("RFingerprint mismatch: expected=%q got=%q",
			rfingerprint, keys[0].RFingerprint)
	}
	return keys[0], nil
}

// keywordsFromTSVector converts a PostgreSQL tsvector back into a slice of tokens.
func keywordsFromTSVector(tsv string) (result []string) {
	m := make(map[string]bool)
	var s string
	for {
		i := strings.Index(tsv, "'")
		if i == -1 {
			break
		}
		tsv = tsv[i+1:]
		i = 0
		for {
			j := strings.Index(tsv[i:], "'")
			if j == -1 {
				log.Debugf("unpaired single quote in TSVector, truncating")
				i = 0
				break
			}
			i += j
			// if the single quote is the last character,
			// or the character after the match is NOT another single quote,
			// we have found the real closing single quote
			if i == len(tsv)-1 || tsv[i+1] != 0x27 {
				break
			}
			// skip both single quotes and go around
			i += 2
		}
		if i == 0 {
			break
		}
		s, tsv = tsv[:i], tsv[i+1:]
		m[s] = true
	}
	for k := range m {
		result = append(result, desanitiseFromTSVector(k))
	}
	return
}

// keywordsFromKey returns slices of keyword tokens, email addresses, and UIDs
// extracted from the UserID packets of the given key.
//
// TODO: shouldn't this be a method on openpgp.PrimaryKey instead?
// It's not specific to PostgreSQL, or even to storage.
func keywordsFromKey(key *openpgp.PrimaryKey) (keywords []string, emails []string, uids []string) {
	keywordMap := make(map[string]bool)
	emailMap := make(map[string]bool)
	uidMap := make(map[string]bool)
	for _, uid := range key.UserIDs {
		s := strings.ToLower(uid.Keywords)
		// always include full text of UserID (lowercased)
		keywordMap[s] = true
		uidMap[s] = true
		email := ""
		commentary := s
		lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
		if lbr != -1 && rbr > lbr {
			email = s[lbr+1 : rbr]
			commentary = s[:lbr]
		} else {
			email = s
			commentary = ""
		}
		// TODO: this still doesn't recognise all possible forms of UID :confounded:
		if email != "" {
			keywordMap[email] = true
			emailMap[email] = true
			parts := strings.SplitN(email, "@", 2)
			if len(parts) == 2 {
				keywordMap[parts[0]] = true
				keywordMap[parts[1]] = true
			}
		}
		if commentary != "" {
			for _, field := range strings.FieldsFunc(commentary, func(r rune) bool {
				return !utf8.ValidRune(r) || // split on invalid runes
					!(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '@') // split on [^[:alnum:]@-]
			}) {
				keywordMap[field] = true
				for _, part := range strings.Split(field, "-") {
					keywordMap[part] = true
				}
			}
		}
	}
	for k := range keywordMap {
		// discard empty strings, low ASCII symbols, single digits, stop words
		if k == "" || (len(k) == 1 && k[0] < 0x41) || slices.Contains(pgEnglishStopWords, k) {
			continue
		}
		keywords = append(keywords, k)
	}
	for k := range emailMap {
		if k == "" {
			continue
		}
		emails = append(emails, k)
	}
	for k := range uidMap {
		if k == "" {
			continue
		}
		uids = append(uids, k)
	}
	return
}

// keywordsFromSearch returns slices of keyword tokens and email addresses
// extracted from the supplied search string.
//
// TODO: shouldn't this also be generic?
func keywordsFromSearch(search string) (keywords []string, emails []string) {
	keywordMap := make(map[string]bool)
	emailMap := make(map[string]bool)
	s := strings.ToLower(search)
	email := s
	lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
	if lbr != -1 && rbr > lbr {
		email = s[lbr+1 : rbr]
		keywordMap[email] = true
		emailMap[email] = true
	} else {
		for _, field := range strings.FieldsFunc(s, func(r rune) bool {
			return !utf8.ValidRune(r) || unicode.IsSpace(r) // split on invalid runes and whitespace
		}) {
			keywordMap[field] = true
		}
	}
	for k := range keywordMap {
		// discard empty strings, low ASCII symbols, single digits, stop words
		if k == "" || (len(k) == 1 && k[0] < 0x41) || slices.Contains(pgEnglishStopWords, k) {
			continue
		}
		keywords = append(keywords, k)
	}
	for k := range emailMap {
		if k == "" {
			continue
		}
		emails = append(emails, k)
	}
	return
}

func KeywordsTSVector(key *openpgp.PrimaryKey) string {
	keywords, _, _ := keywordsFromKey(key)
	tsv, err := keywordsToTSVector(keywords, " ")
	if err != nil {
		// In this case we've found a key that generated
		// an invalid tsvector - this is pretty much guaranteed
		// to be a bogus key, since having a valid key with
		// user IDs that exceed limits is highly unlikely.
		// In the future we should catch this earlier and
		// reject it as a bad key, but for now we just skip
		// storing keyword information.
		log.Warningf("keywords for rfp=%q exceeds limit, ignoring: %v", key.RFingerprint, err)
		return ""
	}
	return tsv
}

func KeywordsTSQuery(query string) (string, error) {
	keywords, _ := keywordsFromSearch(query)
	tsq, err := keywordsToTSVector(keywords, " & ")
	if err != nil {
		log.Warningf("cannot convert search string to tsquery: %v", err)
		return "", err
	}
	return tsq, nil
}

// A woefully incomplete list of PostgreSQL stop words to minimise TSVector churn.
// https://github.com/postgres/postgres/blob/master/src/backend/snowball/stopwords/english.stop
var pgEnglishStopWords = []string{
	"i", "me", "my", "myself", "we", "our", "ours", "ourselves", "you", "your", "yours", "yourself", "yourselves",
	"he", "him", "his", "himself", "she", "her", "hers", "herself", "it", "its", "itself",
	"they", "them", "their", "theirs", "themselves", "what", "which", "who", "whom", "this", "that", "these", "those",
	"am", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "having", "do", "does", "did", "doing",
	"a", "an", "the", "and", "but", "if", "or",
	"because", "as", "until", "while", "of", "at", "by", "for", "with", "about", "against", "between", "into",
	"through", "during", "before", "after", "above", "below",
	"to", "from", "up", "down", "in", "out", "on", "off", "over", "under", "again", "further",
	"then", "once", "here", "there", "when", "where", "why", "how", "all", "any", "both", "each",
	"few", "more", "most", "other", "some", "such",
	"no", "nor", "not", "only", "own", "same", "so", "than", "too", "very",
	"s", "t", "can", "will", "just", "don", "should", "now",
	"[", "\\", "]", "^", "_", "`", "{", "|", "}", "~", // easier to list these than calculate a formula
}

// sanitiseForTSVector escapes characters that have special meaning to ::TSVECTOR
func sanitiseForTSVector(s string) string {
	s = strings.ReplaceAll(s, `'`, `''`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return s
}

// desanitiseFromTSVector un-escapes characters that have special meaning to ::TSVECTOR
// It is the inverse of sanitiseForTSVector
func desanitiseFromTSVector(s string) string {
	s = strings.ReplaceAll(s, `''`, `'`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

// keywordsToTSVector converts a slice of keywords to a
// PostgreSQL tsvector. If the resulting tsvector would
// be considered invalid by PostgreSQL an error is
// returned instead.
// `sep` SHOULD be either " " or "&". If "&", the output
// string is a tsquery rather than a tsvector.
func keywordsToTSVector(keywords []string, sep string) (string, error) {
	const (
		lexemeLimit   = 2048            // 2KB for single lexeme
		tsvectorLimit = 1 * 1024 * 1024 // 1MB for lexemes + positions
	)
	newKeywords := []string{}
	for _, k := range keywords {
		if l := len(k); l >= lexemeLimit {
			return "", fmt.Errorf("keyword exceeds limit (%d >= %d)", l, lexemeLimit)
		}
		newKeywords = append(newKeywords, fmt.Sprintf("'%s'", sanitiseForTSVector(k)))
	}
	tsv := strings.Join(newKeywords, sep)

	if l := len(tsv); l >= tsvectorLimit {
		return "", fmt.Errorf("keywords exceeds limit (%d >= %d)", l, tsvectorLimit)
	}
	return tsv, nil
}

// refresh updates the keyDoc fields that cache values from the jsonb document.
// This is called by pghkp.refreshBunch to ensure the DB columns are correctly populated,
// for example after changes to the keyword indexing policy, or to the DB schema.
func (kd *KeyDoc) Refresh() (changed bool, err error) {
	// Unmarshal the doc
	var pk jsonhkp.PrimaryKey
	err = json.Unmarshal([]byte(kd.Doc), &pk)
	if err != nil {
		return false, err
	}
	rfp := openpgp.Reverse(pk.Fingerprint)
	key, err := ReadOneKey(pk.Bytes(), rfp)
	if err != nil {
		return false, err
	}
	if key == nil {
		// ReadOneKey could not find any keys in the JSONB doc
		return false, openpgp.ErrKeyEvaporated
	}

	// Regenerate keywords
	newKeywords, _, _ := keywordsFromKey(key)
	oldKeywords := keywordsFromTSVector(kd.Keywords)
	slices.Sort(newKeywords)
	slices.Sort(oldKeywords)
	if !slices.Equal(oldKeywords, newKeywords) {
		log.Debugf("keyword mismatch on fp=%s, was %q now %q", pk.Fingerprint, oldKeywords, newKeywords)
		kd.Keywords, err = keywordsToTSVector(newKeywords, " ")
		changed = true
	}

	// Update to post-2.3 keyDoc schema
	if kd.VFingerprint == "" || kd.KeyID == "" {
		kd.VFingerprint = key.VFingerprint
		kd.KeyID = key.KeyID
		changed = true
	}

	// TODO: also update the subkeys table, and create a userids table!

	// In future we may add further tasks here.
	// DO NOT update the md5 field, as this is used by bulkReindex to prevent simultaneous updates.

	return changed, err
}

func subkeys(key *openpgp.PrimaryKey) []string {
	var result []string
	for _, subkey := range key.SubKeys {
		result = append(result, subkey.RFingerprint)
	}
	return result
}
