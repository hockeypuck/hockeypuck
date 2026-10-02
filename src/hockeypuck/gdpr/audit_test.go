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

package gdpr

import (
	"os"
	"path/filepath"
	"time"

	gc "gopkg.in/check.v1"
)

type AuditSuite struct{}

var _ = gc.Suite(&AuditSuite{})

// openTestLog creates an audit trail under a fresh temporary directory,
// including a directory level that does not exist yet.
func (s *AuditSuite) openTestLog(c *gc.C) (*Log, string) {
	path := filepath.Join(c.MkDir(), "nested", "audit.jsonl")
	log, err := OpenLog(path)
	c.Assert(err, gc.IsNil)
	return log, path
}

func (s *AuditSuite) TestRoundTrip(c *gc.C) {
	log, path := s.openTestLog(c)
	c.Assert(log.Path(), gc.Equals, path)

	when := time.Date(2026, 8, 22, 10, 30, 0, 0, time.UTC)
	c.Assert(log.Append(Entry{
		Time:        when,
		Action:      ActionErase,
		Result:      ResultErased,
		Case:        "GDPR-2026-001",
		Operator:    "operator",
		Fingerprint: v4fp,
		UserIDHash:  HashUserIDs([]string{"Alice <alice@example.com>"}),
	}), gc.IsNil)
	c.Assert(log.Append(Entry{
		Action:      ActionErase,
		Result:      ResultErased,
		Case:        "GDPR-2026-002",
		Fingerprint: v6fp,
	}), gc.IsNil)
	c.Assert(log.Close(), gc.IsNil)

	entries, err := ReadLog(path)
	c.Assert(err, gc.IsNil)
	c.Assert(entries, gc.HasLen, 2)
	c.Check(entries[0].Time.Equal(when), gc.Equals, true)
	c.Check(entries[0].Case, gc.Equals, "GDPR-2026-001")
	c.Check(entries[0].UserIDs, gc.IsNil)
	// An entry appended without a timestamp is stamped on write.
	c.Check(entries[1].Time.IsZero(), gc.Equals, false)
}

func (s *AuditSuite) TestAppendsRatherThanTruncates(c *gc.C) {
	log, path := s.openTestLog(c)
	c.Assert(log.Append(Entry{Action: ActionErase, Result: ResultErased, Fingerprint: v4fp}), gc.IsNil)
	c.Assert(log.Close(), gc.IsNil)

	reopened, err := OpenLog(path)
	c.Assert(err, gc.IsNil)
	c.Assert(reopened.Append(Entry{Action: ActionErase, Result: ResultErased, Fingerprint: v6fp}), gc.IsNil)
	c.Assert(reopened.Close(), gc.IsNil)

	entries, err := ReadLog(path)
	c.Assert(err, gc.IsNil)
	c.Assert(entries, gc.HasLen, 2)
}

func (s *AuditSuite) TestReadMissingLogIsEmpty(c *gc.C) {
	entries, err := ReadLog(filepath.Join(c.MkDir(), "absent.jsonl"))
	c.Assert(err, gc.IsNil)
	c.Check(entries, gc.HasLen, 0)
}

func (s *AuditSuite) TestReadCorruptLogFails(c *gc.C) {
	path := filepath.Join(c.MkDir(), "corrupt.jsonl")
	c.Assert(os.WriteFile(path, []byte("{\"action\":\"erase\"}\nnot json\n"), 0o600), gc.IsNil)
	_, err := ReadLog(path)
	c.Assert(err, gc.ErrorMatches, ".*corrupt audit log.*line 2.*")
}

func (s *AuditSuite) TestHashUserIDsIsOrderIndependent(c *gc.C) {
	a := HashUserIDs([]string{"Alice <alice@example.com>", "alice@example.net"})
	b := HashUserIDs([]string{"alice@example.net", "ALICE <Alice@Example.com>"})
	c.Check(a, gc.Equals, b)
	c.Check(a, gc.Not(gc.Equals), HashUserIDs([]string{"bob@example.com"}))
	c.Check(HashUserIDs(nil), gc.Equals, "")
}

func (s *AuditSuite) TestErasedFingerprintsExcludesDryRunsAndFailures(c *gc.C) {
	entries := []Entry{
		{Action: ActionErase, Result: ResultErased, Case: "A", Fingerprint: v4fp},
		// A repeat of the same erasure must not double up.
		{Action: ActionErase, Result: ResultErased, Case: "A", Fingerprint: v4fp},
		{Action: ActionErase, Result: ResultErased, Case: "A", Fingerprint: v6fp, DryRun: true},
		{Action: ActionErase, Result: ResultFailed, Case: "A", Fingerprint: v6fp},
		{Action: ActionErase, Result: ResultNotFound, Case: "A", Fingerprint: v6fp},
		{Action: ActionExport, Result: ResultExported, Case: "A", Fingerprint: v6fp},
		{Action: ActionErase, Result: ResultErased, Case: "B", Fingerprint: v6fp},
	}
	c.Check(ErasedFingerprints(entries, Filter{}), gc.DeepEquals, []string{v4fp, v6fp})
	c.Check(ErasedFingerprints(entries, Filter{Case: "a"}), gc.DeepEquals, []string{v4fp})
	c.Check(ErasedFingerprints(entries, Filter{Case: "B"}), gc.DeepEquals, []string{v6fp})
}

func (s *AuditSuite) TestFilterSince(c *gc.C) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	entries := []Entry{
		{Time: old, Action: ActionErase, Result: ResultErased, Fingerprint: v4fp},
		{Time: recent, Action: ActionErase, Result: ResultErased, Fingerprint: v6fp},
	}
	filtered := FilterEntries(entries, Filter{Since: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)})
	c.Assert(filtered, gc.HasLen, 1)
	c.Check(filtered[0].Fingerprint, gc.Equals, v6fp)
}
