/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  the Hockeypuck Contributors

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

package pks

import (
	"net/http/httptest"
	stdtesting "testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	gc "gopkg.in/check.v1"

	"hockeypuck/hkp"
	"hockeypuck/hkp/pks/storage"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/hkp/storage/mock"
	"hockeypuck/openpgp"
	"hockeypuck/testing"
)

type testKey struct {
	fp   string
	sid  string
	file string
}

var (
	testKeyDefault = &testKey{
		fp:   "10fe8cf1b483f7525039aa2a361bc1f023e0dcca",
		sid:  "23e0dcca",
		file: "alice_signed.asc",
	}
	testKeys = map[string]*testKey{
		testKeyDefault.fp: testKeyDefault,
	}
)

var statuses []*storage.Status

func Test(t *stdtesting.T) { gc.TestingT(t) }

type PksSuite struct {
	storage *mock.Storage
	srv     *httptest.Server
	sender  *Sender
	handler *hkp.Handler
}

var _ = gc.Suite(&PksSuite{})

func (s *PksSuite) SetUpTest(c *gc.C) {
	s.storage = mock.NewStorage(
		mock.ModifiedSinceToFp(func(time.Time, time.Time) ([]string, time.Time, error) {
			tk := testKeyDefault
			return []string{tk.fp}, time.Now().UTC(), nil
		}),
		mock.FetchRecordsByFp(func(keys []string, options ...string) ([]*hkpstorage.Record, error) {
			tk := testKeyDefault
			if len(keys) == 1 && testKeys[keys[0]] != nil {
				tk = testKeys[keys[0]]
			}
			records := []*hkpstorage.Record{}
			for _, v := range openpgp.MustReadArmorKeys(testing.MustInput(tk.file)) {

				records = append(records, &hkpstorage.Record{PrimaryKey: v, CTime: time.Now(), MTime: time.Now()})
			}
			return records, nil
		}),
		mock.PksInit(func(address string, time time.Time) error {
			for _, v := range statuses {
				if v.Addr == address {
					return errors.Errorf("Peer '%s' is already initialized", address)
				}
			}
			statuses = append(statuses, &storage.Status{Addr: address, LastSync: time})
			return nil
		}),
		mock.PksAll(func() ([]*storage.Status, error) {
			return statuses, nil
		}),
		mock.PksUpdate(func(status *storage.Status) error {
			for k, v := range statuses {
				if v.Addr == status.Addr {
					statuses[k] = status
					return nil
				}
			}
			return errors.Errorf("Peer '%s' is not initialized", status.Addr)
		}),
	)

	r := httprouter.New()
	policy, err := openpgp.NewPolicy()
	c.Assert(err, gc.IsNil)
	handler, err := hkp.NewHandler(s.storage, policy)
	c.Assert(err, gc.IsNil)
	s.handler = handler
	s.handler.Register(r)
	s.srv = httptest.NewServer(r)

	settings := &Settings{From: "test@example.com", To: []string{"hkp://" + s.srv.Listener.Addr().String()}, SMTP: SMTPConfig{Host: "localhost:25"}}
	sender, err := NewSender(s.storage, s.storage, settings, "hockeypuck/~unreleased")
	c.Assert(err, gc.IsNil)
	s.sender = sender
}

func (s *PksSuite) TearDownTest(c *gc.C) {
	s.srv.Close()
}

func (s *PksSuite) TestPks(c *gc.C) {
	statuses, err := s.sender.Status()
	c.Assert(err, gc.IsNil)
	c.Assert(len(statuses), gc.Equals, 1)
	err = s.sender.SendKeys(statuses[0])
	c.Assert(err, gc.IsNil)
}

// PksBookmarkSuite builds its own storage and sender rather than reusing
// PksSuite's: that fixture appends to a package-level status list on every
// SetUpTest, and TestPks asserts on its length.
type PksBookmarkSuite struct{}

var _ = gc.Suite(&PksBookmarkSuite{})

// TestBookmarkWaitsForTheWholeTimestamp: a keydump load stamps every row it
// writes with one timestamp, and the next query asks for mtime > LastSync. So
// the bookmark must not move within a group of records that share a timestamp:
// if a later one fails, everything else at that timestamp would be excluded from
// the retry and never sent. A tombstone makes this sharpest, because it advances
// the bookmark without anything having been sent.
func (s *PksBookmarkSuite) TestBookmarkWaitsForTheWholeTimestamp(c *gc.C) {
	// Sorted by (mtime, fingerprint), so the block is dealt with first.
	const blockFp = "00fe8cf1b483f7525039aa2a361bc1f023e0dcca"
	stamp := time.Now().UTC().Truncate(time.Second)
	start := stamp.AddDate(0, 0, -1)

	block, err := openpgp.NewTombstone(openpgp.Tombstone{Fingerprint: blockFp, Origin: "pgpkeys.eu"})
	c.Assert(err, gc.IsNil)
	keys := openpgp.MustReadArmorKeys(testing.MustInput(testKeyDefault.file))
	c.Assert(keys, gc.Not(gc.HasLen), 0)

	var updated []*storage.Status
	st := mock.NewStorage(
		mock.ModifiedSinceToFp(func(time.Time, time.Time) ([]string, time.Time, error) {
			return []string{blockFp, testKeyDefault.fp}, stamp, nil
		}),
		mock.FetchRecordsByFp(func([]string, ...string) ([]*hkpstorage.Record, error) {
			return []*hkpstorage.Record{
				{PrimaryKey: block, Fingerprint: blockFp, MTime: stamp},
				{PrimaryKey: keys[0], Fingerprint: testKeyDefault.fp, MTime: stamp},
			}, nil
		}),
		mock.PksUpdate(func(status *storage.Status) error {
			copied := *status
			updated = append(updated, &copied)
			return nil
		}),
	)
	// Nothing is listening there, so the ordinary key's send fails.
	settings := &Settings{From: "test@example.com", To: []string{"hkp://127.0.0.1:1"},
		SMTP: SMTPConfig{Host: "localhost:25"}}
	sender, err := NewSender(st, st, settings, "hockeypuck/~unreleased")
	c.Assert(err, gc.IsNil)

	err = sender.SendKeys(&storage.Status{Addr: settings.To[0], LastSync: start})
	c.Assert(err, gc.NotNil, gc.Commentf("the send was meant to fail"))

	c.Assert(updated, gc.Not(gc.HasLen), 0)
	for _, status := range updated {
		c.Check(status.LastSync.After(start), gc.Equals, false,
			gc.Commentf("the bookmark moved past a timestamp whose keys had not all been sent"))
	}
}

// TestBookmarkDefersTheTrailingTimestamp: the query caps its result and orders
// by mtime alone, so the records sharing the last timestamp in a batch may
// continue past the cap. Taking that group and moving the bookmark to its
// timestamp would leave the remainder behind a mtime > LastSync test for good,
// so the last timestamp is left for the next cycle.
func (s *PksBookmarkSuite) TestBookmarkDefersTheTrailingTimestamp(c *gc.C) {
	first := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	last := first.Add(time.Second)
	start := first.Add(-time.Hour)

	// All blocks, so nothing is sent and the test does not pay the send delay.
	// The bookmark logic is the same either way.
	var records []*hkpstorage.Record
	for i, spec := range []struct {
		fp    string
		mtime time.Time
	}{
		{"00fe8cf1b483f7525039aa2a361bc1f023e0dcca", first},
		{"11fe8cf1b483f7525039aa2a361bc1f023e0dcca", last},
		{"22fe8cf1b483f7525039aa2a361bc1f023e0dcca", last},
	} {
		block, err := openpgp.NewTombstone(openpgp.Tombstone{Fingerprint: spec.fp, Origin: "pgpkeys.eu"})
		c.Assert(err, gc.IsNil, gc.Commentf("record %d", i))
		records = append(records, &hkpstorage.Record{
			PrimaryKey: block, Fingerprint: spec.fp, MTime: spec.mtime})
	}

	var updated []*storage.Status
	st := mock.NewStorage(
		mock.ModifiedSinceToFp(func(time.Time, time.Time) ([]string, time.Time, error) {
			fps := []string{}
			for _, r := range records {
				fps = append(fps, r.Fingerprint)
			}
			return fps, last, nil
		}),
		mock.FetchRecordsByFp(func([]string, ...string) ([]*hkpstorage.Record, error) {
			return records, nil
		}),
		mock.PksUpdate(func(status *storage.Status) error {
			copied := *status
			updated = append(updated, &copied)
			return nil
		}),
	)
	settings := &Settings{From: "test@example.com", To: []string{"hkp://127.0.0.1:1"},
		SMTP: SMTPConfig{Host: "localhost:25"}}
	sender, err := NewSender(st, st, settings, "hockeypuck/~unreleased")
	c.Assert(err, gc.IsNil)

	c.Assert(sender.SendKeys(&storage.Status{Addr: settings.To[0], LastSync: start}), gc.IsNil)

	c.Assert(updated, gc.HasLen, 1)
	c.Check(updated[0].LastSync.Equal(first), gc.Equals, true,
		gc.Commentf("expected the bookmark to stop at %v, got %v", first, updated[0].LastSync))
}

// TestCompleteUpTo covers the shapes the batch can take, including the one the
// bookmark cannot defer: every record sharing a single timestamp, where
// deferring would stall the sender on that timestamp for good.
func (s *PksBookmarkSuite) TestCompleteUpTo(c *gc.C) {
	t0 := time.Now().UTC().Truncate(time.Second)
	at := func(offsets ...int) []*hkpstorage.Record {
		var records []*hkpstorage.Record
		for _, o := range offsets {
			records = append(records, &hkpstorage.Record{MTime: t0.Add(time.Duration(o) * time.Second)})
		}
		return records
	}
	for _, test := range []struct {
		name    string
		records []*hkpstorage.Record
		want    int
	}{
		{"empty", nil, 0},
		{"one record", at(0), 1},
		{"all one timestamp", at(0, 0, 0), 3},
		{"trailing group of one", at(0, 1), 1},
		{"trailing group of two", at(0, 0, 1, 1), 2},
		{"three groups", at(0, 1, 1, 2), 3},
	} {
		c.Check(completeUpTo(test.records), gc.Equals, test.want, gc.Commentf("%s", test.name))
	}
}
