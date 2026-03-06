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
		mock.ModifiedSinceToFp(func(time.Time) ([]string, error) {
			tk := testKeyDefault
			return []string{tk.fp}, nil
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
