/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  Casey Marshall and the Hockeypuck Contributors

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

package pghkp

import (
	pksstorage "hockeypuck/hkp/pks/storage"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	gc "gopkg.in/check.v1"
)

func (s *S) TestPKS(c *gc.C) {
	log.Infof("starting TestPKS")
	testAddr := "mailto:test@example.com"
	now := time.Now()
	testError := errors.Errorf("unknown error")
	testStatus := pksstorage.Status{Addr: testAddr, LastSync: now, LastError: testError}

	err := s.storage.PKSInit(testAddr, now)
	c.Assert(err, gc.IsNil, gc.Commentf("PKSInit"))
	statuses, err := s.storage.PKSAll()
	comment := gc.Commentf("PKSInit")
	c.Assert(err, gc.IsNil, comment)
	c.Assert(statuses, gc.HasLen, 1, comment)
	status := statuses[0]
	c.Assert(status.Addr, gc.Equals, testAddr, comment)
	c.Assert(status.LastSync.UTC().Add(time.Microsecond).After(now), gc.Equals, true, comment)
	c.Assert(status.LastError, gc.IsNil, comment)

	// PKSUpdate should populate LastError
	err = s.storage.PKSUpdate(&testStatus)
	c.Assert(err, gc.IsNil, gc.Commentf("PKSUpdate"))
	status, err = s.storage.PKSGet(testAddr)
	comment = gc.Commentf("PKSGet %s first time", testAddr)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(status.LastError, gc.NotNil, comment)
	c.Assert(status.LastError.Error(), gc.Equals, testError.Error(), comment)

	// PKSInit should not update
	next := now.Add(time.Second)
	err = s.storage.PKSInit(testAddr, next)
	c.Assert(err, gc.IsNil, gc.Commentf("PKSInit again"))
	status, err = s.storage.PKSGet(testAddr)
	comment = gc.Commentf("PKSGet %s second time", testAddr)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(status.LastSync.UTC().Before(next), gc.Equals, true, comment)
	c.Assert(status.LastError, gc.NotNil, comment)
	c.Assert(status.LastError.Error(), gc.Equals, testError.Error(), comment)

	testStatus2 := pksstorage.Status{Addr: testAddr, LastSync: next, LastError: nil}
	err = s.storage.PKSUpdate(&testStatus2)
	c.Assert(err, gc.IsNil, gc.Commentf("PKSUpdate again"))
	status, err = s.storage.PKSGet(testAddr)
	comment = gc.Commentf("PKSGet %s third time", testAddr)
	c.Assert(err, gc.IsNil, comment)
	c.Assert(status.Addr, gc.Equals, testAddr, comment)
	c.Assert(status.LastSync.UTC().Add(time.Microsecond).After(next), gc.Equals, true, comment)
	c.Assert(status.LastError, gc.IsNil, comment)

	err = s.storage.PKSRemove(testAddr)
	c.Assert(err, gc.IsNil, gc.Commentf("PKSRemove"))
	statuses, err = s.storage.PKSAll()
	c.Assert(err, gc.IsNil, gc.Commentf("PKSAll final"))
	c.Assert(statuses, gc.HasLen, 0)
}
