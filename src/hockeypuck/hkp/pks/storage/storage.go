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

package storage

import "time"

// Status of PKS synchronization
type Status struct {
	// Address of the PKS server.
	Addr string
	// Timestamp of the last sync to this server.
	LastSync time.Time
	// Error message of last sync failure.
	LastError error
	// Flags to denote the running state (not used by the storage layer).
	Permanent  bool // Set from the config file
	Historical bool // In the DB but not the running state
}

type PKSStatuses []*Status

func (s PKSStatuses) Len() int           { return len(s) }
func (s PKSStatuses) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s PKSStatuses) Less(i, j int) bool { return s[i].Addr < s[j].Addr }

// Storage implements a simple interface to persist the status of multiple PKS peers.
// All methods are prefixed by `PKS` so that a concrete storage class can implement multiple Storage interfaces.
// NB: PKSInit() MUST be called with lastSync == time.Now() to prevent an update storm on startup.
type Storage interface {
	PKSInit(addr string, lastSync time.Time) error // Initialise a new PKS peer
	PKSAll() ([]*Status, error)                    // Return the status of all PKS peers
	PKSUpdate(status *Status) error                // Update the status of one PKS peer
	PKSRemove(addr string) error                   // Remove one PKS peer
	PKSGet(addr string) (*Status, error)           // Return the status of one PKS peer
}
