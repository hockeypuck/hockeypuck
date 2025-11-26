/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Hockeypuck Contributors

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

package backend

import (
	"fmt"
)

// Constructor function signature for backend implementations
type Constructor func(interface{}) (interface{}, error)

var constructors = make(map[string]Constructor)

// Register registers a backend constructor
func Register(name string, constructor Constructor) {
	constructors[name] = constructor
}

// New creates a new backend instance based on configuration
func New(backendType string, config interface{}) (interface{}, error) {
	constructor, exists := constructors[backendType]
	if !exists {
		return nil, fmt.Errorf("unknown backend type: %s", backendType)
	}
	return constructor(config)
}
