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

package ratelimit

import (
	"hockeypuck/ratelimit/types"
)

// Type aliases for configuration types
type Config = types.Config
type BackendConfig = types.BackendConfig
type TorConfig = types.TorConfig
type WhitelistConfig = types.WhitelistConfig
type KeyserverSyncConfig = types.KeyserverSyncConfig
type HeaderConfig = types.HeaderConfig
type MemoryBackendConfig = types.MemoryBackendConfig
type RedisBackendConfig = types.RedisBackendConfig
type PartnerProvider = types.PartnerProvider

// DefaultConfig returns the default rate limiting configuration
func DefaultConfig() Config {
	return types.DefaultConfig()
}

// DefaultBackendConfig returns the default backend configuration
func DefaultBackendConfig() BackendConfig {
	return types.DefaultBackendConfig()
}
