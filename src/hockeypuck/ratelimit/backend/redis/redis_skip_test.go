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

package redis

import (
	"testing"
	"time"

	"hockeypuck/ratelimit/types"
)

// TestRedisSkipBehavior demonstrates that Redis tests gracefully skip when Redis is not available
func TestRedisSkipBehavior(t *testing.T) {
	config := &types.BackendConfig{
		Type: "redis",
		Redis: types.RedisBackendConfig{
			Addr:      "nonexistent-redis-host:6379", // Invalid address that will fail
			Password:  "",
			DB:        0,
			PoolSize:  10,
			KeyPrefix: "test:",
			TTL:       24 * time.Hour,
		},
	}

	backend, err := New(config)
	if err != nil {
		t.Skipf("Redis not available, skipping test: %v", err)
		return
	}

	// If we somehow get here with an invalid address, that's unexpected
	if backend != nil {
		backend.Close()
		t.Error("Unexpectedly succeeded in connecting to nonexistent Redis host")
	}
}

// TestRedisConnectivityCheck demonstrates checking Redis connectivity before running tests
func TestRedisConnectivityCheck(t *testing.T) {
	// Test with invalid host - should skip gracefully
	invalidConfig := &types.BackendConfig{
		Type: "redis",
		Redis: types.RedisBackendConfig{
			Addr:      "invalid-host:9999",
			Password:  "",
			DB:        0,
			PoolSize:  1,
			KeyPrefix: "test:",
			TTL:       time.Hour,
		},
	}

	backend, err := New(invalidConfig)
	if err != nil {
		t.Logf("Expected: Redis connection failed with invalid host: %v", err)
		t.Skip("Redis connectivity test passed - correctly failed on invalid host")
		return
	}

	if backend != nil {
		backend.Close()
		t.Error("Should not have connected to invalid Redis host")
	}
}
