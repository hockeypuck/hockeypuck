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
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"hockeypuck/ratelimit/types"
)

// createTestBackend creates a Redis backend for testing, skipping if Redis is not available
func createTestBackend(t *testing.T) *Backend {
	config := &types.BackendConfig{
		Type: "redis",
		Redis: types.RedisBackendConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			KeyPrefix:    "hockeypuck:test:ratelimit:",
			TTL:          24 * time.Hour,
		},
	}

	backend, err := New(config)
	if err != nil {
		t.Skipf("Redis not available, skipping test: %v", err)
	}

	// Test Redis connectivity with a ping
	ctx := context.Background()
	pong, err := backend.client.Ping(ctx).Result()
	if err != nil {
		backend.Close()
		t.Skipf("Redis not reachable, skipping test: %v", err)
	}
	if pong != "PONG" {
		backend.Close()
		t.Skipf("Redis ping failed, expected PONG got %s", pong)
	}

	// Clean up test keys before each test
	pattern := config.Redis.KeyPrefix + "*"
	keys, err := backend.client.Keys(ctx, pattern).Result()
	if err == nil && len(keys) > 0 {
		backend.client.Del(ctx, keys...)
	}

	return backend
}

func TestNewBackend(t *testing.T) {
	config := &types.BackendConfig{
		Type: "redis",
		Redis: types.RedisBackendConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			KeyPrefix:    "hockeypuck:test:",
			TTL:          24 * time.Hour,
		},
	}

	backend, err := New(config)
	if err != nil {
		t.Skipf("Redis not available, skipping test: %v", err)
	}
	defer backend.Close()

	// Test Redis connectivity with a ping
	ctx := context.Background()
	pong, err := backend.client.Ping(ctx).Result()
	if err != nil {
		t.Skipf("Redis not reachable, skipping test: %v", err)
	}
	if pong != "PONG" {
		t.Skipf("Redis ping failed, expected PONG got %s", pong)
	}

	if backend == nil {
		t.Fatal("Backend should not be nil")
	}

	// Test that it implements the Backend interface
	var _ types.Backend = backend
}

func TestNewBackendInvalidConfig(t *testing.T) {
	// Test with nil config
	_, err := New(nil)
	if err == nil {
		t.Error("Expected error with nil config")
	}
	if err.Error() != "Backend configuration is required" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestConstructor(t *testing.T) {
	config := &types.BackendConfig{
		Type: "redis",
		Redis: types.RedisBackendConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			KeyPrefix:    "hockeypuck:test:",
			TTL:          24 * time.Hour,
		},
	}

	backend, err := RedisBackendConstructor(config)
	if err != nil {
		t.Skipf("Redis not available, skipping test: %v", err)
	}
	defer backend.Close()

	if backend == nil {
		t.Fatal("Backend should not be nil")
	}
}

func TestGetMetricsNonExistent(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()

	metrics, err := backend.GetMetrics(ctx, "203.0.113.1")
	if err != nil {
		t.Errorf("GetMetrics should not error for non-existent IP: %v", err)
	}
	if metrics == nil {
		t.Error("GetMetrics should return empty metrics, not nil")
	}
	if metrics.Connections.Count != 0 {
		t.Error("New metrics should have zero connection count")
	}
}

func TestSetAndGetMetrics(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Create test metrics
	originalMetrics := &types.IPMetrics{
		Connections: types.ConnectionTracker{
			Count:    5,
			Rate:     []time.Time{now, now.Add(-time.Second)},
			LastSeen: now,
		},
		Requests: types.RequestTracker{
			Requests: []time.Time{now, now.Add(-time.Minute)},
			Errors:   []time.Time{now.Add(-time.Hour)},
			LastSeen: now,
		},
	}

	// Set metrics
	err := backend.SetMetrics(ctx, ip, originalMetrics)
	if err != nil {
		t.Errorf("SetMetrics failed: %v", err)
	}

	// Get metrics back
	retrievedMetrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if retrievedMetrics.Connections.Count != originalMetrics.Connections.Count {
		t.Errorf("Expected connection count %d, got %d",
			originalMetrics.Connections.Count, retrievedMetrics.Connections.Count)
	}

	if len(retrievedMetrics.Requests.Requests) != len(originalMetrics.Requests.Requests) {
		t.Errorf("Expected %d requests, got %d",
			len(originalMetrics.Requests.Requests), len(retrievedMetrics.Requests.Requests))
	}
}

func TestIncrementConnections(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	err := backend.IncrementConnections(ctx, ip, now)
	if err != nil {
		t.Errorf("IncrementConnections failed: %v", err)
	}

	metrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count 1, got %d", metrics.Connections.Count)
	}

	// Increment again
	err = backend.IncrementConnections(ctx, ip, now)
	if err != nil {
		t.Errorf("IncrementConnections failed: %v", err)
	}

	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if metrics.Connections.Count != 2 {
		t.Errorf("Expected connection count 2, got %d", metrics.Connections.Count)
	}
}

func TestDecrementConnections(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Set initial count
	backend.IncrementConnections(ctx, ip, now)
	backend.IncrementConnections(ctx, ip, now)

	err := backend.DecrementConnections(ctx, ip)
	if err != nil {
		t.Errorf("DecrementConnections failed: %v", err)
	}

	metrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count 1, got %d", metrics.Connections.Count)
	}

	// Decrement to zero
	err = backend.DecrementConnections(ctx, ip)
	if err != nil {
		t.Errorf("DecrementConnections failed: %v", err)
	}

	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if metrics.Connections.Count != 0 {
		t.Errorf("Expected connection count 0, got %d", metrics.Connections.Count)
	}

	// Decrement below zero should not go negative
	err = backend.DecrementConnections(ctx, ip)
	if err != nil {
		t.Errorf("DecrementConnections failed: %v", err)
	}

	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if metrics.Connections.Count < 0 {
		t.Errorf("Connection count should not be negative, got %d", metrics.Connections.Count)
	}
}

func TestAddRequest(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	err := backend.AddRequest(ctx, ip, now)
	if err != nil {
		t.Errorf("AddRequest failed: %v", err)
	}

	metrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if len(metrics.Requests.Requests) != 1 {
		t.Errorf("Expected 1 request entry, got %d", len(metrics.Requests.Requests))
	}
}

func TestAddError(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	err := backend.AddError(ctx, ip, now)
	if err != nil {
		t.Errorf("AddError failed: %v", err)
	}

	metrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	if len(metrics.Requests.Errors) != 1 {
		t.Errorf("Expected 1 error entry, got %d", len(metrics.Requests.Errors))
	}
}

func TestBanOperations(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Test setting a ban
	banRecord := &types.BanRecord{
		Reason:       "test ban",
		BannedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		IsTorExit:    false,
		OffenseCount: 1,
	}

	err := backend.SetBan(ctx, ip, banRecord)
	if err != nil {
		t.Errorf("SetBan failed: %v", err)
	}

	// Test getting the ban
	retrievedBan, err := backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan failed: %v", err)
	}

	if retrievedBan == nil {
		t.Error("GetBan should return the ban record")
	}

	if retrievedBan.Reason != banRecord.Reason {
		t.Errorf("Expected ban reason '%s', got '%s'", banRecord.Reason, retrievedBan.Reason)
	}

	// Test removing the ban
	err = backend.RemoveBan(ctx, ip)
	if err != nil {
		t.Errorf("RemoveBan failed: %v", err)
	}

	// Verify ban is removed
	retrievedBan, err = backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan failed: %v", err)
	}

	if retrievedBan != nil {
		t.Error("GetBan should return nil after RemoveBan")
	}
}

func TestGetAllBannedIPs(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	now := time.Now()

	// Set multiple bans
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	for _, ip := range ips {
		banRecord := &types.BanRecord{
			Reason:    "test ban",
			BannedAt:  now,
			ExpiresAt: now.Add(time.Hour),
		}
		err := backend.SetBan(ctx, ip, banRecord)
		if err != nil {
			t.Errorf("SetBan failed for %s: %v", ip, err)
		}
	}

	// Get all banned IPs
	bannedIPs, err := backend.GetAllBannedIPs(ctx)
	if err != nil {
		t.Errorf("GetAllBannedIPs failed: %v", err)
	}

	if len(bannedIPs) != len(ips) {
		t.Errorf("Expected %d banned IPs, got %d", len(ips), len(bannedIPs))
	}

	// Verify all IPs are present
	bannedMap := make(map[string]bool)
	for _, ip := range bannedIPs {
		bannedMap[ip] = true
	}

	for _, ip := range ips {
		if !bannedMap[ip] {
			t.Errorf("IP %s should be in banned list", ip)
		}
	}
}

func TestGetStats(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()
	now := time.Now()

	// Create some test data
	ip1 := "203.0.113.1"
	ip2 := "203.0.113.2"

	// Add connections
	backend.IncrementConnections(ctx, ip1, now)
	backend.IncrementConnections(ctx, ip2, now)

	// Add a ban
	banRecord := &types.BanRecord{
		Reason:    "test ban",
		BannedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		IsTorExit: true,
	}
	backend.SetBan(ctx, ip1, banRecord)

	stats, err := backend.GetStats(ctx)
	if err != nil {
		t.Errorf("GetStats failed: %v", err)
	}

	if stats.TrackedIPs != 2 {
		t.Errorf("Expected 2 tracked IPs, got %d", stats.TrackedIPs)
	}

	if stats.BannedIPs != 1 {
		t.Errorf("Expected 1 banned IP, got %d", stats.BannedIPs)
	}

	if stats.TorBannedIPs != 1 {
		t.Errorf("Expected 1 Tor banned IP, got %d", stats.TorBannedIPs)
	}
}

func TestCleanup(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()

	// Add some old data
	oldTime := time.Now().Add(-48 * time.Hour)
	ip := "203.0.113.1"

	backend.AddRequest(ctx, ip, oldTime)

	// Run cleanup
	err := backend.Cleanup(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// Note: Redis backend cleanup is implemented via TTL, so old entries may still exist
	// until they expire naturally. This test verifies cleanup doesn't error.
}

func TestConcurrentAccess(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()

	numGoroutines := 10
	numOperations := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Run concurrent operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("203.0.113.%d", id+1)
			now := time.Now()

			for j := 0; j < numOperations; j++ {
				// Mix of operations
				backend.IncrementConnections(ctx, ip, now)
				backend.AddRequest(ctx, ip, now)
				if j%2 == 0 {
					backend.AddError(ctx, ip, now)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	stats, err := backend.GetStats(ctx)
	if err != nil {
		t.Errorf("GetStats failed after concurrent access: %v", err)
	}

	// Should have tracked all IPs
	if stats.TrackedIPs != numGoroutines {
		t.Errorf("Expected %d tracked IPs, got %d", numGoroutines, stats.TrackedIPs)
	}
}

func TestTorBackendOperations(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()
	ctx := context.Background()

	// Test storing Tor exits
	exits := map[string]bool{
		"203.0.113.1": true,
		"203.0.113.2": true,
		"203.0.113.3": false, // This should not be stored
	}

	err := backend.StoreTorExits(ctx, exits)
	if err != nil {
		t.Errorf("StoreTorExits failed: %v", err)
	}

	// Test loading Tor exits
	loadedExits, err := backend.LoadTorExits(ctx)
	if err != nil {
		t.Errorf("LoadTorExits failed: %v", err)
	}

	// Should only contain true exits
	expectedCount := 2
	if len(loadedExits) != expectedCount {
		t.Errorf("Expected %d exits, got %d", expectedCount, len(loadedExits))
	}

	// Test individual exit checks
	isTor, err := backend.IsTorExit(ctx, "203.0.113.1")
	if err != nil {
		t.Errorf("IsTorExit failed: %v", err)
	}
	if !isTor {
		t.Error("203.0.113.1 should be identified as Tor exit")
	}

	isTor, err = backend.IsTorExit(ctx, "203.0.113.3")
	if err != nil {
		t.Errorf("IsTorExit failed: %v", err)
	}
	if isTor {
		t.Error("203.0.113.3 should not be identified as Tor exit")
	}

	// Test Tor stats
	torStats, err := backend.GetTorStats(ctx)
	if err != nil {
		t.Errorf("GetTorStats failed: %v", err)
	}
	if torStats.Count != expectedCount {
		t.Errorf("Expected Tor count=%d, got %d", expectedCount, torStats.Count)
	}
}

func TestClose(t *testing.T) {
	backend := createTestBackend(t)

	err := backend.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestKeyGeneration(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	// Test key generation methods
	ip := "203.0.113.1"
	prefix := backend.keyPrefix

	expectedKeys := map[string]string{
		"ip":          prefix + "ip:" + ip,
		"ban":         prefix + "ban:" + ip,
		"connections": prefix + "conn:" + ip,
		"requests":    prefix + "req:" + ip,
		"errors":      prefix + "err:" + ip,
		"allBans":     prefix + "bans",
		"torExit":     prefix + "tor:exits",
		"torStats":    prefix + "tor:stats",
	}

	actualKeys := map[string]string{
		"ip":          backend.ipKey(ip),
		"ban":         backend.banKey(ip),
		"connections": backend.connectionsKey(ip),
		"requests":    backend.requestsKey(ip),
		"errors":      backend.errorsKey(ip),
		"allBans":     backend.allBansKey(),
		"torExit":     backend.torExitKey(),
		"torStats":    backend.torStatsKey(),
	}

	for keyType, expected := range expectedKeys {
		if actual := actualKeys[keyType]; actual != expected {
			t.Errorf("Key type %s: expected %s, got %s", keyType, expected, actual)
		}
	}
}
