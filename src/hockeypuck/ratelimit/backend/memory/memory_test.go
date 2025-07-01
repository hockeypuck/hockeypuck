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

package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"hockeypuck/ratelimit/types"
)

func TestNewBackend(t *testing.T) {
	config := types.MemoryBackendConfig{}
	backend, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create memory backend: %v", err)
	}
	if backend == nil {
		t.Fatal("Backend should not be nil")
	}

	// Test that it implements the Backend interface
	var _ types.Backend = backend
}

func TestConstructor(t *testing.T) {
	config := &types.BackendConfig{
		Type:   "memory",
		Memory: types.MemoryBackendConfig{},
	}

	backend, err := MemoryBackendConstructor(config)
	if err != nil {
		t.Fatalf("MemoryBackendConstructor failed: %v", err)
	}
	if backend == nil {
		t.Fatal("Backend should not be nil")
	}
}

func TestGetMetricsNonExistent(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
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
	backend, _ := New(types.MemoryBackendConfig{})
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

	// Verify data integrity
	if retrievedMetrics.Connections.Count != 5 {
		t.Errorf("Expected connection count=5, got %d", retrievedMetrics.Connections.Count)
	}
	if len(retrievedMetrics.Connections.Rate) != 2 {
		t.Errorf("Expected 2 rate entries, got %d", len(retrievedMetrics.Connections.Rate))
	}
	if len(retrievedMetrics.Requests.Requests) != 2 {
		t.Errorf("Expected 2 request entries, got %d", len(retrievedMetrics.Requests.Requests))
	}
	if len(retrievedMetrics.Requests.Errors) != 1 {
		t.Errorf("Expected 1 error entry, got %d", len(retrievedMetrics.Requests.Errors))
	}
}

func TestUpdateMetrics(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	ip := "203.0.113.1"

	// Update non-existent metrics
	err := backend.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Connections.Count = 1
		return metrics
	})
	if err != nil {
		t.Errorf("UpdateMetrics failed: %v", err)
	}

	// Verify update
	metrics, _ := backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}

	// Update existing metrics
	err = backend.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Connections.Count += 2
		return metrics
	})
	if err != nil {
		t.Errorf("UpdateMetrics failed: %v", err)
	}

	// Verify second update
	metrics, _ = backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count != 3 {
		t.Errorf("Expected connection count=3, got %d", metrics.Connections.Count)
	}
}

func TestIncrementConnections(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Increment connections
	err := backend.IncrementConnections(ctx, ip, now)
	if err != nil {
		t.Errorf("IncrementConnections failed: %v", err)
	}

	// Verify increment
	metrics, _ := backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}
	if len(metrics.Connections.Rate) != 1 {
		t.Errorf("Expected 1 rate entry, got %d", len(metrics.Connections.Rate))
	}

	// Increment again
	later := now.Add(time.Second)
	err = backend.IncrementConnections(ctx, ip, later)
	if err != nil {
		t.Errorf("Second IncrementConnections failed: %v", err)
	}

	metrics, _ = backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count != 2 {
		t.Errorf("Expected connection count=2, got %d", metrics.Connections.Count)
	}
	if len(metrics.Connections.Rate) != 2 {
		t.Errorf("Expected 2 rate entries, got %d", len(metrics.Connections.Rate))
	}
}

func TestDecrementConnections(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Set up initial connections
	backend.IncrementConnections(ctx, ip, now)
	backend.IncrementConnections(ctx, ip, now.Add(time.Second))

	// Decrement connections
	err := backend.DecrementConnections(ctx, ip)
	if err != nil {
		t.Errorf("DecrementConnections failed: %v", err)
	}

	// Verify decrement
	metrics, _ := backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}

	// Decrement to zero
	err = backend.DecrementConnections(ctx, ip)
	if err != nil {
		t.Errorf("Second DecrementConnections failed: %v", err)
	}

	metrics, _ = backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count != 0 {
		t.Errorf("Expected connection count=0, got %d", metrics.Connections.Count)
	}

	// Decrement below zero should not go negative
	err = backend.DecrementConnections(ctx, ip)
	if err != nil {
		t.Errorf("DecrementConnections below zero failed: %v", err)
	}

	metrics, _ = backend.GetMetrics(ctx, ip)
	if metrics.Connections.Count < 0 {
		t.Errorf("Connection count should not go below zero, got %d", metrics.Connections.Count)
	}
}

func TestAddRequest(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	err := backend.AddRequest(ctx, ip, now)
	if err != nil {
		t.Errorf("AddRequest failed: %v", err)
	}

	metrics, _ := backend.GetMetrics(ctx, ip)
	if len(metrics.Requests.Requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(metrics.Requests.Requests))
	}
	if !metrics.Requests.Requests[0].Equal(now) {
		t.Error("Request timestamp not preserved")
	}
}

func TestAddError(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	err := backend.AddError(ctx, ip, now)
	if err != nil {
		t.Errorf("AddError failed: %v", err)
	}

	metrics, _ := backend.GetMetrics(ctx, ip)
	if len(metrics.Requests.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(metrics.Requests.Errors))
	}
	if !metrics.Requests.Errors[0].Equal(now) {
		t.Error("Error timestamp not preserved")
	}
}

func TestBanOperations(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Test getting non-existent ban
	ban, err := backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan should not error for non-existent ban: %v", err)
	}
	if ban != nil {
		t.Error("GetBan should return nil for non-existent ban")
	}

	// Test setting ban
	banRecord := &types.BanRecord{
		BannedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		Reason:       "Test ban",
		IsTorExit:    true,
		OffenseCount: 2,
	}

	err = backend.SetBan(ctx, ip, banRecord)
	if err != nil {
		t.Errorf("SetBan failed: %v", err)
	}

	// Test getting ban
	retrievedBan, err := backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan failed: %v", err)
	}
	if retrievedBan == nil {
		t.Fatal("GetBan should return the ban")
	}
	if retrievedBan.Reason != "Test ban" {
		t.Errorf("Expected ban reason='Test ban', got '%s'", retrievedBan.Reason)
	}
	if !retrievedBan.IsTorExit {
		t.Error("Expected ban to be for Tor exit")
	}
	if retrievedBan.OffenseCount != 2 {
		t.Errorf("Expected offense count=2, got %d", retrievedBan.OffenseCount)
	}

	// Test removing ban
	err = backend.RemoveBan(ctx, ip)
	if err != nil {
		t.Errorf("RemoveBan failed: %v", err)
	}

	ban, err = backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan after removal failed: %v", err)
	}
	if ban != nil {
		t.Error("Ban should be removed")
	}
}

func TestGetAllBannedIPs(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	now := time.Now()

	// Test with no bans
	bannedIPs, err := backend.GetAllBannedIPs(ctx)
	if err != nil {
		t.Errorf("GetAllBannedIPs failed: %v", err)
	}
	if len(bannedIPs) != 0 {
		t.Errorf("Expected 0 banned IPs, got %d", len(bannedIPs))
	}

	// Add bans
	ban := &types.BanRecord{
		BannedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "Test ban",
	}

	backend.SetBan(ctx, "203.0.113.1", ban)
	backend.SetBan(ctx, "203.0.113.2", ban)

	bannedIPs, err = backend.GetAllBannedIPs(ctx)
	if err != nil {
		t.Errorf("GetAllBannedIPs failed: %v", err)
	}
	if len(bannedIPs) != 2 {
		t.Errorf("Expected 2 banned IPs, got %d", len(bannedIPs))
	}

	// Verify IPs are in result
	ipMap := make(map[string]bool)
	for _, ip := range bannedIPs {
		ipMap[ip] = true
	}
	if !ipMap["203.0.113.1"] || !ipMap["203.0.113.2"] {
		t.Error("Expected banned IPs not found in result")
	}
}

func TestGetStats(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	now := time.Now()

	// Test empty stats
	stats, err := backend.GetStats(ctx)
	if err != nil {
		t.Errorf("GetStats failed: %v", err)
	}
	if stats.TrackedIPs != 0 {
		t.Errorf("Expected 0 tracked IPs, got %d", stats.TrackedIPs)
	}
	if stats.BannedIPs != 0 {
		t.Errorf("Expected 0 banned IPs, got %d", stats.BannedIPs)
	}
	if stats.BackendType != "memory" {
		t.Errorf("Expected backend type=memory, got %s", stats.BackendType)
	}

	// Add some data
	backend.IncrementConnections(ctx, "203.0.113.1", now)
	backend.IncrementConnections(ctx, "203.0.113.2", now)

	ban := &types.BanRecord{
		BannedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Reason:    "Test ban",
		IsTorExit: true,
	}
	backend.SetBan(ctx, "203.0.113.1", ban)

	// Test stats with data
	stats, err = backend.GetStats(ctx)
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
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	now := time.Now()
	old := now.Add(-2 * time.Hour)

	// Add old and new data
	backend.IncrementConnections(ctx, "old-ip", old)
	backend.IncrementConnections(ctx, "new-ip", now)

	// Cleanup with threshold between old and new
	threshold := now.Add(-time.Hour)
	err := backend.Cleanup(ctx, threshold)
	if err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// Verify old data is removed
	metrics, _ := backend.GetMetrics(ctx, "old-ip")
	if metrics.Connections.Count > 0 {
		t.Error("Old IP should have been cleaned up")
	}

	// Verify new data is kept
	metrics, _ = backend.GetMetrics(ctx, "new-ip")
	if metrics.Connections.Count == 0 {
		t.Error("New IP should not have been cleaned up")
	}
}

func TestConcurrentAccess(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
	ctx := context.Background()
	now := time.Now()

	// Test concurrent access
	const numGoroutines = 10
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "203.0.113." + string(rune('1'+id))

			for j := 0; j < operationsPerGoroutine; j++ {
				backend.IncrementConnections(ctx, ip, now)
				backend.AddRequest(ctx, ip, now)
				if j%10 == 0 {
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
	if stats.TrackedIPs != numGoroutines {
		t.Errorf("Expected %d tracked IPs, got %d", numGoroutines, stats.TrackedIPs)
	}
}

func TestTorBackendOperations(t *testing.T) {
	backend, _ := New(types.MemoryBackendConfig{})
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
	backend, _ := New(types.MemoryBackendConfig{})

	err := backend.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Memory backend should handle multiple closes gracefully
	err = backend.Close()
	if err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}
