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

package types

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Test basic configuration
	if !config.Enabled {
		t.Error("Expected Enabled to be true by default")
	}
	if config.MaxConcurrentConnections != 80 {
		t.Errorf("Expected MaxConcurrentConnections=80, got %d", config.MaxConcurrentConnections)
	}
	if config.ConnectionRate != 40 {
		t.Errorf("Expected ConnectionRate=40, got %d", config.ConnectionRate)
	}
	if config.HTTPRequestRate != 100 {
		t.Errorf("Expected HTTPRequestRate=100, got %d", config.HTTPRequestRate)
	}
	if config.HTTPErrorRate != 20 {
		t.Errorf("Expected HTTPErrorRate=20, got %d", config.HTTPErrorRate)
	}
	if config.CrawlerBlockDuration != 24*time.Hour {
		t.Errorf("Expected CrawlerBlockDuration=24h, got %v", config.CrawlerBlockDuration)
	}

	// Test Tor configuration
	if !config.Tor.Enabled {
		t.Error("Expected Tor.Enabled to be true by default")
	}
	if config.Tor.MaxRequestsPerConnection != 2 {
		t.Errorf("Expected Tor.MaxRequestsPerConnection=2, got %d", config.Tor.MaxRequestsPerConnection)
	}
	if config.Tor.MaxConcurrentConnections != 1 {
		t.Errorf("Expected Tor.MaxConcurrentConnections=1, got %d", config.Tor.MaxConcurrentConnections)
	}
	if config.Tor.ConnectionRate != 1 {
		t.Errorf("Expected Tor.ConnectionRate=1, got %d", config.Tor.ConnectionRate)
	}
	if config.Tor.ConnectionRateWindow != 10*time.Second {
		t.Errorf("Expected Tor.ConnectionRateWindow=10s, got %v", config.Tor.ConnectionRateWindow)
	}
	if config.Tor.BanDuration != 24*time.Hour {
		t.Errorf("Expected Tor.BanDuration=24h, got %v", config.Tor.BanDuration)
	}

	// Test whitelist configuration
	if len(config.Whitelist.IPs) == 0 {
		t.Error("Expected default whitelist to contain IPs")
	}

	// Check for localhost in whitelist
	found := false
	for _, ip := range config.Whitelist.IPs {
		if ip == "127.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected localhost (127.0.0.1) to be in default whitelist")
	}

	// Test headers configuration
	if !config.Headers.Enabled {
		t.Error("Expected Headers.Enabled to be true by default")
	}
	if config.Headers.TorHeader != "X-Tor-Exit" {
		t.Errorf("Expected TorHeader=X-Tor-Exit, got %s", config.Headers.TorHeader)
	}
	if config.Headers.BanHeader != "X-RateLimit-Ban" {
		t.Errorf("Expected BanHeader=X-RateLimit-Ban, got %s", config.Headers.BanHeader)
	}
}

func TestDefaultBackendConfig(t *testing.T) {
	config := DefaultBackendConfig()

	if config.Type != "memory" {
		t.Errorf("Expected default backend type=memory, got %s", config.Type)
	}

	// Test Redis defaults
	if config.Redis.Addr != "localhost:6379" {
		t.Errorf("Expected Redis.Addr=localhost:6379, got %s", config.Redis.Addr)
	}
	if config.Redis.DB != 0 {
		t.Errorf("Expected Redis.DB=0, got %d", config.Redis.DB)
	}
	if config.Redis.PoolSize != 10 {
		t.Errorf("Expected Redis.PoolSize=10, got %d", config.Redis.PoolSize)
	}
	if config.Redis.DialTimeout != 5*time.Second {
		t.Errorf("Expected Redis.DialTimeout=5s, got %v", config.Redis.DialTimeout)
	}
	if config.Redis.KeyPrefix != "hockeypuck:ratelimit:" {
		t.Errorf("Expected Redis.KeyPrefix=hockeypuck:ratelimit:, got %s", config.Redis.KeyPrefix)
	}
	if config.Redis.TTL != 24*time.Hour {
		t.Errorf("Expected Redis.TTL=24h, got %v", config.Redis.TTL)
	}
}

func TestBackendRegistration(t *testing.T) {
	// Test that registration functions return the constructor
	testConstructor := func(*BackendConfig) (Backend, error) {
		return nil, nil
	}

	// Test memory backend registration
	returned := RegisterMemoryBackend(testConstructor)
	if returned == nil {
		t.Error("RegisterMemoryBackend should return the constructor")
	}

	// Test redis backend registration
	returned = RegisterRedisBackend(testConstructor)
	if returned == nil {
		t.Error("RegisterRedisBackend should return the constructor")
	}
}

func TestNewBackendWithoutRegistration(t *testing.T) {
	// Reset constructors
	memoryBackendConstructor = nil
	redisBackendConstructor = nil

	config := &BackendConfig{Type: "memory"}
	_, err := NewBackend(config)
	if err == nil {
		t.Error("Expected error when memory backend not registered")
	}
	if err != nil && err.Error() != `memory backend not registered - import _ "hockeypuck/ratelimit/backend/memory"` {
		t.Errorf("Unexpected error message: %v", err)
	}

	config = &BackendConfig{Type: "redis"}
	_, err = NewBackend(config)
	if err == nil {
		t.Error("Expected error when redis backend not registered")
	}
	if err != nil && err.Error() != `redis backend not registered - import _ "hockeypuck/ratelimit/backend/redis"` {
		t.Errorf("Unexpected error message: %v", err)
	}

	config = &BackendConfig{Type: "unknown"}
	_, err = NewBackend(config)
	if err == nil {
		t.Error("Expected error for unknown backend type")
	}
	if err != nil && err.Error() != "unknown backend type: unknown" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestIPMetricsStructure(t *testing.T) {
	metrics := &IPMetrics{}

	// Test that metrics can be initialized with zero values
	if metrics.Connections.Count != 0 {
		t.Error("Expected zero connection count")
	}
	if len(metrics.Connections.Rate) != 0 {
		t.Error("Expected empty connection rate slice")
	}
	if len(metrics.Requests.Requests) != 0 {
		t.Error("Expected empty requests slice")
	}
	if len(metrics.Requests.Errors) != 0 {
		t.Error("Expected empty errors slice")
	}
	if metrics.Ban != nil {
		t.Error("Expected nil ban record")
	}
}

func TestBanRecord(t *testing.T) {
	now := time.Now()
	ban := &BanRecord{
		BannedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		Reason:       "Test ban",
		IsTorExit:    true,
		OffenseCount: 2,
	}

	if ban.BannedAt != now {
		t.Error("BannedAt timestamp not preserved")
	}
	if ban.ExpiresAt != now.Add(time.Hour) {
		t.Error("ExpiresAt timestamp not preserved")
	}
	if ban.Reason != "Test ban" {
		t.Error("Ban reason not preserved")
	}
	if !ban.IsTorExit {
		t.Error("IsTorExit flag not preserved")
	}
	if ban.OffenseCount != 2 {
		t.Error("OffenseCount not preserved")
	}
}

func TestBackendStats(t *testing.T) {
	stats := BackendStats{
		TrackedIPs:   100,
		BannedIPs:    5,
		TorBannedIPs: 2,
		BackendType:  "memory",
		BackendInfo:  map[string]interface{}{"test": "value"},
	}

	if stats.TrackedIPs != 100 {
		t.Error("TrackedIPs not preserved")
	}
	if stats.BannedIPs != 5 {
		t.Error("BannedIPs not preserved")
	}
	if stats.TorBannedIPs != 2 {
		t.Error("TorBannedIPs not preserved")
	}
	if stats.BackendType != "memory" {
		t.Error("BackendType not preserved")
	}
	if stats.BackendInfo["test"] != "value" {
		t.Error("BackendInfo not preserved")
	}
}

func TestTorStats(t *testing.T) {
	now := time.Now()
	stats := TorStats{
		Count:       1000,
		LastUpdated: now,
		TTL:         time.Hour,
	}

	if stats.Count != 1000 {
		t.Error("Count not preserved")
	}
	if stats.LastUpdated != now {
		t.Error("LastUpdated not preserved")
	}
	if stats.TTL != time.Hour {
		t.Error("TTL not preserved")
	}
}

func TestConnectionTracker(t *testing.T) {
	now := time.Now()
	tracker := ConnectionTracker{
		Count:    5,
		Rate:     []time.Time{now, now.Add(-time.Second)},
		LastSeen: now,
	}

	if tracker.Count != 5 {
		t.Error("Connection count not preserved")
	}
	if len(tracker.Rate) != 2 {
		t.Error("Rate slice length not preserved")
	}
	if tracker.LastSeen != now {
		t.Error("LastSeen not preserved")
	}
}

func TestRequestTracker(t *testing.T) {
	now := time.Now()
	tracker := RequestTracker{
		Requests: []time.Time{now, now.Add(-time.Second)},
		Errors:   []time.Time{now.Add(-2 * time.Second)},
		LastSeen: now,
	}

	if len(tracker.Requests) != 2 {
		t.Error("Requests slice length not preserved")
	}
	if len(tracker.Errors) != 1 {
		t.Error("Errors slice length not preserved")
	}
	if tracker.LastSeen != now {
		t.Error("LastSeen not preserved")
	}
}
