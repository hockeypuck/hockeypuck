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

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	// Check default values
	if !config.Enabled {
		t.Error("Rate limiting should be enabled by default")
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

	// Check backend config
	if config.Backend.Type != "memory" {
		t.Errorf("Expected default backend type=memory, got %s", config.Backend.Type)
	}

	// Check Tor config
	if !config.Tor.Enabled {
		t.Error("Tor rate limiting should be enabled by default")
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

	// Check whitelist contains localhost
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
}

func TestMemoryBackend(t *testing.T) {
	backend, err := NewMemoryBackend(&MemoryBackendConfig{})
	if err != nil {
		t.Fatalf("Failed to create memory backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	ip := "203.0.113.1"
	now := time.Now()

	// Test getting non-existent metrics
	metrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics should not error for non-existent IP: %v", err)
	}
	if metrics == nil {
		t.Error("GetMetrics should return empty metrics, not nil")
	}

	// Test incrementing connections
	err = backend.IncrementConnections(ctx, ip, now)
	if err != nil {
		t.Errorf("IncrementConnections failed: %v", err)
	}

	// Test adding request
	err = backend.AddRequest(ctx, ip, now)
	if err != nil {
		t.Errorf("AddRequest failed: %v", err)
	}

	// Test getting updated metrics
	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}
	if len(metrics.Requests.Requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(metrics.Requests.Requests))
	}

	// Test ban operations
	ban := &BanRecord{
		BannedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		Reason:       "Test ban",
		IsTorExit:    false,
		OffenseCount: 1,
	}

	err = backend.SetBan(ctx, ip, ban)
	if err != nil {
		t.Errorf("SetBan failed: %v", err)
	}

	retrievedBan, err := backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan failed: %v", err)
	}
	if retrievedBan == nil {
		t.Error("GetBan should return the ban")
	} else {
		if retrievedBan.Reason != "Test ban" {
			t.Errorf("Expected ban reason='Test ban', got '%s'", retrievedBan.Reason)
		}
	}

	// Test stats
	stats, err := backend.GetStats(ctx)
	if err != nil {
		t.Errorf("GetStats failed: %v", err)
	}
	if stats.TrackedIPs != 1 {
		t.Errorf("Expected tracked IPs=1, got %d", stats.TrackedIPs)
	}
	if stats.BannedIPs != 1 {
		t.Errorf("Expected banned IPs=1, got %d", stats.BannedIPs)
	}
	if stats.BackendType != "memory" {
		t.Errorf("Expected backend type=memory, got %s", stats.BackendType)
	}
}

func TestRateLimiterWhitelist(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test localhost is whitelisted
	if !rl.isWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should be whitelisted")
	}

	// Test private IP is whitelisted
	if !rl.isWhitelisted("192.168.1.1") {
		t.Error("192.168.1.1 should be whitelisted")
	}

	// Test public IP is not whitelisted
	if rl.isWhitelisted("8.8.8.8") {
		t.Error("8.8.8.8 should not be whitelisted")
	}
}

func TestRateLimiterIPExtraction(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test direct IP extraction
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	ip := rl.extractClientIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("Expected IP 203.0.113.1, got %s", ip)
	}

	// Test X-Forwarded-For when trust proxy headers is enabled
	rl.config.TrustProxyHeaders = true
	req.Header.Set("X-Forwarded-For", "203.0.113.2, 203.0.113.3")
	ip = rl.extractClientIP(req)
	if ip != "203.0.113.2" {
		t.Errorf("Expected IP 203.0.113.2 from X-Forwarded-For, got %s", ip)
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.MaxConcurrentConnections = 1
	config.ConnectionRate = 1
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(handler)

	// Test whitelisted IP passes through
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Whitelisted IP should pass through, got status %d", rr.Code)
	}

	// Test rate limiting for non-whitelisted IP
	req.RemoteAddr = "203.0.113.1:12345"

	// First request should succeed
	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("First request should succeed, got status %d", rr.Code)
	}

	// Second request should be rate limited
	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Second request should be rate limited, got status %d", rr.Code)
	}
}

func TestTorExitNodeDetection(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Manually add a test Tor exit
	rl.mu.Lock()
	rl.torExits["203.0.113.1"] = true
	rl.mu.Unlock()

	// Test detection
	if !rl.isTorExit("203.0.113.1") {
		t.Error("203.0.113.1 should be detected as Tor exit")
	}

	if rl.isTorExit("203.0.113.2") {
		t.Error("203.0.113.2 should not be detected as Tor exit")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Enabled = false
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(handler)

	// Test that disabled rate limiter passes all requests
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"

	// Multiple rapid requests should all succeed when disabled
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d should succeed when rate limiting disabled, got status %d", i, rr.Code)
		}
	}
}

func TestBanEscalation(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Backend.Type = "memory"
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	ctx := context.Background()
	ip := "203.0.113.1"

	// First ban
	rl.banIP(ip, "test violation", true)

	firstBan, err := rl.backend.GetBan(ctx, ip)
	if err != nil {
		t.Fatalf("Failed to get first ban: %v", err)
	}
	if firstBan == nil {
		t.Fatal("First ban should exist")
	}
	if firstBan.OffenseCount != 1 {
		t.Errorf("Expected OffenseCount=1, got %d", firstBan.OffenseCount)
	}

	// Wait a bit to ensure different timestamps
	time.Sleep(10 * time.Millisecond)

	// Second ban (repeat offender)
	rl.banIP(ip, "test violation", true)

	secondBan, err := rl.backend.GetBan(ctx, ip)
	if err != nil {
		t.Fatalf("Failed to get second ban: %v", err)
	}
	if secondBan == nil {
		t.Fatal("Second ban should exist")
	}
	if secondBan.OffenseCount != 2 {
		t.Errorf("Expected OffenseCount=2, got %d", secondBan.OffenseCount)
	}

	// Repeat offender should have longer ban
	if secondBan.ExpiresAt.Sub(secondBan.BannedAt) <= firstBan.ExpiresAt.Sub(firstBan.BannedAt) {
		t.Error("Repeat offender should have longer ban duration")
	}
}

func TestRateLimitStats(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Backend.Type = "memory"
	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Add some test data
	ip := "203.0.113.1"

	// Create some activity and then ban the IP
	ctx := context.Background()
	now := time.Now()
	rl.backend.IncrementConnections(ctx, ip, now)
	rl.banIP(ip, "test ban", false)

	// Get stats
	stats := rl.GetRateLimitStats()

	if !stats["enabled"].(bool) {
		t.Error("Expected enabled=true in stats")
	}

	if stats["tracked_ips"].(int) != 1 {
		t.Errorf("Expected tracked_ips=1, got %v", stats["tracked_ips"])
	}

	if stats["banned_ips"].(int) != 1 {
		t.Errorf("Expected banned_ips=1, got %v", stats["banned_ips"])
	}
}

func TestRateLimiterWithMemoryBackend(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.MaxConcurrentConnections = 2
	config.ConnectionRate = 3
	config.HTTPRequestRate = 5
	config.Backend.Type = "memory"

	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test whitelisted IP passes through
	if !rl.isWhitelisted("127.0.0.1") {
		t.Error("127.0.0.1 should be whitelisted")
	}

	// Test rate limiting for non-whitelisted IP
	ip := "203.0.113.1"

	// First request should succeed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip + ":12345"

	violated, reason := rl.checkRateLimits(ip, req)
	if violated {
		t.Errorf("First request should not be rate limited: %s", reason)
	}

	// Track the request
	rl.trackRequest(ip, req)

	// Get metrics to verify tracking
	ctx := context.Background()
	metrics, err := rl.backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("Failed to get metrics: %v", err)
	}
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}
}

func TestBackendConfiguration(t *testing.T) {
	// Test memory backend creation
	memoryConfig := MetricsBackendConfig{
		Type:   "memory",
		Memory: &MemoryBackendConfig{},
	}

	backend, err := NewMetricsBackend(memoryConfig)
	if err != nil {
		t.Errorf("Failed to create memory backend: %v", err)
	}
	if backend == nil {
		t.Error("Memory backend should not be nil")
	}
	backend.Close()

	// Test invalid backend type
	invalidConfig := MetricsBackendConfig{
		Type: "invalid",
	}

	_, err = NewMetricsBackend(invalidConfig)
	if err == nil {
		t.Error("Should return error for invalid backend type")
	}
}

func TestTorExitDetection(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Backend.Type = "memory"

	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Manually add a test Tor exit
	rl.mu.Lock()
	rl.torExits["203.0.113.1"] = true
	rl.mu.Unlock()

	// Test detection
	if !rl.isTorExit("203.0.113.1") {
		t.Error("203.0.113.1 should be detected as Tor exit")
	}

	if rl.isTorExit("203.0.113.2") {
		t.Error("203.0.113.2 should not be detected as Tor exit")
	}
}

func TestRedisBackend(t *testing.T) {
	// Skip test if Redis is not available
	config := DefaultMetricsBackendConfig().Redis
	backend, err := NewRedisBackend(config)
	if err != nil {
		t.Skipf("Redis not available, skipping Redis backend tests: %v", err)
		return
	}
	defer backend.Close()

	ctx := context.Background()
	ip := "203.0.113.100"
	now := time.Now()

	// Test getting non-existent metrics
	metrics, err := backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics should not error for non-existent IP: %v", err)
	}
	if metrics == nil {
		t.Error("GetMetrics should return empty metrics, not nil")
	}

	// Test incrementing connections
	err = backend.IncrementConnections(ctx, ip, now)
	if err != nil {
		t.Errorf("IncrementConnections failed: %v", err)
	}

	// Test adding request
	err = backend.AddRequest(ctx, ip, now)
	if err != nil {
		t.Errorf("AddRequest failed: %v", err)
	}

	// Test adding error
	err = backend.AddError(ctx, ip, now)
	if err != nil {
		t.Errorf("AddError failed: %v", err)
	}

	// Test getting updated metrics
	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}
	if len(metrics.Requests.Requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(metrics.Requests.Requests))
	}
	if len(metrics.Requests.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(metrics.Requests.Errors))
	}

	// Test ban operations
	ban := &BanRecord{
		BannedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		Reason:       "Redis test ban",
		IsTorExit:    true,
		OffenseCount: 2,
	}

	err = backend.SetBan(ctx, ip, ban)
	if err != nil {
		t.Errorf("SetBan failed: %v", err)
	}

	retrievedBan, err := backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan failed: %v", err)
	}
	if retrievedBan == nil {
		t.Error("GetBan should return the ban")
	} else {
		if retrievedBan.Reason != "Redis test ban" {
			t.Errorf("Expected ban reason='Redis test ban', got '%s'", retrievedBan.Reason)
		}
		if !retrievedBan.IsTorExit {
			t.Error("Expected ban to be for Tor exit")
		}
		if retrievedBan.OffenseCount != 2 {
			t.Errorf("Expected offense count=2, got %d", retrievedBan.OffenseCount)
		}
	}

	// Test getting all banned IPs
	bannedIPs, err := backend.GetAllBannedIPs(ctx)
	if err != nil {
		t.Errorf("GetAllBannedIPs failed: %v", err)
	}
	if len(bannedIPs) != 1 {
		t.Errorf("Expected 1 banned IP, got %d", len(bannedIPs))
	}
	if len(bannedIPs) > 0 && bannedIPs[0] != ip {
		t.Errorf("Expected banned IP=%s, got %s", ip, bannedIPs[0])
	}

	// Test stats
	stats, err := backend.GetStats(ctx)
	if err != nil {
		t.Errorf("GetStats failed: %v", err)
	}
	if stats.TrackedIPs < 1 {
		t.Errorf("Expected at least 1 tracked IP, got %d", stats.TrackedIPs)
	}
	if stats.BannedIPs != 1 {
		t.Errorf("Expected 1 banned IP, got %d", stats.BannedIPs)
	}
	if stats.TorBannedIPs != 1 {
		t.Errorf("Expected 1 Tor banned IP, got %d", stats.TorBannedIPs)
	}
	if stats.BackendType != "redis" {
		t.Errorf("Expected backend type=redis, got %s", stats.BackendType)
	}

	// Test removing ban
	err = backend.RemoveBan(ctx, ip)
	if err != nil {
		t.Errorf("RemoveBan failed: %v", err)
	}

	retrievedBan, err = backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("GetBan after removal failed: %v", err)
	}
	if retrievedBan != nil {
		t.Error("Ban should be removed")
	}

	// Test cleanup
	staleThreshold := now.Add(time.Hour)
	err = backend.Cleanup(ctx, staleThreshold)
	if err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

func TestRateLimiterWithRedisBackend(t *testing.T) {
	// Skip test if Redis is not available
	config := DefaultRateLimitConfig()
	config.Backend.Type = "redis"
	config.MaxConcurrentConnections = 2
	config.ConnectionRate = 3
	config.HTTPRequestRate = 5

	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Skipf("Redis not available, skipping Redis rate limiter tests: %v", err)
		return
	}
	defer rl.Stop()

	// Test rate limiting with Redis backend
	ip := "203.0.113.200"

	// First request should succeed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip + ":12345"

	violated, reason := rl.checkRateLimits(ip, req)
	if violated {
		t.Errorf("First request should not be rate limited: %s", reason)
	}

	// Track the request
	rl.trackRequest(ip, req)

	// Get metrics to verify tracking through Redis
	ctx := context.Background()
	metrics, err := rl.backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("Failed to get metrics from Redis: %v", err)
	}
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}

	// Test ban through Redis
	rl.banIP(ip, "Redis integration test", false)

	ban, err := rl.backend.GetBan(ctx, ip)
	if err != nil {
		t.Errorf("Failed to get ban from Redis: %v", err)
	}
	if ban == nil {
		t.Error("Ban should exist in Redis")
	} else if ban.Reason != "Redis integration test" {
		t.Errorf("Expected ban reason='Redis integration test', got '%s'", ban.Reason)
	}
}

func TestBackendSwitching(t *testing.T) {
	// Test creating rate limiter with memory backend
	memoryConfig := DefaultRateLimitConfig()
	memoryConfig.Backend.Type = "memory"

	rlMemory, err := NewRateLimiter(&memoryConfig)
	if err != nil {
		t.Fatalf("Failed to create memory rate limiter: %v", err)
	}
	defer rlMemory.Stop()

	// Verify it's using memory backend
	stats := rlMemory.GetRateLimitStats()
	if stats["backend_type"].(string) != "memory" {
		t.Errorf("Expected memory backend, got %s", stats["backend_type"])
	}

	// Test creating rate limiter with Redis backend (skip if Redis unavailable)
	redisConfig := DefaultRateLimitConfig()
	redisConfig.Backend.Type = "redis"

	rlRedis, err := NewRateLimiter(&redisConfig)
	if err != nil {
		t.Logf("Redis not available, skipping Redis backend test: %v", err)
		return
	}
	defer rlRedis.Stop()

	// Verify it's using Redis backend
	stats = rlRedis.GetRateLimitStats()
	if stats["backend_type"].(string) != "redis" {
		t.Errorf("Expected redis backend, got %s", stats["backend_type"])
	}
}

func TestConcurrentBackendAccess(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Backend.Type = "memory"

	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test concurrent access to the backend
	const numGoroutines = 10
	const requestsPerGoroutine = 20

	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			ip := fmt.Sprintf("203.0.113.%d", goroutineID)

			for j := 0; j < requestsPerGoroutine; j++ {
				// Concurrent operations
				now := time.Now()
				rl.backend.IncrementConnections(ctx, ip, now)
				rl.backend.AddRequest(ctx, ip, now)

				if j%5 == 0 {
					rl.backend.AddError(ctx, ip, now)
				}

				if j%10 == 0 {
					ban := &BanRecord{
						BannedAt:  now,
						ExpiresAt: now.Add(time.Minute),
						Reason:    fmt.Sprintf("Concurrent test %d", j),
					}
					rl.backend.SetBan(ctx, ip, ban)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	stats, err := rl.backend.GetStats(ctx)
	if err != nil {
		t.Errorf("Failed to get stats after concurrent access: %v", err)
	}

	if stats.TrackedIPs != numGoroutines {
		t.Errorf("Expected %d tracked IPs, got %d", numGoroutines, stats.TrackedIPs)
	}
}

func TestRateLimiterHeaders(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Backend.Type = "memory"
	config.Headers.Enabled = true
	config.MaxConcurrentConnections = 2
	config.HTTPRequestRate = 3

	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Add a test Tor exit
	rl.mu.Lock()
	rl.torExits["203.0.113.1"] = true
	rl.mu.Unlock()

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(handler)

	// Test 1: Tor exit should get X-Tor-Exit header
	req := httptest.NewRequest("GET", "/pks/lookup", nil)
	req.RemoteAddr = "203.0.113.1:12345"

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if torHeader := rr.Header().Get("X-Tor-Exit"); torHeader != "true" {
		t.Errorf("Expected X-Tor-Exit header to be 'true', got '%s'", torHeader)
	}

	// Test 2: Regular IP should not get Tor header
	req = httptest.NewRequest("GET", "/pks/lookup", nil)
	req.RemoteAddr = "8.8.8.8:12345"

	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if torHeader := rr.Header().Get("X-Tor-Exit"); torHeader != "" {
		t.Errorf("Expected no X-Tor-Exit header for regular IP, got '%s'", torHeader)
	}

	// Test 3: Rate limit violation should set ban headers
	testIP := "203.0.113.42"

	// Trigger rate limit by making multiple rapid requests
	for i := 0; i < 5; i++ {
		req = httptest.NewRequest("GET", "/pks/lookup", nil)
		req.RemoteAddr = testIP + ":12345"

		rr = httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code == http.StatusTooManyRequests {
			banHeader := rr.Header().Get("X-RateLimit-Ban")
			reasonHeader := rr.Header().Get("X-RateLimit-Ban-Reason")
			typeHeader := rr.Header().Get("X-RateLimit-Ban-Type")

			if banHeader == "" {
				t.Error("Expected X-RateLimit-Ban header to be set")
			}
			if reasonHeader == "" {
				t.Error("Expected X-RateLimit-Ban-Reason header to be set")
			}
			if typeHeader == "" {
				t.Error("Expected X-RateLimit-Ban-Type header to be set")
			}

			t.Logf("Ban headers set correctly: duration=%s, reason=%s, type=%s",
				banHeader, reasonHeader, typeHeader)
			break
		}
	}
}

func TestRateLimiterHeadersDisabled(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.Backend.Type = "memory"
	config.Headers.Enabled = false // Disable headers
	config.MaxConcurrentConnections = 1

	rl, err := NewRateLimiter(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Add a test Tor exit
	rl.mu.Lock()
	rl.torExits["203.0.113.1"] = true
	rl.mu.Unlock()

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(handler)

	// Test that no headers are set when disabled
	req := httptest.NewRequest("GET", "/pks/lookup", nil)
	req.RemoteAddr = "203.0.113.1:12345" // Tor IP

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	// Even though this is a Tor IP, no header should be set when disabled
	if torHeader := rr.Header().Get("X-Tor-Exit"); torHeader != "" {
		t.Errorf("Expected no headers when disabled, got X-Tor-Exit: '%s'", torHeader)
	}

	// Trigger rate limit violation
	req = httptest.NewRequest("GET", "/pks/lookup", nil)
	req.RemoteAddr = "203.0.113.1:12345"

	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code == http.StatusTooManyRequests {
		// Check that ban headers are not set when disabled
		banHeader := rr.Header().Get("X-RateLimit-Ban")
		if banHeader != "" {
			t.Errorf("Expected no ban headers when disabled, got X-RateLimit-Ban: '%s'", banHeader)
		}
	}
}
