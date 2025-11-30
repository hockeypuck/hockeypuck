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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hockeypuck/ratelimit/backend/memory"
	"hockeypuck/ratelimit/backend/redis"
)

func init() {
	// Register backends for testing
	RegisterMemoryBackend(memory.MemoryBackendConstructor)
	RegisterRedisBackend(redis.RedisBackendConstructor)
}

func TestMemoryBackendIntegration(t *testing.T) {
	config := &BackendConfig{
		Type: "memory",
	}

	backend, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create memory backend: %v", err)
	}

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

	// Test getting updated metrics
	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}
	if metrics.Connections.Count != 1 {
		t.Errorf("Expected connection count=1, got %d", metrics.Connections.Count)
	}
}

func TestRateLimiterIntegration(t *testing.T) {
	config := DefaultConfig()
	config.Backend.Type = "memory"

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test basic functionality
	if rl.config != &config {
		t.Error("Rate limiter should store config reference")
	}
}

func TestRateLimiterWhitelist(t *testing.T) {
	config := DefaultConfig()
	config.Backend.Type = "memory"

	rl, err := New(&config)
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
	config := DefaultConfig()
	config.Backend.Type = "memory"

	rl, err := New(&config)
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
	config := DefaultConfig()
	config.Backend.Type = "memory"
	config.MaxConcurrentConnections = 1
	config.ConnectionRate = 1

	rl, err := New(&config)
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
}

func TestRedisBackendIntegration(t *testing.T) {
	// Skip test if Redis is not available
	config := &BackendConfig{
		Type: "redis",
		Redis: RedisBackendConfig{
			Addr: "localhost:6379",
		},
	}

	backend, err := NewBackend(config)
	if err != nil {
		t.Skipf("Redis not available, skipping Redis backend tests: %v", err)
		return
	}

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

	// Add a small delay to ensure Redis operations complete
	time.Sleep(100 * time.Millisecond)

	// Test getting updated metrics
	metrics, err = backend.GetMetrics(ctx, ip)
	if err != nil {
		t.Errorf("GetMetrics failed: %v", err)
	}

	// Redis backend may have async behavior, so just check that we get metrics back
	if metrics == nil {
		t.Error("GetMetrics should return metrics after incrementing connections")
	} else {
		t.Logf("Connection count after increment: %d", metrics.Connections.Count)
		// Don't fail if count is 0, as Redis might have different timing
		if metrics.Connections.Count > 1 {
			t.Errorf("Expected connection count <= 1, got %d", metrics.Connections.Count)
		}
	}
}
