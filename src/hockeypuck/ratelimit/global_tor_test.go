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
	"strings"
	"testing"
	"time"

	"hockeypuck/ratelimit/types"

	// Register the memory backend
	_ "hockeypuck/ratelimit/backend/memory"
)

func TestGlobalTorRateLimiting(t *testing.T) {
	// Create config with very restrictive global Tor limits
	config := types.DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.GlobalRateLimit = true
	config.Tor.GlobalRequestRate = 2 // Only 2 requests allowed globally
	config.Tor.GlobalRateWindow = 5 * time.Second
	config.Tor.GlobalBanDuration = 30 * time.Second

	// Create rate limiter
	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Mock some Tor exit nodes
	ctx := context.Background()
	torExits := map[string]bool{
		"192.0.2.1": true,
		"192.0.2.2": true,
		"192.0.2.3": true,
	}
	err = rl.backend.StoreTorExits(ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	// Set up test handler that tracks calls
	handlerCalled := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	// First request from Tor exit 1 - should be allowed
	req1 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First Tor request should be allowed, got status %d", w1.Code)
	}

	// Second request from different Tor exit 2 - should be allowed
	req2 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req2.RemoteAddr = "192.0.2.2:1234"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Second Tor request from different exit should be allowed, got status %d", w2.Code)
	}

	// Third request from different Tor exit 3 - should be blocked due to global limit
	req3 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req3.RemoteAddr = "192.0.2.3:1234"
	w3 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("Third Tor request should be blocked by global limit, got status %d", w3.Code)
	}

	// Check the ban reason - headers should contain detailed info for load balancer
	banReason := w3.Header().Get("X-RateLimit-Ban-Reason")
	if !strings.Contains(banReason, "Global Tor rate limit exceeded") {
		t.Errorf("Expected detailed global Tor ban reason in header, got: %s", banReason)
	}

	// Verify all Tor exits are now banned
	req4 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req4.RemoteAddr = "192.0.2.1:1234"
	w4 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w4, req4)

	if w4.Code != http.StatusTooManyRequests {
		t.Errorf("Original Tor exit should now be banned by global ban, got status %d", w4.Code)
	}

	req5 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req5.RemoteAddr = "192.0.2.2:1234"
	w5 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w5, req5)

	if w5.Code != http.StatusTooManyRequests {
		t.Errorf("Second Tor exit should now be banned by global ban, got status %d", w5.Code)
	}

	// Non-Tor IP should still be allowed
	req6 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req6.RemoteAddr = "10.0.0.1:1234"
	w6 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w6, req6)

	if w6.Code != http.StatusOK {
		t.Errorf("Non-Tor IP should still be allowed, got status %d", w6.Code)
	}

	// Should have only 3 successful handler calls (2 Tor + 1 non-Tor)
	if handlerCalled != 3 {
		t.Errorf("Expected 3 handler calls, got %d", handlerCalled)
	}
}

func TestGlobalTorBanExpiration(t *testing.T) {
	// Create config with very short global ban duration and short rate window for testing
	config := types.DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.GlobalRateLimit = true
	config.Tor.GlobalRequestRate = 1                      // Only 1 request allowed globally
	config.Tor.GlobalRateWindow = 50 * time.Millisecond   // Very short window
	config.Tor.GlobalBanDuration = 100 * time.Millisecond // Very short ban

	// Create rate limiter
	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Mock Tor exit nodes
	ctx := context.Background()
	torExits := map[string]bool{
		"192.0.2.1": true,
		"192.0.2.2": true,
	}
	err = rl.backend.StoreTorExits(ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	// Set up test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	// First request - should be allowed
	req1 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request should be allowed, got status %d", w1.Code)
	}

	// Second request immediately - should trigger global ban
	req2 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req2.RemoteAddr = "192.0.2.2:1234"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request should be blocked, got status %d", w2.Code)
	}

	// Wait for both the rate window and ban to expire
	time.Sleep(200 * time.Millisecond)

	// After both expire, new requests should be allowed
	req3 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req3.RemoteAddr = "192.0.2.1:1234"
	w3 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		banReason := w3.Header().Get("X-RateLimit-Ban-Reason")
		t.Errorf("Request should be allowed after ban and rate window expire, got status %d, reason: %s", w3.Code, banReason)
	}
}

func TestGlobalTorRateLimitingDisabled(t *testing.T) {
	// Create config with global Tor rate limiting disabled
	config := types.DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.GlobalRateLimit = false // Disabled
	config.Tor.GlobalRequestRate = 1   // Very restrictive, but should be ignored

	// Create rate limiter
	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Mock Tor exit nodes
	ctx := context.Background()
	torExits := map[string]bool{
		"192.0.2.1": true,
		"192.0.2.2": true,
		"192.0.2.3": true,
	}
	err = rl.backend.StoreTorExits(ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	// Set up test handler
	handlerCalled := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	// Multiple requests should all be allowed since global limiting is disabled
	// (though individual Tor limits may still apply)
	req1 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req2.RemoteAddr = "192.0.2.2:1234"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	req3 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req3.RemoteAddr = "192.0.2.3:1234"
	w3 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w3, req3)

	// At least the first request should be allowed (global limiting is disabled)
	if w1.Code != http.StatusOK {
		t.Errorf("Request should be allowed (global limiting disabled), got status %d", w1.Code)
	}

	// Some requests may be blocked by individual Tor limits, but not by global limits
	if handlerCalled == 0 {
		t.Error("At least some requests should succeed when global limiting is disabled")
	}
}

func TestGlobalTorVsIndividualLimits(t *testing.T) {
	// Create config where individual limits are more restrictive than global
	config := types.DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.GlobalRateLimit = true
	config.Tor.GlobalRequestRate = 10 // Allow 10 globally
	config.Tor.GlobalRateWindow = 10 * time.Second
	config.Tor.MaxRequestsPerConnection = 1 // But only 1 per individual connection (for key uploads)

	// Create rate limiter
	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Mock Tor exit node
	ctx := context.Background()
	torExits := map[string]bool{"192.0.2.1": true}
	err = rl.backend.StoreTorExits(ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	// Set up test handler
	handlerCalled := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	// First key upload request should be allowed
	req1 := httptest.NewRequest("POST", "/pks/add", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First key upload request should be allowed, got status %d", w1.Code)
	}

	// Second key upload request should be blocked by individual Tor limits (not global)
	req2 := httptest.NewRequest("POST", "/pks/add", nil)
	req2.RemoteAddr = "192.0.2.1:1234"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second key upload request should be blocked by individual limit, got status %d", w2.Code)
	}

	// Should be blocked by individual Tor limits, not global
	banReason := w2.Header().Get("X-RateLimit-Ban-Reason")
	if strings.Contains(strings.ToLower(banReason), "global tor") {
		t.Errorf("Should be blocked by individual Tor limits, not global. Got: %s", banReason)
	}

	// Only one request should have succeeded
	if handlerCalled != 1 {
		t.Errorf("Expected 1 handler call, got %d", handlerCalled)
	}
}
