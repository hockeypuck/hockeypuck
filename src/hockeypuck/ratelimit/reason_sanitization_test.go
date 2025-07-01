/*
   Test sanitization of ban reasons for client responses
*/

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "hockeypuck/ratelimit/backend/memory"
)

func TestReasonSanitization(t *testing.T) {
	tests := []struct {
		name           string
		detailedReason string
		expectedClient string
	}{
		{
			name:           "Global Tor ban",
			detailedReason: "Global Tor rate limit exceeded (2 >= 1 per 10s)",
			expectedClient: "Service temporarily unavailable for Tor users",
		},
		{
			name:           "Tor exit specific ban",
			detailedReason: "Tor exit: too many concurrent connections (1 >= 1)",
			expectedClient: "Request temporarily blocked",
		},
		{
			name:           "Already banned",
			detailedReason: "IP banned until 2025-07-01T15:14:53Z: Request rate exceeded",
			expectedClient: "Access temporarily restricted",
		},
		{
			name:           "Connection rate",
			detailedReason: "Too many concurrent connections (5 >= 2)",
			expectedClient: "Too many connections",
		},
		{
			name:           "Request rate",
			detailedReason: "Request rate exceeded (101 >= 100 per 10s)",
			expectedClient: "Too many requests",
		},
		{
			name:           "Error rate",
			detailedReason: "Error rate exceeded (21 >= 20 per 5m)",
			expectedClient: "Too many errors",
		},
		{
			name:           "Rapid fire abuse",
			detailedReason: "Tor exit: rapid request pattern detected (6 >= 5 per 30s)",
			expectedClient: "Request pattern detected",
		},
		{
			name:           "Generic fallback",
			detailedReason: "Some unknown rate limit condition",
			expectedClient: "Rate limit exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeReasonForClient(tt.detailedReason)
			if result != tt.expectedClient {
				t.Errorf("sanitizeReasonForClient(%q) = %q, want %q",
					tt.detailedReason, result, tt.expectedClient)
			}
		})
	}
}

func TestMiddlewareReasonSanitization(t *testing.T) {
	// Create rate limiter with very restrictive limits to trigger bans
	config := DefaultConfig()
	config.MaxConcurrentConnections = 100 // High enough to avoid connection limit
	config.HTTPRequestRate = 1            // Only 1 request per 10 seconds

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	testIP := "192.0.2.100"

	// First request should pass
	req1 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req1.RemoteAddr = testIP + ":1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request should pass, got status %d", w1.Code)
	}

	// Second request should be rate limited
	req2 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req2.RemoteAddr = testIP + ":1235"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request should be rate limited, got status %d", w2.Code)
	}

	// Check that the response body contains sanitized reason
	responseBody := w2.Body.String()
	if !strings.Contains(responseBody, "Too many requests") {
		t.Errorf("Response should contain sanitized reason, got: %s", responseBody)
	}

	// Ensure the response does not contain internal details
	if strings.Contains(responseBody, ">=") || strings.Contains(responseBody, "per 10s") {
		t.Errorf("Response should not contain internal rate limit details, got: %s", responseBody)
	}

	// Check sanitized header vs detailed header
	banReason := w2.Header().Get("X-RateLimit-Ban-Reason")
	if !strings.Contains(banReason, "Request rate exceeded") || !strings.Contains(banReason, ">=") {
		t.Errorf("Expected detailed header reason for load balancer, got: %s", banReason)
	}

	// Headers should contain internal details for load balancer intelligence
	if !strings.Contains(banReason, ">=") || !strings.Contains(banReason, "per 10s") {
		t.Errorf("Header should contain internal rate limit details for load balancer, got: %s", banReason)
	}
}

func TestTorReasonSanitization(t *testing.T) {
	// Create rate limiter with global Tor limits
	config := DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.GlobalRateLimit = true
	config.Tor.GlobalRequestRate = 1
	config.Tor.GlobalRateWindow = 5 * time.Second

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Mock Tor exit nodes
	torExits := map[string]bool{"192.0.2.1": true}
	err = rl.backend.StoreTorExits(rl.ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	// First Tor request
	req1 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	// Should be allowed
	if w1.Code != http.StatusOK {
		t.Errorf("First Tor request should be allowed, got status %d", w1.Code)
	}

	// Second Tor request (should trigger global ban)
	req2 := httptest.NewRequest("GET", "/pks/lookup", nil)
	req2.RemoteAddr = "192.0.2.1:1235"
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	// Should be blocked
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second Tor request should be blocked, got status %d", w2.Code)
	}

	// Check that response contains generic Tor message
	responseBody := w2.Body.String()
	if !strings.Contains(responseBody, "Service temporarily unavailable for Tor users") {
		t.Errorf("Response should contain generic Tor message, got: %s", responseBody)
	}

	// Ensure response doesn't expose internal details
	if strings.Contains(responseBody, "global requests") || strings.Contains(responseBody, ">=") {
		t.Errorf("Response should not contain internal details, got: %s", responseBody)
	}

	// Check header contains detailed info for load balancer
	banReason := w2.Header().Get("X-RateLimit-Ban-Reason")
	if !strings.Contains(banReason, "Global Tor rate limit exceeded") {
		t.Errorf("Expected detailed Tor ban reason in header for load balancer, got: %s", banReason)
	}
}
