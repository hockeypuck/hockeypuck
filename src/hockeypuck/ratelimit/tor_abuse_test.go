/*
   Test rapid-fire abuse detection for Tor exits
*/

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "hockeypuck/ratelimit/backend/memory"
)

// TestTorRapidFireAbuse tests the new anti-vandalism rapid request detection
func TestTorRapidFireAbuse(t *testing.T) {
	config := DefaultConfig()
	config.Tor.Enabled = true

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Add a test Tor exit
	torExits := map[string]bool{"192.0.2.100": true}
	err = rl.backend.StoreTorExits(rl.ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	handlerCalled := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	testIP := "192.0.2.100"

	// Simulate rapid-fire requests that should trigger abuse detection
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/pks/lookup?search=test", nil)
		req.RemoteAddr = testIP + ":1234" + string(rune('0'+i))
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		t.Logf("Request %d: Status %d", i+1, w.Code)

		// After 5 requests in 30 seconds, subsequent requests should be banned
		if i >= 5 {
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("Request %d should be banned with 429, got %d", i+1, w.Code)
			}
		}
	}

	// Verify that only the first few requests reached the handler
	if handlerCalled > 5 {
		t.Errorf("Expected at most 5 handler calls due to rapid-fire protection, got %d", handlerCalled)
	}

	t.Logf("Handler called %d times (should be ≤ 5)", handlerCalled)
}

// TestTorKeyUploadAbuse tests strict limits for key uploads specifically
func TestTorKeyUploadAbuse(t *testing.T) {
	config := DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.MaxRequestsPerConnection = 2

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Add a test Tor exit
	torExits := map[string]bool{"192.0.2.200": true}
	err = rl.backend.StoreTorExits(rl.ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	handlerCalled := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	testIP := "192.0.2.200"

	// Test key upload requests - should be very strict
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/pks/add", strings.NewReader("keytext=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = testIP + ":1234" + string(rune('0'+i))
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		t.Logf("Key upload %d: Status %d", i+1, w.Code)

		// Should be banned very quickly for key uploads
		if i >= 2 { // After MaxRequestsPerConnection
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("Key upload %d should be banned with 429, got %d", i+1, w.Code)
			}
		}
	}

	// Key uploads should be limited very strictly
	if handlerCalled > 3 {
		t.Errorf("Expected at most 3 key upload handler calls, got %d", handlerCalled)
	}

	t.Logf("Handler called %d times for key uploads (should be ≤ 3)", handlerCalled)
}
