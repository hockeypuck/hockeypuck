/*
   Test middleware ban behavior to ensure banned requests don't get processed
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

// TestMiddlewareBansPreventProcessing tests that banned requests don't reach the handler
func TestMiddlewareBansPreventProcessing(t *testing.T) {
	config := DefaultConfig()
	config.HTTPRequestRate = 1 // Very low rate limit
	config.Tor.Enabled = true
	config.Tor.MaxConcurrentConnections = 1

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

	// Track how many times the handler is called
	handlerCalled := 0
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Handler executed"))
	})

	// Wrap with rate limiting middleware
	middleware := rl.Middleware()
	wrappedHandler := middleware(testHandler)

	// First request should succeed
	req1 := httptest.NewRequest("POST", "/pks/add", strings.NewReader("test"))
	req1.RemoteAddr = "192.0.2.100:12345"
	w1 := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request should succeed, got status %d", w1.Code)
	}
	if handlerCalled != 1 {
		t.Errorf("Handler should be called once, was called %d times", handlerCalled)
	}

	// Add more requests to exceed rate limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/pks/add", strings.NewReader("test"))
		req.RemoteAddr = "192.0.2.100:12345"
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
	}

	// Next request should be banned and handler should NOT be called
	prevHandlerCalled := handlerCalled
	req2 := httptest.NewRequest("POST", "/pks/add", strings.NewReader("test"))
	req2.RemoteAddr = "192.0.2.100:12346"
	w2 := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Request should be banned with 429, got status %d, body: %s", w2.Code, w2.Body.String())
	}
	if handlerCalled != prevHandlerCalled {
		t.Errorf("Handler should NOT be called for banned request, but was called %d times (was %d)", handlerCalled, prevHandlerCalled)
	}

	// Verify ban headers are set
	banHeader := w2.Header().Get("X-RateLimit-Ban")
	if banHeader == "" {
		t.Error("Ban header should be set")
	}
	t.Logf("Ban header: %s", banHeader)
}

// TestMiddlewarePreventsConcurrentRequests tests that concurrent requests are properly limited
func TestMiddlewarePreventsConcurrentRequests(t *testing.T) {
	config := DefaultConfig()
	config.MaxConcurrentConnections = 1
	config.Tor.Enabled = true
	config.Tor.MaxConcurrentConnections = 1

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

	handlerCallCount := 0
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCallCount++
		// Simulate slow processing
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Slow handler executed"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(slowHandler)

	// Start first request (should succeed)
	req1 := httptest.NewRequest("POST", "/pks/add", strings.NewReader("test"))
	req1.RemoteAddr = "192.0.2.100:12345"
	w1 := httptest.NewRecorder()

	// Start request in goroutine to simulate concurrent access
	go wrappedHandler.ServeHTTP(w1, req1)

	// Give first request time to start
	time.Sleep(10 * time.Millisecond)

	// Second concurrent request should be rejected immediately
	req2 := httptest.NewRequest("POST", "/pks/add", strings.NewReader("test"))
	req2.RemoteAddr = "192.0.2.100:12346"
	w2 := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w2, req2)

	// Second request should be rejected
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Concurrent request should be rejected with 429, got status %d", w2.Code)
	}

	// Wait for first request to complete
	time.Sleep(200 * time.Millisecond)

	// Only one handler call should have succeeded
	if handlerCallCount > 1 {
		t.Errorf("Only one handler call should succeed, got %d", handlerCallCount)
	}
}
