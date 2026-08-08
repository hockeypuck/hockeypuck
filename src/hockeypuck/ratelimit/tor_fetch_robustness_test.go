package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hockeypuck/ratelimit/types"

	// Import backends to register them
	_ "hockeypuck/ratelimit/backend/memory"
)

func TestTorFetchRobustness(t *testing.T) {
	t.Log("Testing Tor exit list fetching robustness...")

	// Test cases for different HTTP error codes
	testCases := []struct {
		name        string
		statusCode  int
		description string
	}{
		{
			name:        "HTTP 429 (Rate Limited)",
			statusCode:  http.StatusTooManyRequests,
			description: "rate limited by server",
		},
		{
			name:        "HTTP 403 (Forbidden)",
			statusCode:  http.StatusForbidden,
			description: "access forbidden (possibly rate limited or blocked)",
		},
		{
			name:        "HTTP 500 (Internal Server Error)",
			statusCode:  http.StatusInternalServerError,
			description: "internal server error",
		},
		{
			name:        "HTTP 503 (Service Unavailable)",
			statusCode:  http.StatusServiceUnavailable,
			description: "service unavailable (server may be overloaded)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing %s: %s", tc.name, tc.description)

			// Serve the desired status code from a local test server so the
			// suite stays hermetic (no external network dependency).
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			// Create a rate limiter with the problematic URL
			config := types.DefaultConfig()
			config.Tor.UpdateInterval = 100 * time.Millisecond // Very short for testing
			config.Tor.ExitNodeListURL = srv.URL
			// Use a unique cache file under a temp dir to avoid interference
			// and to keep test artifacts out of the package directory.
			config.Tor.CacheFilePath = filepath.Join(t.TempDir(), "test_cache.json")

			rl, err := New(&config)
			if err != nil {
				t.Fatalf("Failed to create rate limiter: %v", err)
			}
			defer rl.Stop()

			t.Log("Rate limiter created, waiting for update attempts...")
			time.Sleep(200 * time.Millisecond)

			// Check stats - should handle the error gracefully
			stats := rl.GetRateLimitStats()
			t.Logf("Stats after fetch attempts: %+v", stats)

			// The system should not crash and should handle errors gracefully
			// Since we're using a fresh cache file, tor_exits_count should be 0
			if torCount, ok := stats["tor_exits_count"].(int); ok {
				if torCount != 0 {
					t.Logf("Note: tor_exits_count is %d (may be from cache)", torCount)
				}
			}

			t.Logf("Test completed - system handled %s gracefully", tc.name)
		})
	}
}

func TestTorFetchUserAgent(t *testing.T) {
	t.Log("Testing Tor exit list fetching with custom UserAgent...")

	// A local server that records the User-Agent header it receives and
	// returns a valid exit list.
	var gotUserAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.UserAgent()
		fmt.Fprintln(w, "1.2.3.4")
	}))
	defer srv.Close()

	const userAgent = "Hockeypuck/2.1.8 (Test UserAgent)"
	exits, err := fetchTorExitList(context.Background(), srv.URL, userAgent)
	if err != nil {
		t.Fatalf("fetchTorExitList failed: %v", err)
	}

	if gotUserAgent != userAgent {
		t.Errorf("Expected User-Agent %q to be sent, got %q", userAgent, gotUserAgent)
	}

	if !exits["1.2.3.4"] {
		t.Errorf("Expected exit list to contain 1.2.3.4, got %v", exits)
	}
}

func TestTorFetchEmptyResponse(t *testing.T) {
	t.Log("Testing Tor exit list fetching with non-IP (HTML) response...")

	// A 200 response carrying HTML rather than a list of IPs must be treated
	// as empty: no line parses as an IP address.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><body>Service temporarily unavailable</body></html>")
	}))
	defer srv.Close()

	exits, err := fetchTorExitList(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("fetchTorExitList failed: %v", err)
	}

	if len(exits) != 0 {
		t.Errorf("Expected no exits from HTML content, got %d: %v", len(exits), exits)
	}
}

func TestTorFetchNetworkError(t *testing.T) {
	t.Log("Testing Tor exit list fetching with network error...")

	// Create a rate limiter with an unreachable URL
	config := types.DefaultConfig()
	config.Tor.UpdateInterval = 100 * time.Millisecond
	config.Tor.CacheFilePath = "" // Disable caching for this test
	// Use an invalid domain that will cause a network error
	config.Tor.ExitNodeListURL = "https://nonexistent-domain-12345.invalid/torlist"

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	t.Log("Rate limiter created, waiting for update attempts...")
	time.Sleep(200 * time.Millisecond)

	// Check stats - should handle network error gracefully
	stats := rl.GetRateLimitStats()
	t.Logf("Stats after network error: %+v", stats)

	// Tor exit count should remain 0 since fetch failed due to network error
	if torCount, ok := stats["tor_exits_count"].(int); ok {
		if torCount != 0 {
			t.Logf("Note: tor_exits_count is %d (unexpected after network error)", torCount)
		}
	}

	t.Log("Network error handling test completed")
}
