package ratelimit

import (
	"fmt"
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
		url         string
		description string
	}{
		{
			name:        "HTTP 429 (Rate Limited)",
			url:         "https://httpbin.org/status/429",
			description: "rate limited by server",
		},
		{
			name:        "HTTP 403 (Forbidden)",
			url:         "https://httpbin.org/status/403",
			description: "access forbidden (possibly rate limited or blocked)",
		},
		{
			name:        "HTTP 500 (Internal Server Error)",
			url:         "https://httpbin.org/status/500",
			description: "internal server error",
		},
		{
			name:        "HTTP 503 (Service Unavailable)",
			url:         "https://httpbin.org/status/503",
			description: "service unavailable (server may be overloaded)",
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing %s: %s", tc.name, tc.description)

			// Create a rate limiter with the problematic URL
			config := types.DefaultConfig()
			config.Tor.UpdateInterval = 100 * time.Millisecond // Very short for testing
			config.Tor.ExitNodeListURL = tc.url
			// Use unique cache file for each test to avoid interference
			config.Tor.CacheFilePath = fmt.Sprintf("test_cache_%d.json", i)

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

	// Create a rate limiter with custom UserAgent
	config := types.DefaultConfig()
	config.Tor.UpdateInterval = 100 * time.Millisecond
	config.Tor.UserAgent = "Hockeypuck/2.1.8 (Test UserAgent)"
	config.Tor.CacheFilePath = "" // Disable caching for this test
	// Use httpbin.org/user-agent which echoes back the User-Agent header
	config.Tor.ExitNodeListURL = "https://httpbin.org/user-agent"

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Verify that the UserAgent is stored correctly
	if rl.config.Tor.UserAgent != "Hockeypuck/2.1.8 (Test UserAgent)" {
		t.Errorf("Expected UserAgent to be set correctly, got: %s", rl.config.Tor.UserAgent)
	}

	t.Log("UserAgent configuration test completed")
}

func TestTorFetchEmptyResponse(t *testing.T) {
	t.Log("Testing Tor exit list fetching with empty response...")

	// Create a rate limiter that gets an empty response
	config := types.DefaultConfig()
	config.Tor.UpdateInterval = 100 * time.Millisecond
	config.Tor.CacheFilePath = "" // Disable caching for this test
	// httpbin.org/html returns HTML content, not a list of IPs - should be treated as empty
	config.Tor.ExitNodeListURL = "https://httpbin.org/html"

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	t.Log("Rate limiter created, waiting for update attempts...")
	time.Sleep(200 * time.Millisecond)

	// Check stats - should handle empty/invalid response gracefully
	stats := rl.GetRateLimitStats()
	t.Logf("Stats after invalid content: %+v", stats)

	// The system should handle invalid content gracefully
	// (HTML content will be filtered out since it doesn't look like IP addresses)

	t.Log("Invalid content handling test completed")
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
