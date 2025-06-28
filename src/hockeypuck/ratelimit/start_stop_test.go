package ratelimit

import (
	"testing"
	"time"
)

func TestRateLimiterStartStop(t *testing.T) {
	config := DefaultConfig()
	config.Backend.Type = "memory"
	config.Enabled = true

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Test that Stop() works without Start()
	rl.Stop()

	// Create a new rate limiter for the start/stop test
	rl2, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create second rate limiter: %v", err)
	}

	// Start background tasks
	rl2.Start()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the rate limiter
	rl2.Stop()
}

func TestRateLimiterTorBackgroundTask(t *testing.T) {
	config := DefaultConfig()
	config.Backend.Type = "memory"
	config.Enabled = true
	config.Tor.Enabled = true
	config.Tor.UpdateInterval = 100 * time.Millisecond
	config.Tor.ExitNodeListURL = "https://httpbin.org/status/404" // This will fail and log warnings

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}

	// Start background tasks
	rl.Start()

	// Give the Tor updater time to run at least once
	time.Sleep(200 * time.Millisecond)

	// Stop the rate limiter
	rl.Stop()

	// The test passes if Start/Stop complete without hanging
	t.Log("Tor background task test completed successfully")
}
