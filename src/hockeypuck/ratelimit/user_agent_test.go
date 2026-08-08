package ratelimit

import (
	"testing"

	"hockeypuck/ratelimit/types"

	// Import backends to register them
	_ "hockeypuck/ratelimit/backend/memory"
)

func TestUserAgentConfiguration(t *testing.T) {
	// Test that UserAgent configuration is properly stored
	config := types.DefaultConfig()
	customUserAgent := "Hockeypuck/2.0.1 (Test Server)"
	config.Tor.UserAgent = customUserAgent

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Verify that the UserAgent is stored in the config
	if rl.config.Tor.UserAgent != customUserAgent {
		t.Errorf("Expected UserAgent %q, got %q", customUserAgent, rl.config.Tor.UserAgent)
	}

	t.Logf("UserAgent correctly set to: %s", rl.config.Tor.UserAgent)
}
