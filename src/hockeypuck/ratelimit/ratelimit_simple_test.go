package ratelimit

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

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

func TestRateLimiterCreation(t *testing.T) {
	config := DefaultConfig()
	config.Backend.Type = "memory"

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	if rl == nil {
		t.Error("Rate limiter should not be nil")
	}

	// Test stats
	stats := rl.GetRateLimitStats()
	if !stats["enabled"].(bool) {
		t.Error("Rate limiter should be enabled")
	}
	if stats["backend_type"].(string) != "memory" {
		t.Errorf("Expected backend type=memory, got %s", stats["backend_type"])
	}
}

func TestBackendCreation(t *testing.T) {
	// Test memory backend
	memoryConfig := &BackendConfig{
		Type: "memory",
	}

	backend, err := NewBackend(memoryConfig)
	if err != nil {
		t.Fatalf("Failed to create memory backend: %v", err)
	}
	defer backend.Close()

	if backend == nil {
		t.Error("Backend should not be nil")
	}

	// Test Redis backend (skip if Redis not available)
	redisConfig := &BackendConfig{
		Type: "redis",
		Redis: RedisBackendConfig{
			Addr: "localhost:6379",
		},
	}

	redisBackend, err := NewBackend(redisConfig)
	if err != nil {
		t.Logf("Redis not available, skipping: %v", err)
		return
	}
	defer redisBackend.Close()

	if redisBackend == nil {
		t.Error("Redis backend should not be nil")
	}
}
