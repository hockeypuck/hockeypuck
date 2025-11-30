package ratelimit

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestTorStatsReporting(t *testing.T) {
	ctx := context.Background()

	// Test: Both memory and redis backends should work the same way
	config1 := DefaultConfig()
	config1.Tor.Enabled = true
	config1.Tor.CacheFilePath = "/tmp/test_tor_cache.json"

	// Clean up any existing cache file
	os.Remove(config1.Tor.CacheFilePath)

	rl1, err := New(&config1)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl1.Stop()

	// Manually store some Tor exits in backend
	testExits := map[string]bool{
		"1.2.3.4":    true,
		"5.6.7.8":    true,
		"9.10.11.12": true,
	}

	err = rl1.backend.StoreTorExits(ctx, testExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits in backend: %v", err)
	}

	// Get stats
	stats1 := rl1.GetRateLimitStats()
	if torCount, ok := stats1["tor_exits_count"].(int); !ok || torCount != 3 {
		t.Errorf("Expected tor_exits_count to be 3, got %v", stats1["tor_exits_count"])
	}

	if lastUpdated, ok := stats1["tor_last_updated"].(time.Time); !ok || lastUpdated.IsZero() {
		t.Errorf("Expected tor_last_updated to be set, got %v", stats1["tor_last_updated"])
	}

	// Test isTorExit functionality
	if isTor, err := rl1.isTorExit("1.2.3.4"); err != nil {
		t.Errorf("Error checking Tor exit status: %v", err)
	} else if !isTor {
		t.Error("Expected 1.2.3.4 to be detected as Tor exit")
	}

	if isTor, err := rl1.isTorExit("192.168.1.1"); err != nil {
		t.Errorf("Error checking Tor exit status: %v", err)
	} else if isTor {
		t.Error("Expected 192.168.1.1 to NOT be detected as Tor exit")
	}

	// Cleanup
	os.Remove(config1.Tor.CacheFilePath)
}
