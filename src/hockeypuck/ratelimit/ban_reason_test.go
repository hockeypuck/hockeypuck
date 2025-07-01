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
	"testing"
	"time"

	_ "hockeypuck/ratelimit/backend/memory"
)

// TestBanReasonNotAppended tests that ban reasons are replaced, not appended
func TestBanReasonNotAppended(t *testing.T) {
	config := DefaultConfig()
	config.HTTPRequestRate = 1 // Very low to trigger quickly

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	testIP := "192.0.2.100"
	ctx := context.Background()

	// Create multiple requests to exceed the request rate
	req1, _ := http.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = testIP + ":12345"

	// Track multiple requests to exceed the limit
	for i := 0; i < 3; i++ {
		err = rl.trackRequest(testIP, req1)
		if err != nil {
			t.Fatalf("Failed to track request %d: %v", i, err)
		}
	}

	// Check if limit is violated and ban the IP
	violated, reason1 := rl.checkRateLimits(testIP, req1)
	if violated {
		rl.recordViolation(testIP, req1, reason1)
	}

	// Get the first ban record
	ban1, err := rl.backend.GetBan(ctx, testIP)
	if err != nil {
		t.Fatalf("Failed to get ban: %v", err)
	}
	if ban1 == nil {
		t.Fatal("Expected IP to be banned")
	}

	originalReason := ban1.Reason
	t.Logf("Original ban reason: %s", originalReason)

	// Try to make another request that would trigger another violation
	// This should NOT result in a new ban due to our fix
	req2, _ := http.NewRequest("POST", "/pks/add", nil)
	req2.RemoteAddr = testIP + ":12346"

	violated2, reason2 := rl.checkRateLimits(testIP, req2)
	if violated2 {
		rl.recordViolation(testIP, req2, reason2)
	}

	// Get the ban record again
	ban2, err := rl.backend.GetBan(ctx, testIP)
	if err != nil {
		t.Fatalf("Failed to get ban: %v", err)
	}
	if ban2 == nil {
		t.Fatal("Expected IP to still be banned")
	}

	t.Logf("Second check ban reason: %s", ban2.Reason)

	// The reason should be the same as the original, not appended
	if ban2.Reason != originalReason {
		t.Errorf("Ban reason changed unexpectedly. Original: %q, New: %q", originalReason, ban2.Reason)
	}

	// The ban should not have been updated recently (should be the same ban)
	if ban2.BannedAt != ban1.BannedAt {
		t.Error("Ban was unexpectedly renewed")
	}
}

// TestTorBanEscalation tests that Tor bans escalate properly without reason appending
func TestTorBanEscalation(t *testing.T) {
	config := DefaultConfig()
	config.Tor.Enabled = true
	config.Tor.MaxConcurrentConnections = 1
	config.Tor.BanDuration = 100 * time.Millisecond // Very short for testing
	config.Tor.RepeatOffenderBanDuration = 200 * time.Millisecond

	rl, err := New(&config)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	testIP := "198.51.100.200"
	ctx := context.Background()

	// Simulate a Tor exit node
	torExits := map[string]bool{testIP: true}
	err = rl.backend.StoreTorExits(ctx, torExits)
	if err != nil {
		t.Fatalf("Failed to store Tor exits: %v", err)
	}

	// First violation and ban
	req1, _ := http.NewRequest("POST", "/pks/add", nil)
	req1.RemoteAddr = testIP + ":12345"

	rl.banIP(testIP, "First Tor violation", true)

	ban1, err := rl.backend.GetBan(ctx, testIP)
	if err != nil {
		t.Fatalf("Failed to get first ban: %v", err)
	}
	if ban1 == nil {
		t.Fatal("Expected IP to be banned")
	}

	t.Logf("First ban reason: %s, Offense count: %d", ban1.Reason, ban1.OffenseCount)

	// Wait for the ban to expire
	time.Sleep(time.Until(ban1.ExpiresAt) + 10*time.Millisecond)

	// Second violation after ban expires - this should escalate
	req2, _ := http.NewRequest("POST", "/pks/add", nil)
	req2.RemoteAddr = testIP + ":12346"

	rl.banIP(testIP, "Second Tor violation", true)

	ban2, err := rl.backend.GetBan(ctx, testIP)
	if err != nil {
		t.Fatalf("Failed to get second ban: %v", err)
	}
	if ban2 == nil {
		t.Fatal("Expected IP to be banned again")
	}

	t.Logf("Second ban reason: %s, Offense count: %d", ban2.Reason, ban2.OffenseCount)

	// The second ban should have escalated offense count
	if ban2.OffenseCount <= ban1.OffenseCount {
		t.Errorf("Expected offense count to escalate, got %d, previous was %d", ban2.OffenseCount, ban1.OffenseCount)
	}

	// The reason should be the new reason, not appended to the old
	if ban2.Reason != "Second Tor violation" {
		t.Errorf("Expected reason to be 'Second Tor violation', got: %q", ban2.Reason)
	}
}
