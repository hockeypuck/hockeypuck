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

package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"hockeypuck/conflux/recon"
)

// mockPartnerProvider implements PartnerProvider for testing
type mockPartnerProvider struct {
	partners []*recon.Partner
}

func (m *mockPartnerProvider) CurrentPartners() []*recon.Partner {
	return m.partners
}

func TestReconPeerExemption(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.MaxConcurrentConnections = 1
	config.ConnectionRate = 1
	config.HTTPRequestRate = 1
	config.KeyserverSync.Enabled = true

	// Create mock recon partners
	partner1IP := net.ParseIP("203.0.113.100")
	partner2IP := net.ParseIP("203.0.113.101")

	partnerProvider := &mockPartnerProvider{
		partners: []*recon.Partner{
			{
				ReconAddr: "203.0.113.100:11370",
				HTTPAddr:  "203.0.113.100:11371",
				IPs:       []net.IP{partner1IP},
			},
			{
				ReconAddr: "203.0.113.101:11370",
				HTTPAddr:  "203.0.113.101:11371",
				IPs:       []net.IP{partner2IP},
			},
		},
	}

	// Create rate limiter with partner provider
	rl, err := NewRateLimiterWithPartners(&config, partnerProvider)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test recon peer detection
	if !rl.isReconPeer("203.0.113.100") {
		t.Error("203.0.113.100 should be detected as recon peer")
	}

	if !rl.isReconPeer("203.0.113.101") {
		t.Error("203.0.113.101 should be detected as recon peer")
	}

	if rl.isReconPeer("203.0.113.102") {
		t.Error("203.0.113.102 should not be detected as recon peer")
	}

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(handler)

	// Test exemption for /pks/hashquery requests from recon peers
	req := httptest.NewRequest("POST", "/pks/hashquery", nil)
	req.RemoteAddr = "203.0.113.100:12345"

	// Multiple rapid requests should succeed for recon peer accessing /pks/hashquery
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d from recon peer to /pks/hashquery should succeed, got status %d", i+1, rr.Code)
		}
	}

	// Test that non-hashquery requests from recon peers are still rate limited
	req = httptest.NewRequest("GET", "/pks/lookup", nil)
	req.RemoteAddr = "203.0.113.100:12345"

	// First request should succeed
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("First non-hashquery request from recon peer should succeed, got status %d", rr.Code)
	}

	// Second request should be rate limited
	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Second non-hashquery request from recon peer should be rate limited, got status %d", rr.Code)
	}

	// Test that non-recon peers are rate limited for /pks/hashquery
	req = httptest.NewRequest("POST", "/pks/hashquery", nil)
	req.RemoteAddr = "203.0.113.102:12345"

	// First request should succeed
	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("First request from non-recon peer should succeed, got status %d", rr.Code)
	}

	// Second request should be rate limited
	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Second request from non-recon peer should be rate limited, got status %d", rr.Code)
	}
}

func TestReconPeerExemptionDisabled(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.MaxConcurrentConnections = 1
	config.ConnectionRate = 1
	config.HTTPRequestRate = 1
	config.KeyserverSync.Enabled = false // Disable keyserver sync exemptions

	// Create mock recon partners
	partnerProvider := &mockPartnerProvider{
		partners: []*recon.Partner{
			{
				ReconAddr: "203.0.113.100:11370",
				HTTPAddr:  "203.0.113.100:11371",
				IPs:       []net.IP{net.ParseIP("203.0.113.100")},
			},
		},
	}

	rl, err := NewRateLimiterWithPartners(&config, partnerProvider)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test that recon peer detection is disabled
	if rl.isReconPeer("203.0.113.100") {
		t.Error("Recon peer detection should be disabled")
	}

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := rl.Middleware()
	wrappedHandler := middleware(handler)

	// Test that even /pks/hashquery requests are rate limited when exemption disabled
	req := httptest.NewRequest("POST", "/pks/hashquery", nil)
	req.RemoteAddr = "203.0.113.100:12345"

	// First request should succeed
	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("First request should succeed, got status %d", rr.Code)
	}

	// Second request should be rate limited
	rr = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Second request should be rate limited when exemption disabled, got status %d", rr.Code)
	}
}

func TestReconPeerWithoutPartnerProvider(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.KeyserverSync.Enabled = true

	// Create rate limiter without partner provider (nil)
	rl, err := NewRateLimiterWithPartners(&config, nil)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test that no IPs are detected as recon peers when provider is nil
	if rl.isReconPeer("203.0.113.100") {
		t.Error("No IPs should be detected as recon peers when provider is nil")
	}
}

func TestReconPeerHostnameResolution(t *testing.T) {
	config := DefaultRateLimitConfig()
	config.KeyserverSync.Enabled = true

	// Create mock recon partner with hostname that should resolve to localhost
	partnerProvider := &mockPartnerProvider{
		partners: []*recon.Partner{
			{
				ReconAddr: "localhost:11370",
				HTTPAddr:  "localhost:11371",
				IPs:       []net.IP{}, // No pre-resolved IPs, should trigger hostname resolution
			},
		},
	}

	rl, err := NewRateLimiterWithPartners(&config, partnerProvider)
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer rl.Stop()

	// Test that localhost resolves to 127.0.0.1 and is detected as recon peer
	if !rl.isReconPeer("127.0.0.1") {
		t.Error("127.0.0.1 should be detected as recon peer via hostname resolution")
	}
}

func TestServerIntegrationWithReconPeer(t *testing.T) {
	// This test verifies that the server properly integrates the recon peer
	// with the rate limiter

	settings := DefaultSettings()
	settings.RateLimit.MaxConcurrentConnections = 1
	settings.RateLimit.ConnectionRate = 1
	settings.RateLimit.HTTPRequestRate = 1
	settings.RateLimit.KeyserverSync.Enabled = true

	// Configure to use a temporary directory for leveldb to avoid DB issues
	settings.OpenPGP.DB.Driver = "" // Disable DB for this test
	tempDir := t.TempDir()
	settings.Conflux.Recon.LevelDB.Path = tempDir

	// This test just verifies that the constructor integration works
	// without actually creating a full server (which requires DB)

	// Test that NewRateLimiterWithPartners works with a nil provider
	rl, err := NewRateLimiterWithPartners(&settings.RateLimit, nil)
	if err != nil {
		t.Fatalf("Failed to create rate limiter with nil partner provider: %v", err)
	}
	defer rl.Stop()

	// Verify the rate limiter was created successfully
	if rl.partnerProvider != nil {
		t.Error("Partner provider should be nil when passed nil")
	}

	// Test with a mock partner provider
	partnerProvider := &mockPartnerProvider{
		partners: []*recon.Partner{
			{
				ReconAddr: "test.example.com:11370",
				HTTPAddr:  "test.example.com:11371",
				IPs:       []net.IP{net.ParseIP("203.0.113.100")},
			},
		},
	}

	rl2, err := NewRateLimiterWithPartners(&settings.RateLimit, partnerProvider)
	if err != nil {
		t.Fatalf("Failed to create rate limiter with mock partner provider: %v", err)
	}
	defer rl2.Stop()

	// Verify the partner provider was set correctly
	if rl2.partnerProvider != partnerProvider {
		t.Error("Partner provider should match the provided mock")
	}

	// Test recon peer detection works
	if !rl2.isReconPeer("203.0.113.100") {
		t.Error("Should detect mock recon peer IP")
	}
}
