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
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"hockeypuck/conflux/recon"
)

// PartnerProvider provides access to current recon partners
type PartnerProvider interface {
	CurrentPartners() []*recon.Partner
}

// RateLimitConfig holds the rate limiting configuration
type RateLimitConfig struct {
	Enabled                  bool          `toml:"enabled"`
	MaxConcurrentConnections int           `toml:"maxConcurrentConnections"`
	ConnectionRate           int           `toml:"connectionRate"`  // per 3 seconds
	HTTPRequestRate          int           `toml:"httpRequestRate"` // per 10 seconds
	HTTPErrorRate            int           `toml:"httpErrorRate"`   // per 5 minutes
	CrawlerBlockDuration     time.Duration `toml:"crawlerBlockDuration"`
	TrustProxyHeaders        bool          `toml:"trustProxyHeaders"`

	Backend       MetricsBackendConfig `toml:"backend"`
	Tor           TorRateLimitConfig   `toml:"tor"`
	Whitelist     WhitelistConfig      `toml:"whitelist"`
	KeyserverSync KeyserverSyncConfig  `toml:"keyserverSync"`
	Headers       HeaderConfig         `toml:"headers"`
}

// TorRateLimitConfig holds Tor-specific rate limiting configuration
type TorRateLimitConfig struct {
	Enabled                   bool          `toml:"enabled"`
	MaxRequestsPerConnection  int           `toml:"maxRequestsPerConnection"`
	MaxConcurrentConnections  int           `toml:"maxConcurrentConnections"`
	ConnectionRate            int           `toml:"connectionRate"`            // per connectionRateWindow
	ConnectionRateWindow      time.Duration `toml:"connectionRateWindow"`      // time window for connection rate (default: 10s)
	BanDuration               time.Duration `toml:"banDuration"`               // 24h
	RepeatOffenderBanDuration time.Duration `toml:"repeatOffenderBanDuration"` // 24 days
	ExitNodeListURL           string        `toml:"exitNodeListURL"`
	UpdateInterval            time.Duration `toml:"updateInterval"`
	CacheFilePath             string        `toml:"cacheFilePath"`
	UseBackendStorage         bool          `toml:"useBackendStorage"` // Store Tor list in backend instead of memory
}

// WhitelistConfig holds IP whitelist configuration
type WhitelistConfig struct {
	IPs []string `toml:"ips"`
}

// KeyserverSyncConfig holds configuration for keyserver synchronization exemptions
type KeyserverSyncConfig struct {
	Enabled bool `toml:"enabled"` // Enable automatic exemptions for configured recon peers
}

// HeaderConfig holds configuration for HTTP response headers
type HeaderConfig struct {
	Enabled   bool   `toml:"enabled"`   // Enable header-based rate limiting communication
	TorHeader string `toml:"torHeader"` // Header name for Tor exit identification (default: X-Tor-Exit)
	BanHeader string `toml:"banHeader"` // Header name for ban duration (default: X-RateLimit-Ban)
}

// DefaultRateLimitConfig returns the default rate limiting configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:                  true,
		MaxConcurrentConnections: 80,
		ConnectionRate:           40,  // per 3 seconds
		HTTPRequestRate:          100, // per 10 seconds
		HTTPErrorRate:            20,  // per 5 minutes
		CrawlerBlockDuration:     24 * time.Hour,
		TrustProxyHeaders:        false,

		Backend: DefaultMetricsBackendConfig(),

		Tor: TorRateLimitConfig{
			Enabled:                   true,
			MaxRequestsPerConnection:  2,
			MaxConcurrentConnections:  1,
			ConnectionRate:            1,                // per connectionRateWindow
			ConnectionRateWindow:      10 * time.Second, // 10 seconds default
			BanDuration:               24 * time.Hour,
			RepeatOffenderBanDuration: 24 * 24 * time.Hour, // 24 days
			ExitNodeListURL:           "https://www.dan.me.uk/torlist/?exit",
			UpdateInterval:            time.Hour,
			CacheFilePath:             "tor_exit_nodes.cache",
			UseBackendStorage:         false, // Default to file-based for compatibility
		},

		Whitelist: WhitelistConfig{
			IPs: []string{
				"127.0.0.1",
				"::1",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},

		KeyserverSync: KeyserverSyncConfig{
			Enabled: true, // Enable automatic exemptions for configured recon peers by default
		},

		Headers: HeaderConfig{
			Enabled:   true,              // Enable header-based communication by default
			TorHeader: "X-Tor-Exit",      // Standard header name for Tor exit identification
			BanHeader: "X-RateLimit-Ban", // Standard header name for ban duration
		},
	}
}

// ConnectionTracker tracks connection-level metrics for rate limiting
type ConnectionTracker struct {
	Count    int         // current concurrent connections
	Rate     []time.Time // connection timestamps for rate calculation
	LastSeen time.Time
}

// RequestTracker tracks HTTP request-level metrics
type RequestTracker struct {
	Requests []time.Time // request timestamps
	Errors   []time.Time // error timestamps
	LastSeen time.Time
}

// BanRecord tracks IP ban information
type BanRecord struct {
	BannedAt     time.Time
	ExpiresAt    time.Time
	Reason       string
	IsTorExit    bool
	OffenseCount int // for escalating Tor bans
}

// IPMetrics holds all tracking data for a single IP
type IPMetrics struct {
	mu          sync.RWMutex
	Connections ConnectionTracker
	Requests    RequestTracker
	Ban         *BanRecord
}

// RateLimiter implements the core rate limiting engine
type RateLimiter struct {
	config          *RateLimitConfig
	backend         MetricsBackend
	partnerProvider PartnerProvider // For accessing recon peers
	mu              sync.RWMutex
	torExits        map[string]bool
	whitelists      []*net.IPNet

	// Cleanup
	cleanupTicker *time.Ticker
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(config *RateLimitConfig) (*RateLimiter, error) {
	return NewRateLimiterWithPartners(config, nil)
}

// NewRateLimiterWithPartners creates a new rate limiter instance with partner provider
func NewRateLimiterWithPartners(config *RateLimitConfig, partnerProvider PartnerProvider) (*RateLimiter, error) {
	if config == nil {
		defaultConfig := DefaultRateLimitConfig()
		config = &defaultConfig
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create metrics backend
	backend, err := NewMetricsBackend(config.Backend)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create metrics backend: %w", err)
	}

	rl := &RateLimiter{
		config:          config,
		backend:         backend,
		partnerProvider: partnerProvider,
		torExits:        make(map[string]bool),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Parse whitelist CIDRs
	if err := rl.parseWhitelists(); err != nil {
		cancel()
		backend.Close()
		return nil, err
	}

	// Start background tasks
	rl.startCleanupTask()
	if config.Tor.Enabled {
		rl.startTorExitUpdater()
	}

	return rl, nil
}

// parseWhitelists parses CIDR strings into IPNet objects
func (rl *RateLimiter) parseWhitelists() error {
	for _, cidr := range rl.config.Whitelist.IPs {
		// Handle single IPs without CIDR notation
		if !contains(cidr, "/") {
			if net.ParseIP(cidr) != nil {
				if contains(cidr, ":") {
					cidr += "/128" // IPv6
				} else {
					cidr += "/32" // IPv4
				}
			}
		}

		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		rl.whitelists = append(rl.whitelists, ipnet)
	}
	return nil
}

// contains is a simple string contains check
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// Stop gracefully shuts down the rate limiter
func (rl *RateLimiter) Stop() {
	if rl.cancel != nil {
		rl.cancel()
	}
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
	if rl.backend != nil {
		rl.backend.Close()
	}
}

// Middleware returns an HTTP middleware that enforces rate limits
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	if !rl.config.Enabled {
		// Rate limiting disabled, return no-op middleware
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract client IP
			clientIP := rl.extractClientIP(r)
			if clientIP == "" {
				// Could not determine client IP, allow request
				next.ServeHTTP(w, r)
				return
			}

			// Set Tor exit header if enabled and this is a Tor exit
			if rl.config.Headers.Enabled && rl.isTorExit(clientIP) {
				w.Header().Set(rl.config.Headers.TorHeader, "true")
			}

			// Check if IP is whitelisted
			if rl.isWhitelisted(clientIP) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if this is a recon peer accessing /pks/hashquery (keyserver sync)
			if rl.isReconPeer(clientIP) && strings.HasPrefix(r.URL.Path, "/pks/hashquery") {
				next.ServeHTTP(w, r)
				return
			}

			// Check rate limits
			if violated, reason := rl.checkRateLimits(clientIP, r); violated {
				// Determine ban details before recording violation
				isTorExit := rl.isTorExit(clientIP)
				banDuration := rl.determineBanDuration(clientIP, isTorExit, reason)
				banType := rl.determineBanType(clientIP, isTorExit, reason)

				// Set ban headers for HAProxy processing if enabled
				if rl.config.Headers.Enabled {
					w.Header().Set(rl.config.Headers.BanHeader, rl.formatBanDuration(banDuration))
					w.Header().Set("X-RateLimit-Ban-Reason", reason)
					w.Header().Set("X-RateLimit-Ban-Type", banType)
				}

				// Record violation and ban the IP
				rl.recordViolation(clientIP, r, reason)

				// Return rate limit error
				w.Header().Set("Retry-After", "60") // Standard retry after header
				http.Error(w, reason, http.StatusTooManyRequests)
				return
			}

			// Track the request
			rl.trackRequest(clientIP, r)

			// Use a custom response writer to track errors
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)

			// Record errors for error rate limiting
			if sw.statusCode >= 400 {
				rl.trackError(clientIP, r)
			}
		})
	}
}

// statusWriter wraps http.ResponseWriter to capture status codes
type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.statusCode = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.statusCode == 0 {
		sw.statusCode = 200
	}
	return sw.ResponseWriter.Write(b)
}
