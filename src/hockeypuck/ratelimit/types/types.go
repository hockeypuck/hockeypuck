/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package types

import (
	"context"
	"fmt"
	"time"

	"hockeypuck/conflux/recon"
)

// PartnerProvider provides access to current recon partners
type PartnerProvider interface {
	CurrentPartners() []*recon.Partner
}

// Config holds the rate limiting configuration
type Config struct {
	Enabled                  bool          `toml:"enabled"`
	MaxConcurrentConnections int           `toml:"maxConcurrentConnections"`
	ConnectionRate           int           `toml:"connectionRate"`  // per 3 seconds
	HTTPRequestRate          int           `toml:"httpRequestRate"` // per 10 seconds
	HTTPErrorRate            int           `toml:"httpErrorRate"`   // per 5 minutes
	CrawlerBlockDuration     time.Duration `toml:"crawlerBlockDuration"`
	TrustProxyHeaders        bool          `toml:"trustProxyHeaders"`

	Backend       BackendConfig       `toml:"backend"`
	Tor           TorConfig           `toml:"tor"`
	Whitelist     WhitelistConfig     `toml:"whitelist"`
	KeyserverSync KeyserverSyncConfig `toml:"keyserverSync"`
	Headers       HeaderConfig        `toml:"headers"`
}

// TorConfig holds Tor-specific rate limiting configuration
type TorConfig struct {
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
	UserAgent                 string        `toml:"userAgent"` // User-Agent header for HTTP requests (set programmatically)
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

// BackendConfig holds the metrics backend configuration
type BackendConfig struct {
	Type   string              `toml:"type"`   // "memory" or "redis"
	Memory MemoryBackendConfig `toml:"memory"` // Memory backend config
	Redis  RedisBackendConfig  `toml:"redis"`  // Redis backend config
}

// MemoryBackendConfig holds configuration for the memory backend
type MemoryBackendConfig struct {
	// No configuration options for memory backend currently
}

// RedisBackendConfig holds configuration for the Redis backend
type RedisBackendConfig struct {
	Addr         string        `toml:"addr"`         // Redis server address (default: "localhost:6379")
	Password     string        `toml:"password"`     // Redis password
	DB           int           `toml:"db"`           // Redis database number (default: 0)
	PoolSize     int           `toml:"poolSize"`     // Connection pool size (default: 10)
	DialTimeout  time.Duration `toml:"dialTimeout"`  // Connection timeout (default: 5s)
	ReadTimeout  time.Duration `toml:"readTimeout"`  // Read timeout (default: 3s)
	WriteTimeout time.Duration `toml:"writeTimeout"` // Write timeout (default: 3s)
	KeyPrefix    string        `toml:"keyPrefix"`    // Key prefix for Redis keys
	TTL          time.Duration `toml:"ttl"`          // Default TTL for Redis keys (default: 24h)
	MaxRetries   int           `toml:"maxRetries"`   // Max number of retries for Redis commands (default: 3)
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
	Connections ConnectionTracker
	Requests    RequestTracker
	Ban         *BanRecord
}

// BackendStats holds statistics about the backend
type BackendStats struct {
	TrackedIPs   int                    `json:"tracked_ips"`
	BannedIPs    int                    `json:"banned_ips"`
	TorBannedIPs int                    `json:"tor_banned_ips"`
	BackendType  string                 `json:"backend_type"`
	BackendInfo  map[string]interface{} `json:"backend_info,omitempty"`
}

// TorStats holds Tor exit node statistics
type TorStats struct {
	Count       int           `json:"count"`
	LastUpdated time.Time     `json:"last_updated"`
	TTL         time.Duration `json:"ttl,omitempty"`
}

// Backend defines the interface for rate limiting storage backends
type Backend interface {
	// GetMetrics retrieves metrics for an IP address
	GetMetrics(ctx context.Context, ip string) (*IPMetrics, error)

	// SetMetrics stores metrics for an IP address
	SetMetrics(ctx context.Context, ip string, metrics *IPMetrics) error

	// UpdateMetrics atomically updates metrics for an IP address
	UpdateMetrics(ctx context.Context, ip string, updateFn func(*IPMetrics) *IPMetrics) error

	// IncrementConnections atomically increments connection count and rate
	IncrementConnections(ctx context.Context, ip string, timestamp time.Time) error

	// DecrementConnections atomically decrements connection count
	DecrementConnections(ctx context.Context, ip string) error

	// AddRequest adds a request timestamp to the metrics
	AddRequest(ctx context.Context, ip string, timestamp time.Time) error

	// AddError adds an error timestamp to the metrics
	AddError(ctx context.Context, ip string, timestamp time.Time) error

	// SetBan sets a ban record for an IP
	SetBan(ctx context.Context, ip string, ban *BanRecord) error

	// GetBan retrieves ban information for an IP
	GetBan(ctx context.Context, ip string) (*BanRecord, error)

	// RemoveBan removes a ban for an IP
	RemoveBan(ctx context.Context, ip string) error

	// GetAllBannedIPs returns all currently banned IPs
	GetAllBannedIPs(ctx context.Context) ([]string, error)

	// GetStats returns backend statistics
	GetStats(ctx context.Context) (BackendStats, error)

	// Cleanup removes stale metrics
	Cleanup(ctx context.Context, staleThreshold time.Time) error

	// Close closes the backend connection
	Close() error

	// TorBackend interface for Tor exit node operations
	TorBackend
}

// TorBackend defines operations for Tor exit node management
type TorBackend interface {
	// StoreTorExits stores the Tor exit node list
	StoreTorExits(ctx context.Context, exits map[string]bool) error

	// LoadTorExits loads the Tor exit node list
	LoadTorExits(ctx context.Context) (map[string]bool, error)

	// IsTorExit checks if an IP is a Tor exit node
	IsTorExit(ctx context.Context, ip string) (bool, error)

	// GetTorStats returns Tor exit statistics
	GetTorStats(ctx context.Context) (TorStats, error)
}

// Backend constructor registry
var (
	memoryBackendConstructor func(*BackendConfig) (Backend, error)
	redisBackendConstructor  func(*BackendConfig) (Backend, error)
)

// RegisterMemoryBackend registers the memory backend constructor and returns it
func RegisterMemoryBackend(constructor func(*BackendConfig) (Backend, error)) func(*BackendConfig) (Backend, error) {
	memoryBackendConstructor = constructor
	return constructor
}

// RegisterRedisBackend registers the redis backend constructor and returns it
func RegisterRedisBackend(constructor func(*BackendConfig) (Backend, error)) func(*BackendConfig) (Backend, error) {
	redisBackendConstructor = constructor
	return constructor
}

// NewBackend creates a new backend instance
func NewBackend(config *BackendConfig) (Backend, error) {
	switch config.Type {
	case "memory", "":
		if memoryBackendConstructor == nil {
			return nil, fmt.Errorf("memory backend not registered - import _ \"hockeypuck/ratelimit/backend/memory\"")
		}
		return memoryBackendConstructor(config)
	case "redis":
		if redisBackendConstructor == nil {
			return nil, fmt.Errorf("redis backend not registered - import _ \"hockeypuck/ratelimit/backend/redis\"")
		}
		return redisBackendConstructor(config)
	default:
		return nil, fmt.Errorf("unknown backend type: %s", config.Type)
	}
}

// DefaultConfig returns the default rate limiting configuration
func DefaultConfig() Config {
	return Config{
		Enabled:                  true,
		MaxConcurrentConnections: 80,
		ConnectionRate:           40,  // per 3 seconds
		HTTPRequestRate:          100, // per 10 seconds
		HTTPErrorRate:            20,  // per 5 minutes
		CrawlerBlockDuration:     24 * time.Hour,
		TrustProxyHeaders:        false,

		Backend: DefaultBackendConfig(),

		Tor: TorConfig{
			Enabled:                   true,
			MaxRequestsPerConnection:  2,
			MaxConcurrentConnections:  1,
			ConnectionRate:            1,                // per connectionRateWindow
			ConnectionRateWindow:      10 * time.Second, // 10 seconds default
			BanDuration:               24 * time.Hour,
			RepeatOffenderBanDuration: 24 * 24 * time.Hour, // 24 days
			ExitNodeListURL:           "https://www.dan.me.uk/torlist/?exit",
			UpdateInterval:            time.Hour, // 1 hour is appropriate for production
			CacheFilePath:             "tor_exit_nodes.cache",
			UserAgent:                 "Hockeypuck-KeyServer/1.0 (Tor exit list fetcher)", // Default, should be overridden
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

// DefaultBackendConfig returns the default backend configuration
func DefaultBackendConfig() BackendConfig {
	return BackendConfig{
		Type:   "memory",
		Memory: MemoryBackendConfig{},
		Redis: RedisBackendConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			KeyPrefix:    "hockeypuck:ratelimit:",
			TTL:          24 * time.Hour,
			MaxRetries:   3,
		},
	}
}
