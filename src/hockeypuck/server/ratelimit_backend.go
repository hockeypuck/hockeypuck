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
	"time"
)

// MetricsBackend defines the interface for rate limiting storage backends
type MetricsBackend interface {
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

	// Tor Backend Methods
	TorBackend
}

// TorBackend defines interface for Tor exit node storage
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

// BackendStats represents statistics from the metrics backend
type BackendStats struct {
	TrackedIPs   int                    `json:"tracked_ips"`
	BannedIPs    int                    `json:"banned_ips"`
	TorBannedIPs int                    `json:"tor_banned_ips"`
	BackendType  string                 `json:"backend_type"`
	BackendInfo  map[string]interface{} `json:"backend_info,omitempty"`
}

// TorStats represents statistics about Tor exit nodes
type TorStats struct {
	Count       int           `json:"count"`
	LastUpdated time.Time     `json:"last_updated"`
	UpdateURL   string        `json:"update_url"`
	TTL         time.Duration `json:"ttl"`
}

// MetricsBackendConfig holds configuration for different backend types
type MetricsBackendConfig struct {
	Type   string               `toml:"type"` // "memory", "redis", "etcd", "zookeeper"
	Memory *MemoryBackendConfig `toml:"memory"`
	Redis  *RedisBackendConfig  `toml:"redis"`
	// Future: Etcd, Zookeeper configs
}

// MemoryBackendConfig holds configuration for in-memory backend
type MemoryBackendConfig struct {
	// No additional config needed for memory backend
}

// RedisBackendConfig holds configuration for Redis backend
type RedisBackendConfig struct {
	Addr         string        `toml:"addr"`         // Redis server address
	Password     string        `toml:"password"`     // Redis password
	DB           int           `toml:"db"`           // Redis database number
	PoolSize     int           `toml:"poolSize"`     // Connection pool size
	DialTimeout  time.Duration `toml:"dialTimeout"`  // Connection timeout
	ReadTimeout  time.Duration `toml:"readTimeout"`  // Read timeout
	WriteTimeout time.Duration `toml:"writeTimeout"` // Write timeout
	KeyPrefix    string        `toml:"keyPrefix"`    // Prefix for Redis keys
	TTL          time.Duration `toml:"ttl"`          // Default TTL for keys
}

// DefaultMetricsBackendConfig returns the default backend configuration
func DefaultMetricsBackendConfig() MetricsBackendConfig {
	return MetricsBackendConfig{
		Type:   "memory",
		Memory: &MemoryBackendConfig{},
		Redis: &RedisBackendConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			KeyPrefix:    "hockeypuck:ratelimit:",
			TTL:          24 * time.Hour,
		},
	}
}

// NewMetricsBackend creates a new metrics backend based on configuration
func NewMetricsBackend(config MetricsBackendConfig) (MetricsBackend, error) {
	switch config.Type {
	case "memory", "":
		return NewMemoryBackend(config.Memory)
	case "redis":
		return NewRedisBackend(config.Redis)
	default:
		return nil, fmt.Errorf("unsupported backend type: %s", config.Type)
	}
}
