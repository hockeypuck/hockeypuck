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

package memory

import (
	"context"
	"sync"
	"time"

	"hockeypuck/ratelimit/types"
)

// Backend implements backend.Backend using in-memory storage
type Backend struct {
	mu      sync.RWMutex
	metrics map[string]*types.IPMetrics
	torData *TorData
}

// New creates a new in-memory backend
func New(config types.MemoryBackendConfig) (types.Backend, error) {
	return &Backend{
		metrics: make(map[string]*types.IPMetrics),
		torData: &TorData{
			exits: make(map[string]bool),
		},
	}, nil
}

// GetMetrics retrieves metrics for an IP address
func (mb *Backend) GetMetrics(ctx context.Context, ip string) (*types.IPMetrics, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	if metrics, exists := mb.metrics[ip]; exists {
		// Return a copy to avoid concurrent modification
		return mb.copyMetrics(metrics), nil
	}

	return &types.IPMetrics{}, nil
}

// SetMetrics stores metrics for an IP address
func (mb *Backend) SetMetrics(ctx context.Context, ip string, metrics *types.IPMetrics) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.metrics[ip] = mb.copyMetrics(metrics)
	return nil
}

// UpdateMetrics atomically updates metrics for an IP address
func (mb *Backend) UpdateMetrics(ctx context.Context, ip string, updateFn func(*types.IPMetrics) *types.IPMetrics) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	current := mb.metrics[ip]
	if current == nil {
		current = &types.IPMetrics{}
	}

	// Apply the update function
	updated := updateFn(mb.copyMetrics(current))
	mb.metrics[ip] = updated

	return nil
}

// IncrementConnections atomically increments connection count and rate
func (mb *Backend) IncrementConnections(ctx context.Context, ip string, timestamp time.Time) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Connections.Count++
		metrics.Connections.Rate = append(metrics.Connections.Rate, timestamp)
		metrics.Connections.LastSeen = timestamp

		// Clean old entries
		mb.cleanConnectionRate(metrics, timestamp)

		return metrics
	})
}

// DecrementConnections atomically decrements connection count
func (mb *Backend) DecrementConnections(ctx context.Context, ip string) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		if metrics.Connections.Count > 0 {
			metrics.Connections.Count--
		}

		return metrics
	})
}

// AddRequest adds a request timestamp to the metrics
func (mb *Backend) AddRequest(ctx context.Context, ip string, timestamp time.Time) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Requests.Requests = append(metrics.Requests.Requests, timestamp)
		metrics.Requests.LastSeen = timestamp

		// Clean old entries
		mb.cleanRequestEntries(metrics, timestamp)

		return metrics
	})
}

// AddError adds an error timestamp to the metrics
func (mb *Backend) AddError(ctx context.Context, ip string, timestamp time.Time) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Requests.Errors = append(metrics.Requests.Errors, timestamp)

		// Clean old entries
		mb.cleanErrorEntries(metrics, timestamp)

		return metrics
	})
}

// SetBan sets a ban record for an IP
func (mb *Backend) SetBan(ctx context.Context, ip string, ban *types.BanRecord) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Ban = &types.BanRecord{
			BannedAt:     ban.BannedAt,
			ExpiresAt:    ban.ExpiresAt,
			Reason:       ban.Reason,
			IsTorExit:    ban.IsTorExit,
			OffenseCount: ban.OffenseCount,
		}

		return metrics
	})
}

// GetBan retrieves ban information for an IP
func (mb *Backend) GetBan(ctx context.Context, ip string) (*types.BanRecord, error) {
	metrics, err := mb.GetMetrics(ctx, ip)
	if err != nil {
		return nil, err
	}

	if metrics.Ban != nil {
		return &types.BanRecord{
			BannedAt:     metrics.Ban.BannedAt,
			ExpiresAt:    metrics.Ban.ExpiresAt,
			Reason:       metrics.Ban.Reason,
			IsTorExit:    metrics.Ban.IsTorExit,
			OffenseCount: metrics.Ban.OffenseCount,
		}, nil
	}

	return nil, nil
}

// RemoveBan removes a ban for an IP
func (mb *Backend) RemoveBan(ctx context.Context, ip string) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *types.IPMetrics) *types.IPMetrics {
		metrics.Ban = nil
		return metrics
	})
}

// GetAllBannedIPs returns all currently banned IPs
func (mb *Backend) GetAllBannedIPs(ctx context.Context) ([]string, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	var bannedIPs []string
	now := time.Now()

	for ip, metrics := range mb.metrics {
		if metrics.Ban != nil && now.Before(metrics.Ban.ExpiresAt) {
			bannedIPs = append(bannedIPs, ip)
		}
	}

	return bannedIPs, nil
}

// GetStats returns backend statistics
func (mb *Backend) GetStats(ctx context.Context) (types.BackendStats, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	now := time.Now()
	var bannedCount, torBannedCount int

	for _, metrics := range mb.metrics {
		if metrics.Ban != nil && now.Before(metrics.Ban.ExpiresAt) {
			bannedCount++
			if metrics.Ban.IsTorExit {
				torBannedCount++
			}
		}
	}

	return types.BackendStats{
		TrackedIPs:   len(mb.metrics),
		BannedIPs:    bannedCount,
		TorBannedIPs: torBannedCount,
		BackendType:  "memory",
		BackendInfo: map[string]interface{}{
			"memory_usage": len(mb.metrics),
		},
	}, nil
}

// Cleanup removes stale metrics
func (mb *Backend) Cleanup(ctx context.Context, staleThreshold time.Time) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	now := time.Now()

	for ip, metrics := range mb.metrics {
		// Check if metrics are stale
		isStale := metrics.Connections.LastSeen.Before(staleThreshold) &&
			metrics.Requests.LastSeen.Before(staleThreshold)

		// Don't remove if banned and ban hasn't expired
		if metrics.Ban != nil && now.Before(metrics.Ban.ExpiresAt) {
			isStale = false
		}

		if isStale {
			delete(mb.metrics, ip)
		}
	}

	return nil
}

// Close closes the backend (no-op for memory backend)
func (mb *Backend) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.metrics = nil
	return nil
}

// Tor Backend Implementation

// TorData stores Tor exit nodes in memory
type TorData struct {
	exits          map[string]bool
	lastUpdated    time.Time
	globalRequests []time.Time      // Global request timestamps for all Tor exits
	globalBan      *types.BanRecord // Global ban for all Tor exits
}

// StoreTorExits stores the Tor exit node list in memory
func (mb *Backend) StoreTorExits(ctx context.Context, exits map[string]bool) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Make a copy to avoid concurrent modification
	mb.torData.exits = make(map[string]bool)
	for ip, isTorExit := range exits {
		if isTorExit {
			mb.torData.exits[ip] = true
		}
	}
	mb.torData.lastUpdated = time.Now()

	return nil
}

// LoadTorExits loads the Tor exit node list from memory
func (mb *Backend) LoadTorExits(ctx context.Context) (map[string]bool, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	// Make a copy to avoid concurrent modification
	exits := make(map[string]bool)
	for ip := range mb.torData.exits {
		exits[ip] = true
	}

	return exits, nil
}

// IsTorExit checks if an IP is a Tor exit node
func (mb *Backend) IsTorExit(ctx context.Context, ip string) (bool, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	return mb.torData.exits[ip], nil
}

// GetTorStats returns Tor exit statistics
func (mb *Backend) GetTorStats(ctx context.Context) (types.TorStats, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	return types.TorStats{
		Count:       len(mb.torData.exits),
		LastUpdated: mb.torData.lastUpdated,
		TTL:         0, // No TTL for memory backend
	}, nil
}

// Global Tor rate limiting methods

// AddGlobalTorRequest adds a timestamp to the global Tor request tracking
func (mb *Backend) AddGlobalTorRequest(ctx context.Context, timestamp time.Time) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.torData.globalRequests = append(mb.torData.globalRequests, timestamp)

	// Clean old entries (keep only last hour)
	cutoff := timestamp.Add(-time.Hour)
	var recent []time.Time
	for _, t := range mb.torData.globalRequests {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	mb.torData.globalRequests = recent

	return nil
}

// GetGlobalTorRequests returns the count of global Tor requests within the specified window
func (mb *Backend) GetGlobalTorRequests(ctx context.Context, window time.Duration) (int, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	count := 0
	for _, t := range mb.torData.globalRequests {
		if t.After(cutoff) {
			count++
		}
	}

	return count, nil
}

// SetGlobalTorBan sets a global ban for all Tor exits
func (mb *Backend) SetGlobalTorBan(ctx context.Context, ban *types.BanRecord) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if ban == nil {
		// Remove the global ban
		mb.torData.globalBan = nil
	} else {
		mb.torData.globalBan = &types.BanRecord{
			BannedAt:     ban.BannedAt,
			ExpiresAt:    ban.ExpiresAt,
			Reason:       ban.Reason,
			IsTorExit:    true,
			OffenseCount: ban.OffenseCount,
		}
	}

	return nil
}

// GetGlobalTorBan retrieves the global Tor ban if active
func (mb *Backend) GetGlobalTorBan(ctx context.Context) (*types.BanRecord, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	if mb.torData.globalBan != nil && time.Now().Before(mb.torData.globalBan.ExpiresAt) {
		// Return a copy
		return &types.BanRecord{
			BannedAt:     mb.torData.globalBan.BannedAt,
			ExpiresAt:    mb.torData.globalBan.ExpiresAt,
			Reason:       mb.torData.globalBan.Reason,
			IsTorExit:    mb.torData.globalBan.IsTorExit,
			OffenseCount: mb.torData.globalBan.OffenseCount,
		}, nil
	}

	return nil, nil
}

// copyMetrics creates a deep copy of IPMetrics
func (mb *Backend) copyMetrics(original *types.IPMetrics) *types.IPMetrics {
	if original == nil {
		return &types.IPMetrics{}
	}

	copy := &types.IPMetrics{
		Connections: types.ConnectionTracker{
			Count:    original.Connections.Count,
			LastSeen: original.Connections.LastSeen,
		},
		Requests: types.RequestTracker{
			LastSeen: original.Requests.LastSeen,
		},
	}

	// Copy slices
	copy.Connections.Rate = make([]time.Time, len(original.Connections.Rate))
	copy.Connections.Rate = append([]time.Time{}, original.Connections.Rate...)

	copy.Requests.Requests = make([]time.Time, len(original.Requests.Requests))
	copy.Requests.Requests = append([]time.Time{}, original.Requests.Requests...)

	copy.Requests.Errors = make([]time.Time, len(original.Requests.Errors))
	copy.Requests.Errors = append([]time.Time{}, original.Requests.Errors...)

	// Copy ban record
	if original.Ban != nil {
		copy.Ban = &types.BanRecord{
			BannedAt:     original.Ban.BannedAt,
			ExpiresAt:    original.Ban.ExpiresAt,
			Reason:       original.Ban.Reason,
			IsTorExit:    original.Ban.IsTorExit,
			OffenseCount: original.Ban.OffenseCount,
		}
	}

	return copy
}

// Helper methods for cleaning old entries
func (mb *Backend) cleanConnectionRate(metrics *types.IPMetrics, now time.Time) {
	cutoff := now.Add(-10 * time.Second)
	cleaned := make([]time.Time, 0, len(metrics.Connections.Rate))
	for _, t := range metrics.Connections.Rate {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	metrics.Connections.Rate = cleaned
}

func (mb *Backend) cleanRequestEntries(metrics *types.IPMetrics, now time.Time) {
	cutoff := now.Add(-10 * time.Second)
	cleaned := make([]time.Time, 0, len(metrics.Requests.Requests))
	for _, t := range metrics.Requests.Requests {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	metrics.Requests.Requests = cleaned
}

func (mb *Backend) cleanErrorEntries(metrics *types.IPMetrics, now time.Time) {
	cutoff := now.Add(-5 * time.Minute)
	cleaned := make([]time.Time, 0, len(metrics.Requests.Errors))
	for _, t := range metrics.Requests.Errors {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	metrics.Requests.Errors = cleaned
}

// Register registers the memory backend with the ratelimit package
func Register() {
	// This will be called from an init function in the main package
	// to register the memory backend constructor
}

// NewBackend creates a new memory backend from a BackendConfig
func NewBackend(config *types.BackendConfig) (types.Backend, error) {
	return &Backend{
		metrics: make(map[string]*types.IPMetrics),
		torData: &TorData{
			exits:          make(map[string]bool),
			globalRequests: make([]time.Time, 0),
			globalBan:      nil,
		},
	}, nil
}

// MemoryBackendConstructor is the constructor function for memory backends
var MemoryBackendConstructor = func(config *types.BackendConfig) (types.Backend, error) {
	return NewBackend(config)
}
