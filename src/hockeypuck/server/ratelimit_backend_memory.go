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
	"sync"
	"time"
)

// MemoryBackend implements MetricsBackend using in-memory storage
type MemoryBackend struct {
	mu      sync.RWMutex
	metrics map[string]*IPMetrics
}

// NewMemoryBackend creates a new in-memory backend
func NewMemoryBackend(config *MemoryBackendConfig) (*MemoryBackend, error) {
	return &MemoryBackend{
		metrics: make(map[string]*IPMetrics),
	}, nil
}

// GetMetrics retrieves metrics for an IP address
func (mb *MemoryBackend) GetMetrics(ctx context.Context, ip string) (*IPMetrics, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	if metrics, exists := mb.metrics[ip]; exists {
		// Return a copy to avoid concurrent modification
		return mb.copyMetrics(metrics), nil
	}

	return &IPMetrics{}, nil
}

// SetMetrics stores metrics for an IP address
func (mb *MemoryBackend) SetMetrics(ctx context.Context, ip string, metrics *IPMetrics) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.metrics[ip] = mb.copyMetrics(metrics)
	return nil
}

// UpdateMetrics atomically updates metrics for an IP address
func (mb *MemoryBackend) UpdateMetrics(ctx context.Context, ip string, updateFn func(*IPMetrics) *IPMetrics) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	current := mb.metrics[ip]
	if current == nil {
		current = &IPMetrics{}
	}

	// Apply the update function
	updated := updateFn(mb.copyMetrics(current))
	mb.metrics[ip] = updated

	return nil
}

// IncrementConnections atomically increments connection count and rate
func (mb *MemoryBackend) IncrementConnections(ctx context.Context, ip string, timestamp time.Time) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *IPMetrics) *IPMetrics {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()

		metrics.Connections.Count++
		metrics.Connections.Rate = append(metrics.Connections.Rate, timestamp)
		metrics.Connections.LastSeen = timestamp

		// Clean old entries
		mb.cleanConnectionRate(metrics, timestamp)

		return metrics
	})
}

// DecrementConnections atomically decrements connection count
func (mb *MemoryBackend) DecrementConnections(ctx context.Context, ip string) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *IPMetrics) *IPMetrics {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()

		if metrics.Connections.Count > 0 {
			metrics.Connections.Count--
		}

		return metrics
	})
}

// AddRequest adds a request timestamp to the metrics
func (mb *MemoryBackend) AddRequest(ctx context.Context, ip string, timestamp time.Time) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *IPMetrics) *IPMetrics {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()

		metrics.Requests.Requests = append(metrics.Requests.Requests, timestamp)
		metrics.Requests.LastSeen = timestamp

		// Clean old entries
		mb.cleanRequestEntries(metrics, timestamp)

		return metrics
	})
}

// AddError adds an error timestamp to the metrics
func (mb *MemoryBackend) AddError(ctx context.Context, ip string, timestamp time.Time) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *IPMetrics) *IPMetrics {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()

		metrics.Requests.Errors = append(metrics.Requests.Errors, timestamp)

		// Clean old entries
		mb.cleanErrorEntries(metrics, timestamp)

		return metrics
	})
}

// SetBan sets a ban record for an IP
func (mb *MemoryBackend) SetBan(ctx context.Context, ip string, ban *BanRecord) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *IPMetrics) *IPMetrics {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()

		metrics.Ban = &BanRecord{
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
func (mb *MemoryBackend) GetBan(ctx context.Context, ip string) (*BanRecord, error) {
	metrics, err := mb.GetMetrics(ctx, ip)
	if err != nil {
		return nil, err
	}

	if metrics.Ban != nil {
		return &BanRecord{
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
func (mb *MemoryBackend) RemoveBan(ctx context.Context, ip string) error {
	return mb.UpdateMetrics(ctx, ip, func(metrics *IPMetrics) *IPMetrics {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()

		metrics.Ban = nil
		return metrics
	})
}

// GetAllBannedIPs returns all currently banned IPs
func (mb *MemoryBackend) GetAllBannedIPs(ctx context.Context) ([]string, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	var bannedIPs []string
	now := time.Now()

	for ip, metrics := range mb.metrics {
		metrics.mu.RLock()
		if metrics.Ban != nil && now.Before(metrics.Ban.ExpiresAt) {
			bannedIPs = append(bannedIPs, ip)
		}
		metrics.mu.RUnlock()
	}

	return bannedIPs, nil
}

// GetStats returns backend statistics
func (mb *MemoryBackend) GetStats(ctx context.Context) (BackendStats, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	now := time.Now()
	var bannedCount, torBannedCount int

	for _, metrics := range mb.metrics {
		metrics.mu.RLock()
		if metrics.Ban != nil && now.Before(metrics.Ban.ExpiresAt) {
			bannedCount++
			if metrics.Ban.IsTorExit {
				torBannedCount++
			}
		}
		metrics.mu.RUnlock()
	}

	return BackendStats{
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
func (mb *MemoryBackend) Cleanup(ctx context.Context, staleThreshold time.Time) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	now := time.Now()

	for ip, metrics := range mb.metrics {
		metrics.mu.RLock()

		// Check if metrics are stale
		isStale := metrics.Connections.LastSeen.Before(staleThreshold) &&
			metrics.Requests.LastSeen.Before(staleThreshold)

		// Don't remove if banned and ban hasn't expired
		if metrics.Ban != nil && now.Before(metrics.Ban.ExpiresAt) {
			isStale = false
		}

		metrics.mu.RUnlock()

		if isStale {
			delete(mb.metrics, ip)
		}
	}

	return nil
}

// Close closes the backend (no-op for memory backend)
func (mb *MemoryBackend) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.metrics = nil
	return nil
}

// Tor Backend Implementation

// torExits stores Tor exit nodes in memory
type TorData struct {
	exits       map[string]bool
	lastUpdated time.Time
}

// Initialize torData field in MemoryBackend
var torData = &TorData{
	exits: make(map[string]bool),
}

// StoreTorExits stores the Tor exit node list in memory
func (mb *MemoryBackend) StoreTorExits(ctx context.Context, exits map[string]bool) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Make a copy to avoid concurrent modification
	torData.exits = make(map[string]bool)
	for ip := range exits {
		torData.exits[ip] = true
	}
	torData.lastUpdated = time.Now()

	return nil
}

// LoadTorExits loads the Tor exit node list from memory
func (mb *MemoryBackend) LoadTorExits(ctx context.Context) (map[string]bool, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	// Make a copy to avoid concurrent modification
	exits := make(map[string]bool)
	for ip := range torData.exits {
		exits[ip] = true
	}

	return exits, nil
}

// IsTorExit checks if an IP is a Tor exit node
func (mb *MemoryBackend) IsTorExit(ctx context.Context, ip string) (bool, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	return torData.exits[ip], nil
}

// GetTorStats returns Tor exit statistics
func (mb *MemoryBackend) GetTorStats(ctx context.Context) (TorStats, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	return TorStats{
		Count:       len(torData.exits),
		LastUpdated: torData.lastUpdated,
		TTL:         0, // No TTL for memory backend
	}, nil
}

// copyMetrics creates a deep copy of IPMetrics
func (mb *MemoryBackend) copyMetrics(original *IPMetrics) *IPMetrics {
	if original == nil {
		return &IPMetrics{}
	}

	copy := &IPMetrics{
		Connections: ConnectionTracker{
			Count:    original.Connections.Count,
			LastSeen: original.Connections.LastSeen,
		},
		Requests: RequestTracker{
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
		copy.Ban = &BanRecord{
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
func (mb *MemoryBackend) cleanConnectionRate(metrics *IPMetrics, now time.Time) {
	cutoff := now.Add(-10 * time.Second)
	cleaned := make([]time.Time, 0, len(metrics.Connections.Rate))
	for _, t := range metrics.Connections.Rate {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	metrics.Connections.Rate = cleaned
}

func (mb *MemoryBackend) cleanRequestEntries(metrics *IPMetrics, now time.Time) {
	cutoff := now.Add(-10 * time.Second)
	cleaned := make([]time.Time, 0, len(metrics.Requests.Requests))
	for _, t := range metrics.Requests.Requests {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	metrics.Requests.Requests = cleaned
}

func (mb *MemoryBackend) cleanErrorEntries(metrics *IPMetrics, now time.Time) {
	cutoff := now.Add(-5 * time.Minute)
	cleaned := make([]time.Time, 0, len(metrics.Requests.Errors))
	for _, t := range metrics.Requests.Errors {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	metrics.Requests.Errors = cleaned
}
