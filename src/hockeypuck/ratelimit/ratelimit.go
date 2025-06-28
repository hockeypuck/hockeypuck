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
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"hockeypuck/ratelimit/types"
)

// Type aliases for backend interface
type Backend = types.Backend
type TorBackend = types.TorBackend

// NewBackend creates a new backend instance
func NewBackend(config *BackendConfig) (Backend, error) {
	return types.NewBackend(config)
}

// RegisterMemoryBackend registers the memory backend constructor
func RegisterMemoryBackend(constructor func(*BackendConfig) (Backend, error)) {
	types.RegisterMemoryBackend(constructor)
}

// RegisterRedisBackend registers the redis backend constructor
func RegisterRedisBackend(constructor func(*BackendConfig) (Backend, error)) {
	types.RegisterRedisBackend(constructor)
}

// RateLimiter implements the core rate limiting engine
type RateLimiter struct {
	config          *Config
	backend         Backend
	partnerProvider PartnerProvider // For accessing recon peers
	mu              sync.RWMutex
	whitelists      []*net.IPNet

	// Cleanup
	cleanupTicker *time.Ticker
	ctx           context.Context
	cancel        context.CancelFunc
}

// New creates a new rate limiter instance
func New(config *Config) (*RateLimiter, error) {
	return NewWithPartners(config, nil)
}

// NewWithPartners creates a new rate limiter instance with partner provider
func NewWithPartners(config *Config, partnerProvider PartnerProvider) (*RateLimiter, error) {
	if config == nil {
		defaultConfig := DefaultConfig()
		config = &defaultConfig
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create metrics backend
	b, err := NewBackend(&config.Backend)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create metrics backend: %w", err)
	}

	rl := &RateLimiter{
		config:          config,
		backend:         b,
		partnerProvider: partnerProvider,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Parse whitelist CIDRs
	if err := rl.parseWhitelists(); err != nil {
		cancel()
		b.Close()
		return nil, err
	}

	// Start background tasks
	if config.Enabled {
		rl.startBackgroundTasks()
	}

	return rl, nil
}

// parseWhitelists parses CIDR strings into IPNet objects
func (rl *RateLimiter) parseWhitelists() error {
	for _, cidr := range rl.config.Whitelist.IPs {
		if strings.Contains(cidr, "/") {
			// CIDR notation
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
			}
			rl.whitelists = append(rl.whitelists, ipNet)
		} else {
			// Single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", cidr)
			}

			// Convert to CIDR (/32 for IPv4, /128 for IPv6)
			var mask int
			if ip.To4() != nil {
				mask = 32
			} else {
				mask = 128
			}

			_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), mask))
			if err != nil {
				return fmt.Errorf("failed to create CIDR for IP %s: %w", cidr, err)
			}
			rl.whitelists = append(rl.whitelists, ipNet)
		}
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

// startBackgroundTasks starts background goroutines for maintenance
func (rl *RateLimiter) startBackgroundTasks() {
	// Start cleanup routine
	rl.cleanupTicker = time.NewTicker(10 * time.Minute)
	go rl.cleanupRoutine()

	// Start Tor exit node updater if enabled
	if rl.config.Tor.Enabled {
		go rl.torUpdaterRoutine()
	}
}

// cleanupRoutine periodically cleans up stale metrics
func (rl *RateLimiter) cleanupRoutine() {
	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-rl.cleanupTicker.C:
			staleThreshold := time.Now().Add(-24 * time.Hour)
			if err := rl.backend.Cleanup(rl.ctx, staleThreshold); err != nil {
				log.WithError(err).Error("Failed to cleanup stale metrics")
			}
		}
	}
}

// torUpdaterRoutine periodically updates the Tor exit node list
func (rl *RateLimiter) torUpdaterRoutine() {
	// Initial update
	rl.updateTorExitList()

	// Periodic updates
	ticker := time.NewTicker(rl.config.Tor.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.updateTorExitList()
		}
	}
}

// updateTorExitList fetches and updates the Tor exit node list
func (rl *RateLimiter) updateTorExitList() {
	if !rl.config.Tor.Enabled {
		return
	}

	// Get current exit count for fallback logging
	currentStats, _ := rl.backend.GetTorStats(rl.ctx)

	// Try to load from cache first on startup (if backend is empty)
	if rl.config.Tor.CacheFilePath != "" && currentStats.Count == 0 {
		if cachedExits, err := loadTorExitCache(rl.config.Tor.CacheFilePath); err == nil && len(cachedExits) > 0 {
			if err := rl.backend.StoreTorExits(rl.ctx, cachedExits); err == nil {
				log.WithField("count", len(cachedExits)).Info("Loaded Tor exit list from cache")
			}
		}
	}

	// Fetch the latest Tor exit list from URL
	exits, err := fetchTorExitList(rl.config.Tor.ExitNodeListURL, rl.config.Tor.UserAgent)
	if err != nil {
		// Log the error but don't fail completely - keep using existing data
		log.WithError(err).WithField("current_count", currentStats.Count).
			Warn("Failed to fetch fresh Tor exit list, keeping existing data")

		// If we have no existing data and cache loading failed, this is more serious
		if currentStats.Count == 0 {
			log.WithError(err).Error("No Tor exit data available (fetch failed and no cached data)")
		}
		return
	}

	// Validate that we got some data (empty response might indicate rate limiting)
	if len(exits) == 0 {
		log.WithField("current_count", currentStats.Count).
			Warn("Received empty Tor exit list, possible rate limiting - keeping existing data")
		return
	}

	// Store in backend
	if err := rl.backend.StoreTorExits(rl.ctx, exits); err != nil {
		log.WithError(err).Error("Failed to store Tor exits in backend")
		return
	}

	// Save to cache file for persistence
	if rl.config.Tor.CacheFilePath != "" {
		if err := saveTorExitCache(rl.config.Tor.CacheFilePath, exits); err != nil {
			log.WithError(err).Error("Failed to save Tor exit cache")
		}
	}

	log.WithFields(log.Fields{
		"count":          len(exits),
		"previous_count": currentStats.Count,
	}).Info("Updated Tor exit list")
}

// isTorExit checks if an IP is a Tor exit node
func (rl *RateLimiter) isTorExit(ip string) bool {
	if !rl.config.Tor.Enabled {
		return false
	}

	// Always use backend storage (memory or redis)
	isTor, err := rl.backend.IsTorExit(rl.ctx, ip)
	if err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to check Tor exit status")
		return false
	}
	return isTor
}

// isWhitelisted checks if an IP is in the whitelist
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range rl.whitelists {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// isReconPeer checks if an IP belongs to a configured recon partner
func (rl *RateLimiter) isReconPeer(ip string) bool {
	if !rl.config.KeyserverSync.Enabled || rl.partnerProvider == nil {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	partners := rl.partnerProvider.CurrentPartners()
	for _, partner := range partners {
		for _, partnerIP := range partner.IPs {
			if partnerIP.Equal(parsedIP) {
				return true
			}
		}
	}
	return false
}

// extractClientIP extracts the client IP from the request
func (rl *RateLimiter) extractClientIP(r *http.Request) string {
	// If configured to trust proxy headers, check them first
	if rl.config.TrustProxyHeaders {
		// Check X-Forwarded-For header
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the chain
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Check CF-Connecting-IP header (Cloudflare)
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}

		// Check X-Real-IP header
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkRateLimits checks if a request violates any rate limits
func (rl *RateLimiter) checkRateLimits(ip string, r *http.Request) (bool, string) {
	ctx := context.Background()

	// Get metrics from backend
	metrics, err := rl.backend.GetMetrics(ctx, ip)
	if err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to get metrics")
		return false, "" // Allow request on backend error
	}

	now := time.Now()

	// Check if IP is banned
	ban, err := rl.backend.GetBan(ctx, ip)
	if err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to get ban status")
	} else if ban != nil && now.Before(ban.ExpiresAt) {
		return true, fmt.Sprintf("IP banned until %s: %s",
			ban.ExpiresAt.Format(time.RFC3339), ban.Reason)
	}

	// Check concurrent connections
	if metrics.Connections.Count >= rl.config.MaxConcurrentConnections {
		return true, fmt.Sprintf("Too many concurrent connections (%d >= %d)",
			metrics.Connections.Count, rl.config.MaxConcurrentConnections)
	}

	// Check connection rate (per 3 seconds)
	connectionRate := rl.countRecent(metrics.Connections.Rate, 3*time.Second)
	if connectionRate >= rl.config.ConnectionRate {
		return true, fmt.Sprintf("Connection rate exceeded (%d >= %d per 3s)",
			connectionRate, rl.config.ConnectionRate)
	}

	// Check HTTP request rate (per 10 seconds)
	requestRate := rl.countRecent(metrics.Requests.Requests, 10*time.Second)
	if requestRate >= rl.config.HTTPRequestRate {
		return true, fmt.Sprintf("Request rate exceeded (%d >= %d per 10s)",
			requestRate, rl.config.HTTPRequestRate)
	}

	// Check HTTP error rate (per 5 minutes)
	errorRate := rl.countRecent(metrics.Requests.Errors, 5*time.Minute)
	if errorRate >= rl.config.HTTPErrorRate {
		// Ban for crawler block duration
		return true, fmt.Sprintf("Error rate exceeded (%d >= %d per 5m)",
			errorRate, rl.config.HTTPErrorRate)
	}

	// Check Tor-specific limits
	if rl.config.Tor.Enabled && rl.isTorExit(ip) {
		return rl.checkTorLimits(ip, r, metrics)
	}

	return false, ""
}

// checkTorLimits applies enhanced rate limiting for Tor exit nodes
func (rl *RateLimiter) checkTorLimits(ip string, r *http.Request, metrics *IPMetrics) (bool, string) {
	// Only apply Tor-specific limits to POST /pks/add requests
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/pks/add") {
		// Check Tor concurrent connections
		if metrics.Connections.Count >= rl.config.Tor.MaxConcurrentConnections {
			return true, fmt.Sprintf("Tor exit: too many concurrent connections (%d >= %d)",
				metrics.Connections.Count, rl.config.Tor.MaxConcurrentConnections)
		}

		// Check Tor connection rate (per connectionRateWindow)
		torConnRate := rl.countRecent(metrics.Connections.Rate, rl.config.Tor.ConnectionRateWindow)
		if torConnRate >= rl.config.Tor.ConnectionRate {
			return true, fmt.Sprintf("Tor exit: connection rate exceeded (%d >= %d per %v)",
				torConnRate, rl.config.Tor.ConnectionRate, rl.config.Tor.ConnectionRateWindow)
		}

		// Count requests per connection (simplified as recent requests)
		recentRequests := rl.countRecent(metrics.Requests.Requests, time.Minute)
		if recentRequests >= rl.config.Tor.MaxRequestsPerConnection {
			return true, fmt.Sprintf("Tor exit: too many requests per connection (%d >= %d)",
				recentRequests, rl.config.Tor.MaxRequestsPerConnection)
		}
	}

	return false, ""
}

// countRecent counts events within a time window
func (rl *RateLimiter) countRecent(events []time.Time, window time.Duration) int {
	cutoff := time.Now().Add(-window)
	count := 0
	for _, t := range events {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// trackRequest records a new HTTP request
func (rl *RateLimiter) trackRequest(ip string, r *http.Request) {
	ctx := context.Background()
	now := time.Now()

	// Increment connections and add request
	if err := rl.backend.IncrementConnections(ctx, ip, now); err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to increment connections")
	}

	if err := rl.backend.AddRequest(ctx, ip, now); err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to add request")
	}
}

// trackError records an HTTP error response
func (rl *RateLimiter) trackError(ip string, r *http.Request) {
	ctx := context.Background()
	now := time.Now()

	if err := rl.backend.AddError(ctx, ip, now); err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to add error")
		return
	}

	// Check if we should ban for excessive errors
	metrics, err := rl.backend.GetMetrics(ctx, ip)
	if err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to get metrics for error check")
		return
	}

	errorRate := rl.countRecent(metrics.Requests.Errors, 5*time.Minute)
	if errorRate >= rl.config.HTTPErrorRate {
		rl.banIP(ip, "Excessive HTTP errors", false)
	}
}

// recordViolation logs a rate limit violation and potentially bans the IP
func (rl *RateLimiter) recordViolation(ip string, r *http.Request, reason string) {
	log.WithFields(log.Fields{
		"client_ip":  ip,
		"method":     r.Method,
		"path":       r.URL.Path,
		"reason":     reason,
		"user_agent": r.UserAgent(),
	}).Warn("Rate limit violation")

	isTorExit := rl.isTorExit(ip)

	// Apply bans for certain violations
	if strings.Contains(reason, "rate exceeded") || strings.Contains(reason, "too many") {
		rl.banIP(ip, reason, isTorExit)
	}
}

// banIP bans an IP address
func (rl *RateLimiter) banIP(ip string, reason string, isTorExit bool) {
	ctx := context.Background()
	now := time.Now()

	// Determine ban duration
	duration := rl.determineBanDuration(ip, isTorExit, reason)

	ban := &BanRecord{
		BannedAt:  now,
		ExpiresAt: now.Add(duration),
		Reason:    reason,
		IsTorExit: isTorExit,
	}

	// For Tor exits, increment offense count for escalating bans
	if isTorExit {
		// Get current ban to check offense count
		if currentBan, err := rl.backend.GetBan(ctx, ip); err == nil && currentBan != nil {
			ban.OffenseCount = currentBan.OffenseCount + 1
		} else {
			ban.OffenseCount = 1
		}

		// Recalculate duration based on offense count
		if ban.OffenseCount > 1 {
			ban.ExpiresAt = now.Add(rl.config.Tor.RepeatOffenderBanDuration)
		}
	}

	if err := rl.backend.SetBan(ctx, ip, ban); err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to set ban")
		return
	}

	log.WithFields(log.Fields{
		"ip":            ip,
		"reason":        reason,
		"duration":      duration,
		"expires_at":    ban.ExpiresAt,
		"is_tor":        isTorExit,
		"offense_count": ban.OffenseCount,
	}).Warn("IP banned")
}

// determineBanDuration determines the appropriate ban duration based on IP history and type
func (rl *RateLimiter) determineBanDuration(ip string, isTorExit bool, reason string) time.Duration {
	if isTorExit {
		// Tor exits get longer bans, escalating for repeat offenders
		return rl.config.Tor.BanDuration
	}

	// Regular bans get crawler block duration
	return rl.config.CrawlerBlockDuration
}

// determineBanType determines the ban classification for HAProxy processing
func (rl *RateLimiter) determineBanType(ip string, isTorExit bool, reason string) string {
	if isTorExit {
		return "tor"
	}

	if strings.Contains(reason, "connection") {
		return "connection"
	}

	if strings.Contains(reason, "request") {
		return "request"
	}

	if strings.Contains(reason, "error") {
		return "crawler"
	}

	return "general"
}

// GetRateLimitStats returns current rate limiting statistics
func (rl *RateLimiter) GetRateLimitStats() map[string]interface{} {
	ctx := context.Background()

	stats, err := rl.backend.GetStats(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get backend stats")
		return map[string]interface{}{
			"enabled":      rl.config.Enabled,
			"backend_type": "unknown",
			"error":        err.Error(),
		}
	}

	result := map[string]interface{}{
		"enabled":      rl.config.Enabled,
		"tracked_ips":  stats.TrackedIPs,
		"banned_ips":   stats.BannedIPs,
		"tor_banned":   stats.TorBannedIPs,
		"backend_type": stats.BackendType,
	}

	// Add backend-specific info
	for k, v := range stats.BackendInfo {
		result[k] = v
	}

	// Add Tor stats if enabled
	if rl.config.Tor.Enabled {
		// Always get Tor stats from backend
		if torStats, err := rl.backend.GetTorStats(ctx); err == nil {
			result["tor_exits_count"] = torStats.Count
			result["tor_last_updated"] = torStats.LastUpdated
		}
	}

	return result
}
