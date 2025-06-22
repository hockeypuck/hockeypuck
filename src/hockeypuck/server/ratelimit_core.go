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
	"time"

	log "github.com/sirupsen/logrus"
)

// extractClientIP extracts the real client IP from the request
func (rl *RateLimiter) extractClientIP(r *http.Request) string {
	if rl.config.TrustProxyHeaders {
		// Check CF-Connecting-IP first (Cloudflare)
		if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
			if net.ParseIP(ip) != nil {
				return ip
			}
		}

		// Check X-Forwarded-For header
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP from the comma-separated list
			if ips := strings.Split(xff, ","); len(ips) > 0 {
				if ip := strings.TrimSpace(ips[0]); ip != "" {
					if net.ParseIP(ip) != nil {
						return ip
					}
				}
			}
		}
	}

	// Fall back to connection source IP
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Might be just IP without port
	}
	return host
}

// isWhitelisted checks if an IP is in the whitelist
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	for _, ipnet := range rl.whitelists {
		if ipnet.Contains(clientIP) {
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

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	// Get current partners from the recon peer
	partners := rl.partnerProvider.CurrentPartners()

	for _, partner := range partners {
		// Check against resolved IPs for this partner
		for _, partnerIP := range partner.IPs {
			if partnerIP.Equal(clientIP) {
				return true
			}
		}

		// Also check against the recon address hostname resolution
		if partner.ReconAddr != "" {
			host, _, err := net.SplitHostPort(partner.ReconAddr)
			if err == nil {
				// Try to resolve hostname to IPs
				ips, err := net.LookupIP(host)
				if err == nil {
					for _, resolvedIP := range ips {
						if resolvedIP.Equal(clientIP) {
							return true
						}
					}
				}
			}
		}

		// Also check against the HTTP address hostname resolution
		if partner.HTTPAddr != "" {
			host, _, err := net.SplitHostPort(partner.HTTPAddr)
			if err == nil {
				// Try to resolve hostname to IPs
				ips, err := net.LookupIP(host)
				if err == nil {
					for _, resolvedIP := range ips {
						if resolvedIP.Equal(clientIP) {
							return true
						}
					}
				}
			}
		}
	}

	return false
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

	// Record metrics
	recordRateLimitViolation(reason, isTorExit)

	// Apply bans for certain violations
	if strings.Contains(reason, "rate exceeded") || strings.Contains(reason, "too many") {
		rl.banIP(ip, reason, isTorExit)
	}
}

// banIP bans an IP address
func (rl *RateLimiter) banIP(ip string, reason string, isTorExit bool) {
	ctx := context.Background()
	now := time.Now()

	// Check for existing ban to get offense count
	offenseCount := 1
	if existingBan, err := rl.backend.GetBan(ctx, ip); err == nil && existingBan != nil {
		offenseCount = existingBan.OffenseCount + 1
	}

	duration := rl.determineBanDuration(ip, isTorExit, reason)
	banType := rl.determineBanType(ip, isTorExit, reason)
	formattedDuration := rl.formatBanDuration(duration)

	newBan := &BanRecord{
		BannedAt:     now,
		ExpiresAt:    now.Add(duration),
		Reason:       reason,
		IsTorExit:    isTorExit,
		OffenseCount: offenseCount,
	}

	if err := rl.backend.SetBan(ctx, ip, newBan); err != nil {
		log.WithError(err).WithField("ip", ip).Error("Failed to set ban")
	}

	log.WithFields(log.Fields{
		"client_ip":  ip,
		"reason":     reason,
		"expires_at": now.Add(duration),
		"duration":   formattedDuration,
		"is_tor":     isTorExit,
		"ban_type":   banType,
	}).Warn("IP banned")
}

// determineBanDuration determines the appropriate ban duration based on IP history and type
func (rl *RateLimiter) determineBanDuration(ip string, isTorExit bool, reason string) time.Duration {
	ctx := context.Background()

	// For Tor exits, use configured Tor ban durations with escalation
	if isTorExit {
		if ban, err := rl.backend.GetBan(ctx, ip); err == nil && ban != nil {
			// Repeat Tor offender - use longer ban duration
			if ban.OffenseCount > 0 {
				return rl.config.Tor.RepeatOffenderBanDuration
			}
		}
		// First-time Tor offender
		return rl.config.Tor.BanDuration
	}

	// For regular IPs, use escalating ban durations based on violation type
	if strings.Contains(reason, "Error rate exceeded") {
		// Crawler behavior - use crawler block duration
		return rl.config.CrawlerBlockDuration
	}

	// Connection or request rate violations - start with short bans
	if ban, err := rl.backend.GetBan(ctx, ip); err == nil && ban != nil {
		// Escalate bans for repeat offenders
		switch ban.OffenseCount {
		case 0:
			return 30 * time.Minute // First offense: 30 minutes
		case 1:
			return 2 * time.Hour // Second offense: 2 hours
		case 2:
			return 8 * time.Hour // Third offense: 8 hours
		default:
			return 24 * time.Hour // Persistent offenders: 24 hours
		}
	}

	// First-time regular offender
	return 30 * time.Minute
}

// determineBanType determines the ban classification for HAProxy processing
func (rl *RateLimiter) determineBanType(ip string, isTorExit bool, reason string) string {
	if isTorExit {
		return "tor"
	}

	if strings.Contains(reason, "Error rate exceeded") {
		return "crawler"
	}

	if strings.Contains(reason, "Connection rate exceeded") ||
		strings.Contains(reason, "concurrent connections") {
		return "connection"
	}

	if strings.Contains(reason, "Request rate exceeded") {
		return "request"
	}

	return "general"
}

// formatBanDuration formats a duration for HAProxy consumption (e.g., "30m", "2h", "24h")
func (rl *RateLimiter) formatBanDuration(duration time.Duration) string {
	if duration < time.Hour {
		return fmt.Sprintf("%.0fm", duration.Minutes())
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%.0fh", duration.Hours())
	}
	return fmt.Sprintf("%.0fd", duration.Hours()/24)
}

// isTorExit checks if an IP is a known Tor exit node
func (rl *RateLimiter) isTorExit(ip string) bool {
	if rl.config.Tor.UseBackendStorage {
		// Check backend first
		ctx := context.Background()
		if isTor, err := rl.backend.IsTorExit(ctx, ip); err == nil {
			return isTor
		}
		// Fall back to local cache on error
	}

	// Check local memory cache
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.torExits[ip]
}

// startCleanupTask starts a background task to clean up stale metrics
func (rl *RateLimiter) startCleanupTask() {
	rl.cleanupTicker = time.NewTicker(5 * time.Minute)

	go func() {
		for {
			select {
			case <-rl.cleanupTicker.C:
				rl.cleanup()
			case <-rl.ctx.Done():
				return
			}
		}
	}()
}

// cleanup removes stale IP metrics
func (rl *RateLimiter) cleanup() {
	ctx := context.Background()
	staleThreshold := time.Now().Add(-time.Hour) // Remove metrics older than 1 hour

	if err := rl.backend.Cleanup(ctx, staleThreshold); err != nil {
		log.WithError(err).Error("Failed to cleanup backend metrics")
		return
	}

	// Update Prometheus metrics
	stats, err := rl.backend.GetStats(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get backend stats for metrics")
		return
	}

	updateRateLimitStats(stats.TrackedIPs, stats.BannedIPs-stats.TorBannedIPs, stats.TorBannedIPs)

	log.WithField("active_ips", stats.TrackedIPs).Debug("Rate limiter cleanup completed")
}
