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
	"fmt"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

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
			if rl.config.Headers.Enabled {
				if isTor, err := rl.isTorExit(clientIP); err != nil {
					log.WithError(err).WithField("client_ip", clientIP).Debug("Failed to check Tor exit status for header")
				} else if isTor {
					w.Header().Set(rl.config.Headers.TorHeader, "true")
				}
			}

			// Check if IP is whitelisted
			if rl.isWhitelisted(clientIP) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if IP is a recon peer
			if rl.isReconPeer(clientIP) {
				next.ServeHTTP(w, r)
				return
			}

			// Check rate limits
			violated, reason := rl.checkRateLimits(clientIP, r)
			if violated {
				// Record the violation
				rl.recordViolation(clientIP, r, reason)

				// Set ban headers if enabled
				if rl.config.Headers.Enabled {
					isTor, err := rl.isTorExit(clientIP)
					if err != nil {
						log.WithError(err).WithField("client_ip", clientIP).Debug("Failed to check Tor exit status for ban headers")
						isTor = false // Default to false on error
					}

					duration := rl.determineBanDuration(clientIP, isTor, reason)
					banType := rl.determineBanType(clientIP, isTor, reason)

					w.Header().Set(rl.config.Headers.BanHeader, formatDuration(duration))
					w.Header().Set(rl.config.Headers.BanHeader+"-Reason", reason)
					w.Header().Set(rl.config.Headers.BanHeader+"-Type", banType)
				}

				// Return 429 Too Many Requests
				http.Error(w, fmt.Sprintf("Rate limit exceeded: %s", reason), http.StatusTooManyRequests)
				return
			}

			// Track the request
			if err := rl.trackRequest(clientIP, r); err != nil {
				log.WithError(err).WithField("client_ip", clientIP).Error("Failed to track request")
			}

			// Wrap response writer to capture status code
			wrapper := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapper, r)

			// Track errors (4xx and 5xx responses)
			if wrapper.statusCode >= 400 {
				if err := rl.trackError(clientIP, r); err != nil {
					log.WithError(err).WithField("client_ip", clientIP).Error("Failed to track error")
				}
			}

			// Decrement connection count on completion
			ctx := r.Context()
			go func() {
				<-ctx.Done()
				if err := rl.backend.DecrementConnections(ctx, clientIP); err != nil {
					log.WithError(err).WithField("ip", clientIP).Error("Failed to decrement connections")
				}
			}()
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

// formatDuration formats a duration for headers (e.g., "30m", "2h", "1d")
func formatDuration(d time.Duration) string {
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	} else if d < 24*time.Hour {
		return strconv.Itoa(int(d.Hours())) + "h"
	} else {
		return strconv.Itoa(int(d.Hours()/24)) + "d"
	}
}
