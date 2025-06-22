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
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisBackend implements MetricsBackend using Redis
type RedisBackend struct {
	client    *redis.Client
	keyPrefix string
	ttl       time.Duration
}

// NewRedisBackend creates a new Redis backend
func NewRedisBackend(config *RedisBackendConfig) (*RedisBackend, error) {
	if config == nil {
		config = DefaultMetricsBackendConfig().Redis
	}

	client := redis.NewClient(&redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisBackend{
		client:    client,
		keyPrefix: config.KeyPrefix,
		ttl:       config.TTL,
	}, nil
}

// Redis key patterns
func (rb *RedisBackend) ipKey(ip string) string {
	return rb.keyPrefix + "ip:" + ip
}

func (rb *RedisBackend) banKey(ip string) string {
	return rb.keyPrefix + "ban:" + ip
}

func (rb *RedisBackend) connectionsKey(ip string) string {
	return rb.keyPrefix + "conn:" + ip
}

func (rb *RedisBackend) requestsKey(ip string) string {
	return rb.keyPrefix + "req:" + ip
}

func (rb *RedisBackend) errorsKey(ip string) string {
	return rb.keyPrefix + "err:" + ip
}

func (rb *RedisBackend) allBansKey() string {
	return rb.keyPrefix + "bans"
}

// GetMetrics retrieves metrics for an IP address
func (rb *RedisBackend) GetMetrics(ctx context.Context, ip string) (*IPMetrics, error) {
	pipe := rb.client.Pipeline()

	// Get basic metrics
	ipCmd := pipe.HGetAll(ctx, rb.ipKey(ip))
	banCmd := pipe.HGetAll(ctx, rb.banKey(ip))

	// Get time-series data
	connRateCmd := pipe.LRange(ctx, rb.connectionsKey(ip), 0, -1)
	requestsCmd := pipe.LRange(ctx, rb.requestsKey(ip), 0, -1)
	errorsCmd := pipe.LRange(ctx, rb.errorsKey(ip), 0, -1)

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get metrics for IP %s: %w", ip, err)
	}

	metrics := &IPMetrics{}

	// Parse basic metrics
	ipData := ipCmd.Val()
	if countStr := ipData["conn_count"]; countStr != "" {
		if count, err := strconv.Atoi(countStr); err == nil {
			metrics.Connections.Count = count
		}
	}
	if lastSeenStr := ipData["conn_last_seen"]; lastSeenStr != "" {
		if lastSeen, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
			metrics.Connections.LastSeen = lastSeen
		}
	}
	if lastSeenStr := ipData["req_last_seen"]; lastSeenStr != "" {
		if lastSeen, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
			metrics.Requests.LastSeen = lastSeen
		}
	}

	// Parse ban data
	banData := banCmd.Val()
	if len(banData) > 0 {
		ban := &BanRecord{}
		if bannedAtStr := banData["banned_at"]; bannedAtStr != "" {
			if bannedAt, err := time.Parse(time.RFC3339, bannedAtStr); err == nil {
				ban.BannedAt = bannedAt
			}
		}
		if expiresAtStr := banData["expires_at"]; expiresAtStr != "" {
			if expiresAt, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
				ban.ExpiresAt = expiresAt
			}
		}
		ban.Reason = banData["reason"]
		if isTorStr := banData["is_tor"]; isTorStr == "true" {
			ban.IsTorExit = true
		}
		if offenseCountStr := banData["offense_count"]; offenseCountStr != "" {
			if count, err := strconv.Atoi(offenseCountStr); err == nil {
				ban.OffenseCount = count
			}
		}

		// Only set ban if it hasn't expired
		if time.Now().Before(ban.ExpiresAt) {
			metrics.Ban = ban
		}
	}

	// Parse time-series data
	metrics.Connections.Rate = rb.parseTimeList(connRateCmd.Val())
	metrics.Requests.Requests = rb.parseTimeList(requestsCmd.Val())
	metrics.Requests.Errors = rb.parseTimeList(errorsCmd.Val())

	return metrics, nil
}

// SetMetrics stores metrics for an IP address
func (rb *RedisBackend) SetMetrics(ctx context.Context, ip string, metrics *IPMetrics) error {
	pipe := rb.client.Pipeline()

	// Store basic metrics
	ipData := map[string]interface{}{
		"conn_count":     metrics.Connections.Count,
		"conn_last_seen": metrics.Connections.LastSeen.Format(time.RFC3339),
		"req_last_seen":  metrics.Requests.LastSeen.Format(time.RFC3339),
	}

	pipe.HMSet(ctx, rb.ipKey(ip), ipData)
	pipe.Expire(ctx, rb.ipKey(ip), rb.ttl)

	// Store time-series data
	rb.storeTimeList(ctx, pipe, rb.connectionsKey(ip), metrics.Connections.Rate)
	rb.storeTimeList(ctx, pipe, rb.requestsKey(ip), metrics.Requests.Requests)
	rb.storeTimeList(ctx, pipe, rb.errorsKey(ip), metrics.Requests.Errors)

	// Store ban if exists
	if metrics.Ban != nil {
		banData := map[string]interface{}{
			"banned_at":     metrics.Ban.BannedAt.Format(time.RFC3339),
			"expires_at":    metrics.Ban.ExpiresAt.Format(time.RFC3339),
			"reason":        metrics.Ban.Reason,
			"is_tor":        strconv.FormatBool(metrics.Ban.IsTorExit),
			"offense_count": metrics.Ban.OffenseCount,
		}

		pipe.HMSet(ctx, rb.banKey(ip), banData)
		pipe.Expire(ctx, rb.banKey(ip), rb.ttl)
		pipe.SAdd(ctx, rb.allBansKey(), ip)
		pipe.Expire(ctx, rb.allBansKey(), rb.ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// UpdateMetrics atomically updates metrics for an IP address
func (rb *RedisBackend) UpdateMetrics(ctx context.Context, ip string, updateFn func(*IPMetrics) *IPMetrics) error {
	// Redis transactions for atomic updates
	err := rb.client.Watch(ctx, func(tx *redis.Tx) error {
		// Get current metrics
		current, err := rb.GetMetrics(ctx, ip)
		if err != nil {
			return err
		}

		// Apply update function
		updated := updateFn(current)

		// Store updated metrics
		return rb.SetMetrics(ctx, ip, updated)
	}, rb.ipKey(ip), rb.banKey(ip))

	return err
}

// IncrementConnections atomically increments connection count and rate
func (rb *RedisBackend) IncrementConnections(ctx context.Context, ip string, timestamp time.Time) error {
	pipe := rb.client.Pipeline()

	// Increment connection count
	pipe.HIncrBy(ctx, rb.ipKey(ip), "conn_count", 1)
	pipe.HSet(ctx, rb.ipKey(ip), "conn_last_seen", timestamp.Format(time.RFC3339))
	pipe.Expire(ctx, rb.ipKey(ip), rb.ttl)

	// Add to connection rate list
	pipe.LPush(ctx, rb.connectionsKey(ip), timestamp.Format(time.RFC3339))
	pipe.LTrim(ctx, rb.connectionsKey(ip), 0, 99) // Keep last 100 entries
	pipe.Expire(ctx, rb.connectionsKey(ip), rb.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// DecrementConnections atomically decrements connection count
func (rb *RedisBackend) DecrementConnections(ctx context.Context, ip string) error {
	// Use Lua script for atomic decrement with min 0
	script := `
		local count = redis.call('HGET', KEYS[1], 'conn_count')
		if count and tonumber(count) > 0 then
			return redis.call('HINCRBY', KEYS[1], 'conn_count', -1)
		end
		return 0
	`

	return rb.client.Eval(ctx, script, []string{rb.ipKey(ip)}).Err()
}

// AddRequest adds a request timestamp to the metrics
func (rb *RedisBackend) AddRequest(ctx context.Context, ip string, timestamp time.Time) error {
	pipe := rb.client.Pipeline()

	// Update last seen
	pipe.HSet(ctx, rb.ipKey(ip), "req_last_seen", timestamp.Format(time.RFC3339))
	pipe.Expire(ctx, rb.ipKey(ip), rb.ttl)

	// Add to requests list
	pipe.LPush(ctx, rb.requestsKey(ip), timestamp.Format(time.RFC3339))
	pipe.LTrim(ctx, rb.requestsKey(ip), 0, 199) // Keep last 200 entries
	pipe.Expire(ctx, rb.requestsKey(ip), rb.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// AddError adds an error timestamp to the metrics
func (rb *RedisBackend) AddError(ctx context.Context, ip string, timestamp time.Time) error {
	pipe := rb.client.Pipeline()

	// Add to errors list
	pipe.LPush(ctx, rb.errorsKey(ip), timestamp.Format(time.RFC3339))
	pipe.LTrim(ctx, rb.errorsKey(ip), 0, 99) // Keep last 100 entries
	pipe.Expire(ctx, rb.errorsKey(ip), rb.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// SetBan sets a ban record for an IP
func (rb *RedisBackend) SetBan(ctx context.Context, ip string, ban *BanRecord) error {
	pipe := rb.client.Pipeline()

	banData := map[string]interface{}{
		"banned_at":     ban.BannedAt.Format(time.RFC3339),
		"expires_at":    ban.ExpiresAt.Format(time.RFC3339),
		"reason":        ban.Reason,
		"is_tor":        strconv.FormatBool(ban.IsTorExit),
		"offense_count": ban.OffenseCount,
	}

	pipe.HMSet(ctx, rb.banKey(ip), banData)
	pipe.Expire(ctx, rb.banKey(ip), rb.ttl)
	pipe.SAdd(ctx, rb.allBansKey(), ip)
	pipe.Expire(ctx, rb.allBansKey(), rb.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// GetBan retrieves ban information for an IP
func (rb *RedisBackend) GetBan(ctx context.Context, ip string) (*BanRecord, error) {
	banData, err := rb.client.HGetAll(ctx, rb.banKey(ip)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	if len(banData) == 0 {
		return nil, nil
	}

	ban := &BanRecord{}
	if bannedAtStr := banData["banned_at"]; bannedAtStr != "" {
		if bannedAt, err := time.Parse(time.RFC3339, bannedAtStr); err == nil {
			ban.BannedAt = bannedAt
		}
	}
	if expiresAtStr := banData["expires_at"]; expiresAtStr != "" {
		if expiresAt, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
			ban.ExpiresAt = expiresAt
		}
	}
	ban.Reason = banData["reason"]
	if isTorStr := banData["is_tor"]; isTorStr == "true" {
		ban.IsTorExit = true
	}
	if offenseCountStr := banData["offense_count"]; offenseCountStr != "" {
		if count, err := strconv.Atoi(offenseCountStr); err == nil {
			ban.OffenseCount = count
		}
	}

	// Check if ban has expired
	if time.Now().After(ban.ExpiresAt) {
		// Clean up expired ban
		rb.client.Del(ctx, rb.banKey(ip))
		rb.client.SRem(ctx, rb.allBansKey(), ip)
		return nil, nil
	}

	return ban, nil
}

// RemoveBan removes a ban for an IP
func (rb *RedisBackend) RemoveBan(ctx context.Context, ip string) error {
	pipe := rb.client.Pipeline()
	pipe.Del(ctx, rb.banKey(ip))
	pipe.SRem(ctx, rb.allBansKey(), ip)
	_, err := pipe.Exec(ctx)
	return err
}

// GetAllBannedIPs returns all currently banned IPs
func (rb *RedisBackend) GetAllBannedIPs(ctx context.Context) ([]string, error) {
	ips, err := rb.client.SMembers(ctx, rb.allBansKey()).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, err
	}

	// Filter out expired bans
	var activeBans []string
	for _, ip := range ips {
		ban, err := rb.GetBan(ctx, ip)
		if err != nil {
			continue
		}
		if ban != nil {
			activeBans = append(activeBans, ip)
		}
	}

	return activeBans, nil
}

// GetStats returns backend statistics
func (rb *RedisBackend) GetStats(ctx context.Context) (BackendStats, error) {
	pipe := rb.client.Pipeline()

	// Get Redis info
	infoCmd := pipe.Info(ctx, "memory")
	dbSizeCmd := pipe.DBSize(ctx)
	bannedIPsCmd := pipe.SCard(ctx, rb.allBansKey())

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return BackendStats{}, err
	}

	// Count tracked IPs by scanning keys
	var trackedIPs int
	iter := rb.client.Scan(ctx, 0, rb.keyPrefix+"ip:*", 0).Iterator()
	for iter.Next(ctx) {
		trackedIPs++
	}

	// Count Tor banned IPs
	bannedIPs, _ := rb.GetAllBannedIPs(ctx)
	var torBannedCount int
	for _, ip := range bannedIPs {
		ban, err := rb.GetBan(ctx, ip)
		if err == nil && ban != nil && ban.IsTorExit {
			torBannedCount++
		}
	}

	backendInfo := map[string]interface{}{
		"redis_db_size": dbSizeCmd.Val(),
		"redis_info":    rb.parseRedisInfo(infoCmd.Val()),
	}

	return BackendStats{
		TrackedIPs:   trackedIPs,
		BannedIPs:    int(bannedIPsCmd.Val()),
		TorBannedIPs: torBannedCount,
		BackendType:  "redis",
		BackendInfo:  backendInfo,
	}, nil
}

// Cleanup removes stale metrics
func (rb *RedisBackend) Cleanup(ctx context.Context, staleThreshold time.Time) error {
	// Redis handles TTL automatically, but we can clean up explicitly
	iter := rb.client.Scan(ctx, 0, rb.keyPrefix+"ip:*", 0).Iterator()

	for iter.Next(ctx) {
		key := iter.Val()
		ip := strings.TrimPrefix(key, rb.keyPrefix+"ip:")

		metrics, err := rb.GetMetrics(ctx, ip)
		if err != nil {
			continue
		}

		// Check if stale
		isStale := metrics.Connections.LastSeen.Before(staleThreshold) &&
			metrics.Requests.LastSeen.Before(staleThreshold)

		// Don't remove if banned
		if metrics.Ban != nil && time.Now().Before(metrics.Ban.ExpiresAt) {
			isStale = false
		}

		if isStale {
			// Delete all keys for this IP
			pipe := rb.client.Pipeline()
			pipe.Del(ctx, rb.ipKey(ip))
			pipe.Del(ctx, rb.connectionsKey(ip))
			pipe.Del(ctx, rb.requestsKey(ip))
			pipe.Del(ctx, rb.errorsKey(ip))
			pipe.Del(ctx, rb.banKey(ip))
			pipe.SRem(ctx, rb.allBansKey(), ip)
			pipe.Exec(ctx)
		}
	}

	return iter.Err()
}

// Close closes the Redis connection
func (rb *RedisBackend) Close() error {
	return rb.client.Close()
}

// Tor Backend Implementation

// torExitKey returns the Redis key for Tor exit nodes set
func (rb *RedisBackend) torExitKey() string {
	return rb.keyPrefix + "tor:exits"
}

// torStatsKey returns the Redis key for Tor statistics
func (rb *RedisBackend) torStatsKey() string {
	return rb.keyPrefix + "tor:stats"
}

// StoreTorExits stores the Tor exit node list in Redis
func (rb *RedisBackend) StoreTorExits(ctx context.Context, exits map[string]bool) error {
	pipe := rb.client.Pipeline()

	// Clear existing set
	pipe.Del(ctx, rb.torExitKey())

	// Add all Tor exit IPs to set
	if len(exits) > 0 {
		ips := make([]interface{}, 0, len(exits))
		for ip := range exits {
			ips = append(ips, ip)
		}
		pipe.SAdd(ctx, rb.torExitKey(), ips...)
	}

	// Set TTL
	pipe.Expire(ctx, rb.torExitKey(), rb.ttl)

	// Store update timestamp and count
	stats := map[string]interface{}{
		"count":        len(exits),
		"last_updated": time.Now().Format(time.RFC3339),
	}
	pipe.HMSet(ctx, rb.torStatsKey(), stats)
	pipe.Expire(ctx, rb.torStatsKey(), rb.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// LoadTorExits loads the Tor exit node list from Redis
func (rb *RedisBackend) LoadTorExits(ctx context.Context) (map[string]bool, error) {
	ips, err := rb.client.SMembers(ctx, rb.torExitKey()).Result()
	if err != nil && err != redis.Nil {
		return nil, err
	}

	exits := make(map[string]bool)
	for _, ip := range ips {
		exits[ip] = true
	}

	return exits, nil
}

// IsTorExit checks if an IP is a Tor exit node
func (rb *RedisBackend) IsTorExit(ctx context.Context, ip string) (bool, error) {
	result, err := rb.client.SIsMember(ctx, rb.torExitKey(), ip).Result()
	if err != nil && err != redis.Nil {
		return false, err
	}
	return result, nil
}

// GetTorStats returns Tor exit statistics
func (rb *RedisBackend) GetTorStats(ctx context.Context) (TorStats, error) {
	statsData, err := rb.client.HGetAll(ctx, rb.torStatsKey()).Result()
	if err != nil && err != redis.Nil {
		return TorStats{}, err
	}

	stats := TorStats{
		TTL: rb.ttl,
	}

	if countStr := statsData["count"]; countStr != "" {
		if count, err := strconv.Atoi(countStr); err == nil {
			stats.Count = count
		}
	}

	if lastUpdatedStr := statsData["last_updated"]; lastUpdatedStr != "" {
		if lastUpdated, err := time.Parse(time.RFC3339, lastUpdatedStr); err == nil {
			stats.LastUpdated = lastUpdated
		}
	}

	return stats, nil
}

// Helper functions
func (rb *RedisBackend) parseTimeList(timeStrings []string) []time.Time {
	times := make([]time.Time, 0, len(timeStrings))
	for _, timeStr := range timeStrings {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			times = append(times, t)
		}
	}
	return times
}

func (rb *RedisBackend) storeTimeList(ctx context.Context, pipe redis.Pipeliner, key string, times []time.Time) {
	if len(times) == 0 {
		return
	}

	// Clear existing list and add new times
	pipe.Del(ctx, key)
	timeStrings := make([]interface{}, len(times))
	for i, t := range times {
		timeStrings[i] = t.Format(time.RFC3339)
	}
	pipe.LPush(ctx, key, timeStrings...)
	pipe.Expire(ctx, key, rb.ttl)
}

func (rb *RedisBackend) parseRedisInfo(info string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(info, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}
	return result
}
