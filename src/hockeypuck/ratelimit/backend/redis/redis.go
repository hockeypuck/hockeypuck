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

package redis

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"hockeypuck/ratelimit/types"
)

// Backend implements backend.Backend using Redis
type Backend struct {
	client    *redis.Client
	keyPrefix string
	ttl       time.Duration
}

// New creates a new Redis backend
func New(config *types.BackendConfig) (*Backend, error) {
	if config == nil {
		return nil, fmt.Errorf("Backend configuration is required")
	}

	client := redis.NewClient(&redis.Options{
		Addr:         config.Redis.Addr,
		Password:     config.Redis.Password,
		DB:           config.Redis.DB,
		PoolSize:     config.Redis.PoolSize,
		DialTimeout:  config.Redis.DialTimeout,
		ReadTimeout:  config.Redis.ReadTimeout,
		WriteTimeout: config.Redis.WriteTimeout,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Backend{
		client:    client,
		keyPrefix: config.Redis.KeyPrefix,
		ttl:       config.Redis.TTL,
	}, nil
}

// Redis key patterns
func (b *Backend) ipKey(ip string) string {
	return b.keyPrefix + "ip:" + ip
}

func (b *Backend) banKey(ip string) string {
	return b.keyPrefix + "ban:" + ip
}

func (b *Backend) connectionsKey(ip string) string {
	return b.keyPrefix + "conn:" + ip
}

func (b *Backend) requestsKey(ip string) string {
	return b.keyPrefix + "req:" + ip
}

func (b *Backend) errorsKey(ip string) string {
	return b.keyPrefix + "err:" + ip
}

func (b *Backend) allBansKey() string {
	return b.keyPrefix + "bans"
}

// GetMetrics retrieves metrics for an IP address
func (b *Backend) GetMetrics(ctx context.Context, ip string) (*types.IPMetrics, error) {
	pipe := b.client.Pipeline()

	// Get basic metrics
	ipCmd := pipe.HGetAll(ctx, b.ipKey(ip))
	banCmd := pipe.HGetAll(ctx, b.banKey(ip))

	// Get time-series data
	connRateCmd := pipe.LRange(ctx, b.connectionsKey(ip), 0, -1)
	requestsCmd := pipe.LRange(ctx, b.requestsKey(ip), 0, -1)
	errorsCmd := pipe.LRange(ctx, b.errorsKey(ip), 0, -1)

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get metrics for IP %s: %w", ip, err)
	}

	metrics := &types.IPMetrics{}

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
		ban := &types.BanRecord{}
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
	metrics.Connections.Rate = b.parseTimeList(connRateCmd.Val())
	metrics.Requests.Requests = b.parseTimeList(requestsCmd.Val())
	metrics.Requests.Errors = b.parseTimeList(errorsCmd.Val())

	return metrics, nil
}

// SetMetrics stores metrics for an IP address
func (b *Backend) SetMetrics(ctx context.Context, ip string, metrics *types.IPMetrics) error {
	pipe := b.client.Pipeline()

	// Store basic metrics
	ipData := map[string]interface{}{
		"conn_count":     metrics.Connections.Count,
		"conn_last_seen": metrics.Connections.LastSeen.Format(time.RFC3339),
		"req_last_seen":  metrics.Requests.LastSeen.Format(time.RFC3339),
	}

	pipe.HMSet(ctx, b.ipKey(ip), ipData)
	pipe.Expire(ctx, b.ipKey(ip), b.ttl)

	// Store time-series data
	b.storeTimeList(ctx, pipe, b.connectionsKey(ip), metrics.Connections.Rate)
	b.storeTimeList(ctx, pipe, b.requestsKey(ip), metrics.Requests.Requests)
	b.storeTimeList(ctx, pipe, b.errorsKey(ip), metrics.Requests.Errors)

	// Store ban if exists
	if metrics.Ban != nil {
		banData := map[string]interface{}{
			"banned_at":     metrics.Ban.BannedAt.Format(time.RFC3339),
			"expires_at":    metrics.Ban.ExpiresAt.Format(time.RFC3339),
			"reason":        metrics.Ban.Reason,
			"is_tor":        strconv.FormatBool(metrics.Ban.IsTorExit),
			"offense_count": metrics.Ban.OffenseCount,
		}

		pipe.HMSet(ctx, b.banKey(ip), banData)
		pipe.Expire(ctx, b.banKey(ip), b.ttl)
		pipe.SAdd(ctx, b.allBansKey(), ip)
		pipe.Expire(ctx, b.allBansKey(), b.ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// UpdateMetrics atomically updates metrics for an IP address
func (b *Backend) UpdateMetrics(ctx context.Context, ip string, updateFn func(*types.IPMetrics) *types.IPMetrics) error {
	// Redis transactions for atomic updates
	err := b.client.Watch(ctx, func(tx *redis.Tx) error {
		// Get current metrics
		current, err := b.GetMetrics(ctx, ip)
		if err != nil {
			return err
		}

		// Apply update function
		updated := updateFn(current)

		// Store updated metrics
		return b.SetMetrics(ctx, ip, updated)
	}, b.ipKey(ip), b.banKey(ip))

	return err
}

// IncrementConnections atomically increments connection count and rate
func (b *Backend) IncrementConnections(ctx context.Context, ip string, timestamp time.Time) error {
	pipe := b.client.Pipeline()

	// Increment connection count
	pipe.HIncrBy(ctx, b.ipKey(ip), "conn_count", 1)
	pipe.HSet(ctx, b.ipKey(ip), "conn_last_seen", timestamp.Format(time.RFC3339))
	pipe.Expire(ctx, b.ipKey(ip), b.ttl)

	// Add to connection rate list
	pipe.LPush(ctx, b.connectionsKey(ip), timestamp.Format(time.RFC3339))
	pipe.LTrim(ctx, b.connectionsKey(ip), 0, 99) // Keep last 100 entries
	pipe.Expire(ctx, b.connectionsKey(ip), b.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// DecrementConnections atomically decrements connection count
func (b *Backend) DecrementConnections(ctx context.Context, ip string) error {
	// Use Lua script for atomic decrement with min 0
	script := `
		local count = redis.call('HGET', KEYS[1], 'conn_count')
		if count and tonumber(count) > 0 then
			return redis.call('HINCRBY', KEYS[1], 'conn_count', -1)
		end
		return 0
	`

	return b.client.Eval(ctx, script, []string{b.ipKey(ip)}).Err()
}

// AddRequest adds a request timestamp to the metrics
func (b *Backend) AddRequest(ctx context.Context, ip string, timestamp time.Time) error {
	pipe := b.client.Pipeline()

	// Update last seen
	pipe.HSet(ctx, b.ipKey(ip), "req_last_seen", timestamp.Format(time.RFC3339))
	pipe.Expire(ctx, b.ipKey(ip), b.ttl)

	// Add to requests list
	pipe.LPush(ctx, b.requestsKey(ip), timestamp.Format(time.RFC3339))
	pipe.LTrim(ctx, b.requestsKey(ip), 0, 199) // Keep last 200 entries
	pipe.Expire(ctx, b.requestsKey(ip), b.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// AddError adds an error timestamp to the metrics
func (b *Backend) AddError(ctx context.Context, ip string, timestamp time.Time) error {
	pipe := b.client.Pipeline()

	// Add to errors list
	pipe.LPush(ctx, b.errorsKey(ip), timestamp.Format(time.RFC3339))
	pipe.LTrim(ctx, b.errorsKey(ip), 0, 99) // Keep last 100 entries
	pipe.Expire(ctx, b.errorsKey(ip), b.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// SetBan sets a ban record for an IP
func (b *Backend) SetBan(ctx context.Context, ip string, ban *types.BanRecord) error {
	pipe := b.client.Pipeline()

	banData := map[string]interface{}{
		"banned_at":     ban.BannedAt.Format(time.RFC3339),
		"expires_at":    ban.ExpiresAt.Format(time.RFC3339),
		"reason":        ban.Reason,
		"is_tor":        strconv.FormatBool(ban.IsTorExit),
		"offense_count": ban.OffenseCount,
	}

	pipe.HMSet(ctx, b.banKey(ip), banData)
	pipe.Expire(ctx, b.banKey(ip), b.ttl)
	pipe.SAdd(ctx, b.allBansKey(), ip)
	pipe.Expire(ctx, b.allBansKey(), b.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// GetBan retrieves ban information for an IP
func (b *Backend) GetBan(ctx context.Context, ip string) (*types.BanRecord, error) {
	banData, err := b.client.HGetAll(ctx, b.banKey(ip)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	if len(banData) == 0 {
		return nil, nil
	}

	ban := &types.BanRecord{}
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
		b.client.Del(ctx, b.banKey(ip))
		b.client.SRem(ctx, b.allBansKey(), ip)
		return nil, nil
	}

	return ban, nil
}

// RemoveBan removes a ban for an IP
func (b *Backend) RemoveBan(ctx context.Context, ip string) error {
	pipe := b.client.Pipeline()
	pipe.Del(ctx, b.banKey(ip))
	pipe.SRem(ctx, b.allBansKey(), ip)
	_, err := pipe.Exec(ctx)
	return err
}

// GetAllBannedIPs returns all currently banned IPs
func (b *Backend) GetAllBannedIPs(ctx context.Context) ([]string, error) {
	ips, err := b.client.SMembers(ctx, b.allBansKey()).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, err
	}

	// Filter out expired bans
	var activeBans []string
	for _, ip := range ips {
		ban, err := b.GetBan(ctx, ip)
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
func (b *Backend) GetStats(ctx context.Context) (types.BackendStats, error) {
	pipe := b.client.Pipeline()

	// Get Redis info
	infoCmd := pipe.Info(ctx, "memory")
	dbSizeCmd := pipe.DBSize(ctx)
	bannedIPsCmd := pipe.SCard(ctx, b.allBansKey())

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return types.BackendStats{}, err
	}

	// Count tracked IPs by scanning keys
	var trackedIPs int
	iter := b.client.Scan(ctx, 0, b.keyPrefix+"ip:*", 0).Iterator()
	for iter.Next(ctx) {
		trackedIPs++
	}

	// Count Tor banned IPs
	bannedIPs, _ := b.GetAllBannedIPs(ctx)
	var torBannedCount int
	for _, ip := range bannedIPs {
		ban, err := b.GetBan(ctx, ip)
		if err == nil && ban != nil && ban.IsTorExit {
			torBannedCount++
		}
	}

	backendInfo := map[string]interface{}{
		"redis_db_size": dbSizeCmd.Val(),
		"redis_info":    b.parseRedisInfo(infoCmd.Val()),
	}

	return types.BackendStats{
		TrackedIPs:   trackedIPs,
		BannedIPs:    int(bannedIPsCmd.Val()),
		TorBannedIPs: torBannedCount,
		BackendType:  "redis",
		BackendInfo:  backendInfo,
	}, nil
}

// Cleanup removes stale metrics
func (b *Backend) Cleanup(ctx context.Context, staleThreshold time.Time) error {
	// Redis handles TTL automatically, but we can clean up explicitly
	iter := b.client.Scan(ctx, 0, b.keyPrefix+"ip:*", 0).Iterator()

	for iter.Next(ctx) {
		key := iter.Val()
		ip := strings.TrimPrefix(key, b.keyPrefix+"ip:")

		metrics, err := b.GetMetrics(ctx, ip)
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
			pipe := b.client.Pipeline()
			pipe.Del(ctx, b.ipKey(ip))
			pipe.Del(ctx, b.connectionsKey(ip))
			pipe.Del(ctx, b.requestsKey(ip))
			pipe.Del(ctx, b.errorsKey(ip))
			pipe.Del(ctx, b.banKey(ip))
			pipe.SRem(ctx, b.allBansKey(), ip)
			pipe.Exec(ctx)
		}
	}

	return iter.Err()
}

// Close closes the Redis connection
func (b *Backend) Close() error {
	return b.client.Close()
}

// Tor Backend Implementation

// torExitKey returns the Redis key for Tor exit nodes set
func (b *Backend) torExitKey() string {
	return b.keyPrefix + "tor:exits"
}

// torStatsKey returns the Redis key for Tor statistics
func (b *Backend) torStatsKey() string {
	return b.keyPrefix + "tor:stats"
}

// StoreTorExits stores the Tor exit node list in Redis
func (b *Backend) StoreTorExits(ctx context.Context, exits map[string]bool) error {
	pipe := b.client.Pipeline()

	// Clear existing set
	pipe.Del(ctx, b.torExitKey())

	// Add all Tor exit IPs to set (only those marked as true)
	trueExitCount := 0
	if len(exits) > 0 {
		ips := make([]interface{}, 0, len(exits))
		for ip, isTorExit := range exits {
			if isTorExit {
				ips = append(ips, ip)
				trueExitCount++
			}
		}
		if len(ips) > 0 {
			pipe.SAdd(ctx, b.torExitKey(), ips...)
		}
	}

	// Set TTL
	pipe.Expire(ctx, b.torExitKey(), b.ttl)

	// Store update timestamp and count
	stats := map[string]interface{}{
		"count":        trueExitCount,
		"last_updated": time.Now().Format(time.RFC3339),
	}
	pipe.HMSet(ctx, b.torStatsKey(), stats)
	pipe.Expire(ctx, b.torStatsKey(), b.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// LoadTorExits loads the Tor exit node list from Redis
func (b *Backend) LoadTorExits(ctx context.Context) (map[string]bool, error) {
	ips, err := b.client.SMembers(ctx, b.torExitKey()).Result()
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
func (b *Backend) IsTorExit(ctx context.Context, ip string) (bool, error) {
	result, err := b.client.SIsMember(ctx, b.torExitKey(), ip).Result()
	if err != nil && err != redis.Nil {
		return false, err
	}
	return result, nil
}

// GetTorStats returns Tor exit statistics
func (b *Backend) GetTorStats(ctx context.Context) (types.TorStats, error) {
	statsData, err := b.client.HGetAll(ctx, b.torStatsKey()).Result()
	if err != nil && err != redis.Nil {
		return types.TorStats{}, err
	}

	stats := types.TorStats{
		TTL: b.ttl,
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
func (b *Backend) parseTimeList(timeStrings []string) []time.Time {
	times := make([]time.Time, 0, len(timeStrings))
	for _, timeStr := range timeStrings {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			times = append(times, t)
		}
	}
	return times
}

func (b *Backend) storeTimeList(ctx context.Context, pipe redis.Pipeliner, key string, times []time.Time) {
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
	pipe.Expire(ctx, key, b.ttl)
}

func (b *Backend) parseRedisInfo(info string) map[string]string {
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

// RedisBackendConstructor is the constructor function for Redis backends
var RedisBackendConstructor = func(config *types.BackendConfig) (types.Backend, error) {
	return New(config)
}
