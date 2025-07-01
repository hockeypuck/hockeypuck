# Hockeypuck Rate Limiting

Hockeypuck includes a comprehensive rate limiting system designed to protect against DDoS attacks, prevent abuse, and provide enhanced security for Tor exit nodes.

## Overview

The rate limiting system provides:

- **Connection-based rate limiting**: Limits concurrent connections and connection rates per IP
- **HTTP request rate limiting**: Limits the number of requests per time window  
- **Error rate monitoring**: Detects and blocks clients generating excessive errors
- **Tor exit node handling**: Enhanced restrictions with escalating bans for Tor traffic
- **Global Tor rate limiting**: Anti-vandalism protection against coordinated Tor attacks
- **IP whitelisting**: Bypass rate limits for trusted IPs
- **Interface-based storage backends**: Support for memory and Redis backends for clustered deployments
- **Keyserver synchronization exemptions**: Automatic exemptions for configured recon peers
- **Automatic cleanup**: Memory-efficient with automatic cleanup of stale metrics
- **Prometheus integration**: Comprehensive metrics for monitoring and alerting
- **Header-based communication**: Enables intelligent rate limiting coordination with proxies

## Storage Backends

The rate limiting system supports multiple storage backends through a clean interface architecture:

### Memory Backend (Default)
- **Use case**: Single-instance deployments
- **Performance**: Fastest access, lowest latency
- **Persistence**: In-memory only, data lost on restart
- **Configuration**: No additional setup required

### Redis Backend  
- **Use case**: Clustered deployments, data persistence
- **Performance**: High performance with network overhead
- **Persistence**: Data persists across restarts
- **Configuration**: Requires Redis server

### Future Backends
The interface design supports extending to additional backends like:
- etcd (for Kubernetes environments)
- Zookeeper (for distributed coordination)
- Database backends (PostgreSQL, MySQL)

## Configuration

Rate limiting is configured in the `[rateLimit]` section of the Hockeypuck configuration file:

```toml
[rateLimit]
enabled = true
maxConcurrentConnections = 80
connectionRate = 40          # per 3 seconds
httpRequestRate = 100        # per 10 seconds  
httpErrorRate = 20           # per 5 minutes
crawlerBlockDuration = "24h"
trustProxyHeaders = false

# Backend configuration
[rateLimit.backend]
type = "memory"  # or "redis"

# Memory backend (default) - no additional config needed
[rateLimit.backend.memory]

# Redis backend configuration
[rateLimit.backend.redis]
addr = "localhost:6379"
password = ""
db = 0
poolSize = 10
dialTimeout = "5s"
readTimeout = "3s" 
writeTimeout = "3s"
keyPrefix = "hockeypuck:ratelimit:"
ttl = "24h"
maxRetries = 3

[rateLimit.tor]
enabled = true
maxRequestsPerConnection = 2
maxConcurrentConnections = 1
connectionRate = 1           # per connectionRateWindow
connectionRateWindow = "10s" # time window for connection rate (default: 10s)
banDuration = "24h"
repeatOffenderBanDuration = "576h"  # 24 days
exitNodeListURL = "https://www.dan.me.uk/torlist/?exit"
updateInterval = "1h"
cacheFilePath = "tor_exit_nodes.cache"

# Global Tor rate limiting (anti-vandalism protection)
globalRateLimit = true       # Enable global rate limiting for all Tor exits
globalRequestRate = 1        # Max requests per globalRateWindow for ALL Tor exits combined
globalRateWindow = "10s"     # Time window for global rate limiting
globalBanDuration = "1h"     # Ban duration when global limit exceeded

[rateLimit.whitelist]
ips = [
    "127.0.0.1",
    "::1", 
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

[rateLimit.keyserverSync]
enabled = true   # Enable automatic exemptions for recon peers

[rateLimit.headers]
enabled = true
torHeader = "X-Tor-Exit"
banHeader = "X-RateLimit-Ban"
```

### Configuration Options

#### General Rate Limiting

- `enabled`: Enable/disable rate limiting (default: true)
- `maxConcurrentConnections`: Maximum concurrent connections per IP (default: 80)
- `connectionRate`: Maximum new connections per 3 seconds (default: 40)
- `httpRequestRate`: Maximum HTTP requests per 10 seconds (default: 100)
- `httpErrorRate`: Maximum HTTP errors per 5 minutes before ban (default: 20)
- `crawlerBlockDuration`: Ban duration for general violations (default: 24h)
- `trustProxyHeaders`: Trust X-Forwarded-For headers (default: false)

#### Tor Exit Node Handling

- `tor.enabled`: Enable enhanced Tor exit node restrictions (default: true)
- `tor.maxRequestsPerConnection`: Max requests per connection for Tor (default: 2)
- `tor.maxConcurrentConnections`: Max concurrent connections for Tor (default: 1)
- `tor.connectionRate`: Max connections per connectionRateWindow for Tor (default: 1)
- `tor.connectionRateWindow`: Time window for Tor connection rate (default: 10s)
- `tor.banDuration`: Initial ban duration for Tor violations (default: 24h)
- `tor.repeatOffenderBanDuration`: Escalated ban duration (default: 24 days)
- `tor.exitNodeListURL`: URL for Tor exit node list (default: dan.me.uk)
- `tor.updateInterval`: How often to update Tor exit list (default: 1h)
- `tor.cacheFilePath`: Local cache file for Tor exit nodes (default: tor_exit_nodes.cache)
- `tor.userAgent`: User-Agent header for Tor exit list fetching (set programmatically by server)

##### Global Tor Rate Limiting (Anti-Vandalism Protection)
These settings apply to ALL Tor exits combined, providing protection against coordinated attacks:

- `tor.globalRateLimit`: Enable global rate limiting for all Tor exits (default: true)
- `tor.globalRequestRate`: Max requests per globalRateWindow for ALL Tor exits combined (default: 1)
- `tor.globalRateWindow`: Time window for global rate limiting (default: 10s)
- `tor.globalBanDuration`: Ban duration when global limit exceeded (default: 1h)

Global rate limiting provides an additional layer of protection beyond per-IP limits. When the combined request rate from all Tor exits exceeds the configured threshold, all Tor exits are temporarily banned. This prevents vandalism attempts that use multiple Tor circuits to circumvent per-IP limits.

#### Header-Based Communication

- `headers.enabled`: Enable HTTP response headers for proxy communication (default: true)
- `headers.torHeader`: Header name for Tor exit identification (default: X-Tor-Exit)
- `headers.banHeader`: Header name for ban duration communication (default: X-RateLimit-Ban)

#### IP Whitelisting

- `whitelist.ips`: Array of IP addresses or CIDR ranges to exempt from rate limiting

#### Keyserver Synchronization

- `keyserverSync.enabled`: Enable automatic exemptions for configured recon peers (default: true)

When enabled, IPs of configured recon partners are automatically exempted from rate limiting to ensure keyserver synchronization is not interrupted. This feature works with the HKP recon protocol configuration to identify legitimate keyserver peers.

#### Keyserver Synchronization

- `keyserverSync.enabled`: Enable automatic exemptions for configured recon peers (default: true)

#### Backend Configuration

- `backend.type`: Backend type for rate limiting storage (default: memory)
- `backend.redis.addr`: Redis server address (default: localhost:6379)
- `backend.redis.password`: Redis server password (default: empty)
- `backend.redis.db`: Redis database index (default: 0)
- `backend.redis.poolSize`: Redis connection pool size (default: 10)
- `backend.redis.dialTimeout`: Timeout for Redis connection (default: 5s)
- `backend.redis.readTimeout`: Timeout for Redis read operations (default: 3s)
- `backend.redis.writeTimeout`: Timeout for Redis write operations (default: 3s)
- `backend.redis.keyPrefix`: Prefix for Redis keys (default: hockeypuck:ratelimit:)
- `backend.redis.ttl`: Time-to-live for Redis keys (default: 24h)
- `backend.redis.maxRetries`: Max number of retries for Redis commands (default: 3)

## Service Data Directory

Hockeypuck supports a global `dataDir` configuration option that specifies where service data files (like cache files) are stored:

```toml
# Service data directory configuration
dataDir = "/var/lib/hockeypuck"

[rateLimit.tor]
cacheFilePath = "tor_exit_nodes.cache"  # Relative to dataDir
# OR
cacheFilePath = "/absolute/path/tor.cache"  # Absolute path
```

- **Relative paths**: Cache files specified with relative paths are placed under `dataDir`
- **Absolute paths**: Cache files specified with absolute paths are used as-is
- **Default**: If `dataDir` is not specified, defaults to `/var/lib/hockeypuck`

## Global Tor Rate Limiting

Global Tor rate limiting provides protection against coordinated vandalism attacks that use multiple Tor circuits to circumvent per-IP rate limits. This feature complements individual Tor exit restrictions by monitoring the aggregate request rate across all Tor exits.

### How It Works

1. **Request Tracking**: Every request from a Tor exit node is tracked globally in addition to per-IP tracking
2. **Rate Monitoring**: The system monitors the total number of requests from all Tor exits within the configured time window
3. **Ban Application**: When the global rate limit is exceeded, all Tor exits are immediately banned for the specified duration
4. **Automatic Recovery**: Bans automatically expire, and the global request counter resets over time

### Use Cases

- **Vandalism Prevention**: Stops attackers using multiple Tor circuits to flood the server
- **Resource Protection**: Prevents Tor traffic from consuming excessive server resources
- **DDoS Mitigation**: Provides rapid response to distributed attacks via Tor

### Configuration Examples

**Conservative (Default)**:
```toml
[rateLimit.tor]
globalRateLimit = true
globalRequestRate = 1      # Only 1 request per 10s across all Tor exits
globalRateWindow = "10s"
globalBanDuration = "1h"
```

**More Permissive**:
```toml
[rateLimit.tor]
globalRateLimit = true
globalRequestRate = 5      # 5 requests per 30s across all Tor exits
globalRateWindow = "30s"
globalBanDuration = "30m"  # Shorter ban duration
```

**Disabled for Testing**:
```toml
[rateLimit.tor]
globalRateLimit = false    # Disable global limits (not recommended for production)
```

### Monitoring Global Bans

When a global Tor ban is active:
- All Tor exit requests return HTTP 429 with ban details in headers
- The ban reason includes "Global Tor rate limit exceeded"
- Statistics reflect the global ban in `tor_banned` counts
- Logs show both the triggering violation and subsequent blocked requests

This ensures consistent data file organization across all Hockeypuck services.

## Lifecycle Management

The rate limiting system uses explicit Start/Stop lifecycle management for background tasks:

### Automatic Integration
When using Hockeypuck server, the rate limiting system is automatically started and stopped:
- **Start**: Background tasks (Tor exit list updates, cleanup) begin when server starts
- **Stop**: Clean shutdown of all background tasks when server stops

### Manual Control
For direct usage of the rate limiting library:

```go
// Create rate limiter
rl, err := ratelimit.New(config)
if err != nil {
    log.Fatal(err)
}

// Start background tasks (Tor updates, cleanup)
rl.Start()

// Use rate limiter...

// Clean shutdown
rl.Stop()
```

### Background Tasks
- **Tor Exit List Updates**: Fetches fresh Tor exit node list at configured intervals
- **Metric Cleanup**: Removes stale metrics and tracks system health
- **Graceful Shutdown**: Uses tomb.Tomb for proper goroutine lifecycle management

All background tasks are automatically managed and will cleanly shut down when `Stop()` is called.

## Error Handling

The rate limiting system has robust error handling throughout:

### Function-Level Error Handling
- All rate limiting functions return errors instead of masking them
- Errors bubble up to appropriate handling levels (middleware, background tasks)
- Detailed error context provided using `fmt.Errorf` with `%w` for error wrapping

### Network Resilience
- Tor exit list fetching includes timeout handling (30-second timeout)
- Graceful fallback when Tor exit list updates fail
- File cache provides persistence across network failures

### Backend Error Handling
- Redis connection failures handled gracefully
- Memory backend includes proper concurrency protection
- All backend operations return detailed error information

### Middleware Integration
- Middleware logs rate limiting errors appropriately
- Non-critical errors don't interrupt request processing
- Critical errors (like backend failures) are properly escalated

## Default Values

The system ships with conservative production-ready defaults based on HAProxy recommendations:

- **80 concurrent connections** per IP (typical web browser limit)
- **40 new connections per 3 seconds** (prevents connection flooding)
- **100 HTTP requests per 10 seconds** (allows normal usage patterns)
- **20 HTTP errors per 5 minutes** before temporary ban
- **Tor exits limited to 1 connection, 2 requests** (anti-abuse)
- **Local/private IPs whitelisted** by default

## Tor Exit Node Protection

The system provides enhanced protection against Tor-based abuse:

### Automatic Tor Detection
- Fetches current Tor exit node list from dan.me.uk hourly
- Caches list locally for reliability
- Graceful fallback if updates fail

### Enhanced Restrictions
- Tor exits limited to 1 concurrent connection
- Maximum 2 requests per connection for POST /pks/add
- Stricter connection rate limits (1 per 10 seconds)

### Tor Storage Options

#### File-based Cache
- **Storage**: Local file cache (`tor.cacheFilePath`)
- **Use case**: All deployments for persistence across restarts
- **Behavior**: Tor exit list is always stored in the backend (memory/Redis) for fast access, with file cache providing persistence
- **Benefits**: Fast in-memory access with persistent storage, automatic recovery on restart

The Tor exit node list is fetched from the configured URL and stored both in the backend (for fast access) and in a local cache file (for persistence). On startup, if the cache file exists and is recent enough, it's loaded to bootstrap the backend storage.

```toml
[rateLimit.tor]
enabled = true
cacheFilePath = "tor_exit_nodes.cache"  # Relative to dataDir
updateInterval = "1h"
```

### Escalating Bans
- **First offense**: 24-hour ban
- **Repeat offenses**: 24-day ban
- Offense count tracked per IP

## Header-Based Communication

Hockeypuck can communicate rate limiting intelligence to upstream proxies (like HAProxy) through HTTP response headers. This enables intelligent ban decisions and coordination between application-level rate limiting and network-level enforcement.

### Response Headers

When header communication is enabled (`headers.enabled = true`), Hockeypuck sets these response headers with **detailed information for load balancer intelligence**:

#### Tor Exit Identification
```http
X-Tor-Exit: true
```
- Set for all requests from detected Tor exit nodes
- Allows proxy to learn about Tor exits and apply consistent policies
- Helps build proxy-side Tor detection databases

#### Rate Limit Violation Information
```http
X-RateLimit-Ban: 30m
X-RateLimit-Ban-Reason: Request rate exceeded (101 >= 100 per 10s)
X-RateLimit-Ban-Type: connection
```

**Important Security Note**: Headers contain detailed rate limiting information for load balancer and proxy intelligence, while HTTP response bodies sent to end clients contain sanitized, generic messages to prevent information disclosure.

**Ban Duration (`X-RateLimit-Ban`)**:
- Format: `30m`, `2h`, `1d` (minutes, hours, days)
- Escalates based on offense history and violation type
- Tor violations: `24h` → `24d` for repeat offenders
- Regular violations: `30m` → `2h` → `8h` → `24h`

**Ban Reason (`X-RateLimit-Ban-Reason`)**:
- **Headers**: Detailed technical description for load balancers (e.g., "Request rate exceeded (101 >= 100 per 10s)")
- **Response Body**: Sanitized user-facing message (e.g., "Too many requests")

**Ban Type (`X-RateLimit-Ban-Type`)**:
- `tor`: Tor-specific violation
- `connection`: Connection rate/concurrency violation  
- `request`: HTTP request rate violation
- `crawler`: Error rate violation (crawler behavior)
- `general`: Other violations

### Configuration

```toml
[rateLimit.headers]
enabled = true                    # Enable header communication (default: true)
torHeader = "X-Tor-Exit"         # Tor identification header name
banHeader = "X-RateLimit-Ban"    # Ban duration header name
```

### Use Cases

#### HAProxy Integration
Headers provide intelligence for HAProxy stick tables and ban decisions:
- Learn Tor exits from application layer
- Coordinate ban durations between layers
- Apply consistent policies across infrastructure

#### Load Balancer Coordination
- Share rate limiting intelligence with upstream load balancers
- Enable application-aware network policies
- Provide context for automated security responses

#### Security Analytics
- Export rate limiting decisions to SIEM systems
- Track abuse patterns across infrastructure layers
- Provide context for incident response

## Backend Selection Guide

### Choose Memory Backend When:
- Running a single Hockeypuck instance
- Maximum performance is required
- Simple deployment preferred
- Data persistence across restarts not needed

### Choose Redis Backend When:
- Running multiple Hockeypuck instances (load balancer setup)
- Data persistence across restarts required
- Centralized rate limiting across multiple services
- Advanced Redis features needed (replication, clustering)

## Clustering Setup

For clustered deployments with multiple Hockeypuck instances:

1. **Setup Redis Server**:
   ```bash
   # Install Redis
   apt-get install redis-server
   
   # Configure Redis for rate limiting
   redis-cli config set maxmemory-policy allkeys-lru
   ```

2. **Configure All Hockeypuck Instances**:
   ```toml
   [rateLimit.backend]
   type = "redis"
   
   [rateLimit.backend.redis]
   addr = "your-redis-server:6379"
   password = "your-redis-password"
   keyPrefix = "hockeypuck:ratelimit:"
   ttl = "24h"
   ```

3. **Load Balancer Configuration**:
   ```
   # HAProxy example - source IP forwarding
   backend hockeypuck
       option forwardfor
       server hkp1 10.0.0.1:11371 check
       server hkp2 10.0.0.2:11371 check
   ```

4. **Enable Proxy Headers**:
   ```toml
   [rateLimit]
   trustProxyHeaders = true  # Trust X-Forwarded-For headers
   ```

### Clustering Benefits

- **Shared Rate Limits**: All instances enforce consistent rate limits
- **Shared Ban Lists**: Banned IPs are blocked across all instances  
- **Shared Tor Lists**: Tor exit nodes detected consistently across cluster
- **Reduced Resource Usage**: Centralized storage reduces memory per instance
- **Atomic Updates**: Configuration changes apply to all instances simultaneously

## Monitoring and Metrics

### Stats Endpoint

Rate limiting statistics are included in the `/pks/stats` endpoint:

```json
{
  "rateLimit": {
    "enabled": true,
    "tracked_ips": 42,
    "banned_ips": 3,
    "tor_banned": 1,
    "backend_type": "memory",
    "tor_exits_count": 1337,
    "tor_last_updated": "2025-06-30T15:00:00Z"
  }
}
```

**Available statistics:**
- `enabled`: Whether rate limiting is enabled
- `tracked_ips`: Number of IPs currently being tracked
- `banned_ips`: Total number of currently banned IPs
- `tor_banned`: Number of currently banned Tor exit IPs  
- `backend_type`: Storage backend type (memory, redis)
- `tor_exits_count`: Number of known Tor exit nodes (when Tor protection enabled)
- `tor_last_updated`: Timestamp of last Tor exit list update (when Tor protection enabled)

**Note:** Global Tor rate limiting statistics are included in the general `banned_ips` and `tor_banned` counts when a global ban is active.

### Prometheus Metrics

The following metrics are exported for Prometheus monitoring:

- `hockeypuck_rate_limit_violations_total{reason,is_tor}`: Rate limit violations by type
- `hockeypuck_rate_limit_banned_ips{is_tor}`: Currently banned IPs  
- `hockeypuck_rate_limit_tracked_ips`: Number of IPs being tracked

### Logging

Rate limit violations are logged with structured data:

```
WARN[2025-06-22T10:30:00Z] Rate limit violation
  client_ip=203.0.113.42
  method=POST
  path=/pks/add
  reason="Request rate exceeded (101 >= 100 per 10s)"
  user_agent="curl/7.68.0"
```

Bans are logged with details:

```
WARN[2025-06-22T10:30:00Z] IP banned
  client_ip=203.0.113.42  
  reason="Request rate exceeded (101 >= 100 per 10s)"
  expires_at=2025-06-23T10:30:00Z
  duration=24h0m0s
  is_tor=false
```

Background task errors are logged appropriately:

```
ERROR[2025-06-22T10:30:00Z] Failed to update Tor exit list
  error="dial tcp: connection refused"
  url="https://www.dan.me.uk/torlist/?exit"
  next_retry="2025-06-22T11:30:00Z"
```

## Security Considerations

### IP Spoofing Protection
- Proxy headers only trusted when explicitly enabled
- Falls back to connection-level IP address
- Whitelist includes only private/local ranges by default

### Memory Management  
- Automatic cleanup of stale metrics every 5 minutes
- Metrics older than 1 hour are removed
- Active bans prevent premature cleanup

### Tor Security
- Enhanced restrictions only apply to POST /pks/add requests
- Regular browsing through Tor unaffected
- Escalating bans discourage persistent abuse

## Security Design: Dual Response System

The rate limiting system implements a **dual response design** to balance security with operational intelligence:

### Client Response Body (Sanitized)
HTTP response bodies sent to end clients contain generic, sanitized messages:
- `"Rate limit exceeded: Too many requests"`
- `"Rate limit exceeded: Service temporarily unavailable for Tor users"`
- `"Rate limit exceeded: Access temporarily restricted"`

This prevents information disclosure that could help attackers understand rate limiting thresholds and circumvent protections.

### Load Balancer Headers (Detailed)
HTTP response headers contain detailed technical information for infrastructure:
- `X-RateLimit-Ban-Reason: Request rate exceeded (101 >= 100 per 10s)`
- `X-RateLimit-Ban-Reason: Global Tor rate limit exceeded (5 >= 1 per 10s)`
- `X-RateLimit-Ban-Reason: Too many concurrent connections (3 >= 2)`

This enables:
- **HAProxy stick tables**: Intelligent ban coordination
- **Load balancer decisions**: Application-aware routing  
- **Rate limiter testing tools**: Detailed debugging information
- **SIEM integration**: Comprehensive security analytics

### Operational Benefits
- **Security**: End clients cannot learn internal rate limiting parameters
- **Intelligence**: Load balancers get actionable technical details
- **Debugging**: Administrators have full violation context in logs
- **Monitoring**: Detailed metrics for alerting and analysis

## Deployment Recommendations

### Production Settings
The default settings are suitable for most production deployments. Consider adjusting:

- Increase `maxConcurrentConnections` for high-traffic servers
- Lower `httpRequestRate` for additional protection
- Add legitimate mirrors to whitelist
- Enable `trustProxyHeaders` only behind trusted proxies

### Behind Load Balancers
When deploying behind HAProxy, nginx, or Cloudflare:

```toml
[rateLimit]
trustProxyHeaders = true  # Enable only with trusted proxies
```

Add your load balancer IPs to the whitelist to prevent false positives.

### Monitoring
Set up Prometheus alerts for:
- High rate limit violation rates
- Unusual numbers of banned IPs
- Tor exit node list update failures

## API Integration (Future)

The rate limiting system is designed to support future administrative APIs for:
- Real-time ban management
- Whitelist updates
- Metric queries
- Configuration adjustments

These APIs will be added when budget approval is secured for the admin interface development.
