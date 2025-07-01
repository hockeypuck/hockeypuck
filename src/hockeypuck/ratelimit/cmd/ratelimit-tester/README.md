# Hockeypuck Rate Limit Tester

A command-line tool for testing rate limiting behavior of Hockeypuck keyservers. Supports HTTP, HTTPS, and SOCKS5 proxies.

## Building

```bash
go build -o ratelimit-tester .
```

## Usage Examples

### Basic connectivity test
```bash
./ratelimit-tester -server http://localhost:11371 -test-only -verbose
```

### Test with GPG key upload
```bash
./ratelimit-tester -server http://localhost:11371 -key test-key.asc -requests 10 -verbose
```

### Test through HTTP proxy
```bash
./ratelimit-tester -server http://keyserver.ubuntu.com:11371 -key test-key.asc -proxy http://proxy.example.com:8080 -verbose
```

### Test through SOCKS5 proxy (e.g., Tor)
```bash
./ratelimit-tester -server http://keys.openpgp.org -key test-key.asc -proxy socks5://127.0.0.1:9050 -verbose
```

### Test through Tor (shortcut)
```bash
./ratelimit-tester -server http://keys.openpgp.org -key test-key.asc -tor -verbose
```

### Rate limiting stress test
```bash
./ratelimit-tester -server http://localhost:11371 -key test-key.asc -requests 50 -concurrent 5 -delay 50ms -verbose
```

### Test against HTTPS keyserver
```bash
./ratelimit-tester -server https://keys.openpgp.org -key test-key.asc -skip-tls-verify -verbose
```

## Command Line Options

- `-server URL`: HKP server URL (default: http://localhost:11371)
- `-key FILE`: Path to .asc file containing ASCII armored GPG key
- `-proxy URL`: Proxy URL (http://proxy:8080, socks5://proxy:1080)
- `-tor`: Use Tor proxy (equivalent to -proxy socks5://127.0.0.1:9050)
- `-requests N`: Number of requests to send (default: 5)
- `-concurrent N`: Number of concurrent connections (default: 1)
- `-delay DURATION`: Delay between requests (default: 100ms)
- `-user-agent STRING`: User-Agent header (default: Hockeypuck-RateLimit-Tester/1.0)
- `-skip-tls-verify`: Skip TLS certificate verification
- `-verbose`: Verbose output including headers and response details
- `-test-only`: Only test connectivity, don't upload keys
- `-format FORMAT`: Output format: text, json (default: text)

## Testing Scenarios

### 1. Local Hockeypuck Testing
Test your local development instance:
```bash
./ratelimit-tester -server http://localhost:11371 -key test-key.asc -requests 20 -verbose
```

### 2. Remote Keyserver Testing
Test against public keyservers:
```bash
./ratelimit-tester -server http://keyserver.ubuntu.com:11371 -key test-key.asc -test-only -verbose
```

### 3. Proxy Configuration Testing
Test proxy connectivity:
```bash
# HTTP proxy
./ratelimit-tester -server http://keys.openpgp.org -proxy http://proxy:8080 -test-only -verbose

# SOCKS5 proxy (Tor)
./ratelimit-tester -server http://keys.openpgp.org -tor -test-only -verbose
```

### 4. Rate Limiting Behavior
Test rate limiting triggers:
```bash
./ratelimit-tester -server http://localhost:11371 -key test-key.asc -requests 100 -concurrent 10 -delay 10ms -verbose
```

## Output Interpretation

The tool provides detailed output about:
- Connection establishment (with proxy info)
- HTTP response codes and headers
- Rate limiting headers (X-RateLimit-*, X-Tor-Exit, etc.)
- Request timing and success rates
- Ban detection and duration

Example output:
```
Testing basic connectivity...
Testing Statistics endpoint (http://localhost:11371/pks/stats)...
  Status: 200 OK
  Server: Hockeypuck/2.2.0
  X-RateLimit-Enabled: true

Starting rate limit test with 5 requests...
Request 1: SUCCESS (200) (0.05s)
Request 2: SUCCESS (200) (0.03s)
Request 3: RATE LIMITED (429) (0.02s)
  X-RateLimit-Ban: 30m
  X-RateLimit-Ban-Reason: Request rate exceeded (3 >= 2 per 10s)
```

## Creating Test Keys

You can create your own test key:
```bash
gpg --batch --gen-key --armor > my-test-key.asc <<EOF
%echo Generating test key
Key-Type: RSA
Key-Length: 2048
Name-Real: Test User
Name-Email: test@example.com
Expire-Date: 1y
%commit
%echo Done
EOF
```

Or use the provided `test-key.asc` file for testing.
