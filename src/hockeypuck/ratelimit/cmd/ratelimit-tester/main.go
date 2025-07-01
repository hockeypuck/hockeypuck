/*
   Hockeypuck Rate Limit Tester
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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type Config struct {
	Server           string
	KeyFile          string
	ProxyURL         string
	Requests         int
	Concurrent       int
	Delay            time.Duration
	UserAgent        string
	SkipTLSVerify    bool
	Verbose          bool
	TorProxy         bool
	TestConnectivity bool
	OutputFormat     string
}

func main() {
	config := &Config{}

	flag.StringVar(&config.Server, "server", "http://localhost:11371", "HKP server URL (e.g., http://localhost:11371)")
	flag.StringVar(&config.KeyFile, "key", "", "Path to .asc file containing ASCII armored GPG key")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Proxy URL (http://proxy:8080, socks5://proxy:1080, or tor for Tor)")
	flag.IntVar(&config.Requests, "requests", 5, "Number of requests to send")
	flag.IntVar(&config.Concurrent, "concurrent", 1, "Number of concurrent connections")
	flag.DurationVar(&config.Delay, "delay", 100*time.Millisecond, "Delay between requests")
	flag.StringVar(&config.UserAgent, "user-agent", "Hockeypuck-RateLimit-Tester/1.0", "User-Agent header")
	flag.BoolVar(&config.SkipTLSVerify, "skip-tls-verify", false, "Skip TLS certificate verification")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.TorProxy, "tor", false, "Use Tor proxy (equivalent to -proxy socks5://127.0.0.1:9050)")
	flag.BoolVar(&config.TestConnectivity, "test-only", false, "Only test connectivity, don't upload keys")
	flag.StringVar(&config.OutputFormat, "format", "text", "Output format: text, json")

	flag.Parse()

	if config.KeyFile == "" && !config.TestConnectivity {
		fmt.Fprintf(os.Stderr, "Error: -key flag is required (or use -test-only for connectivity test)\n")
		flag.Usage()
		os.Exit(1)
	}

	// Handle Tor proxy shortcut
	if config.TorProxy {
		config.ProxyURL = "socks5://127.0.0.1:9050"
	}

	if err := runTest(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runTest(config *Config) error {
	var keyData []byte
	var err error

	// Read the GPG key file if provided
	if config.KeyFile != "" {
		keyData, err = os.ReadFile(config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", config.KeyFile, err)
		}

		if config.Verbose {
			fmt.Printf("Loaded key file: %s (%d bytes)\n", config.KeyFile, len(keyData))
		}
	}

	if config.Verbose {
		fmt.Printf("Server: %s\n", config.Server)
		fmt.Printf("Proxy: %s\n", config.ProxyURL)
		if !config.TestConnectivity {
			fmt.Printf("Requests: %d (concurrent: %d)\n", config.Requests, config.Concurrent)
		}
		fmt.Printf("User-Agent: %s\n", config.UserAgent)
	}

	// Create HTTP client with proxy support
	client, err := createHTTPClient(config)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Test basic connectivity first
	if err := testConnectivity(client, config); err != nil {
		return fmt.Errorf("connectivity test failed: %w", err)
	}

	// If test-only mode, stop here
	if config.TestConnectivity {
		fmt.Println("Connectivity test completed successfully!")
		return nil
	}

	// Run the rate limit test
	return runRateLimitTest(client, config, keyData)
}

func createHTTPClient(config *Config) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
		},
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		switch proxyURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
			if config.Verbose {
				fmt.Printf("Using HTTP proxy: %s\n", config.ProxyURL)
			}
		case "socks5":
			// Create SOCKS5 dialer
			dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, nil, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 proxy: %w", err)
			}

			// Set custom dialer for the transport
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}

			if config.Verbose {
				fmt.Printf("Using SOCKS5 proxy: %s\n", config.ProxyURL)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s (supported: http, https, socks5)", proxyURL.Scheme)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

func testConnectivity(client *http.Client, config *Config) error {
	if config.Verbose {
		fmt.Println("Testing basic connectivity...")
	}

	baseURL := strings.TrimSuffix(config.Server, "/")

	// Test multiple endpoints to get comprehensive information
	endpoints := []struct {
		path        string
		description string
		required    bool
	}{
		{"/pks/stats", "Statistics endpoint", false},
		{"/pks/lookup?op=stats", "HKP stats lookup", false},
		{"/", "Root endpoint", false},
	}

	for _, endpoint := range endpoints {
		testURL := baseURL + endpoint.path
		if config.Verbose {
			fmt.Printf("Testing %s (%s)...\n", endpoint.description, testURL)
		}

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			if endpoint.required {
				return fmt.Errorf("failed to create request for %s: %w", endpoint.path, err)
			}
			continue
		}

		req.Header.Set("User-Agent", config.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			if endpoint.required {
				return fmt.Errorf("failed to connect to %s: %w", endpoint.path, err)
			}
			if config.Verbose {
				fmt.Printf("  Failed: %v\n", err)
			}
			continue
		}
		defer resp.Body.Close()

		if config.Verbose {
			fmt.Printf("  Status: %s\n", resp.Status)

			// Print interesting headers
			for header, values := range resp.Header {
				headerLower := strings.ToLower(header)
				if strings.Contains(headerLower, "rate") ||
					strings.Contains(headerLower, "limit") ||
					strings.Contains(headerLower, "ban") ||
					strings.Contains(headerLower, "tor") ||
					strings.HasPrefix(headerLower, "x-") ||
					header == "Server" {
					fmt.Printf("  %s: %s\n", header, strings.Join(values, ", "))
				}
			}

			// For stats endpoints, show some response body
			if strings.Contains(endpoint.path, "stats") && resp.StatusCode == 200 {
				body, err := io.ReadAll(resp.Body)
				if err == nil && len(body) > 0 {
					// Show first 200 characters of response
					preview := string(body)
					if len(preview) > 200 {
						preview = preview[:200] + "..."
					}
					fmt.Printf("  Response preview: %s\n", preview)
				}
			}
		}

		if resp.StatusCode >= 400 && endpoint.required {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server returned error %d for %s: %s", resp.StatusCode, endpoint.path, string(body))
		}
	}

	return nil
}

func runRateLimitTest(client *http.Client, config *Config, keyData []byte) error {
	fmt.Printf("Starting rate limit test with %d requests...\n", config.Requests)

	results := make(chan TestResult, config.Requests)
	semaphore := make(chan struct{}, config.Concurrent)

	// Start all requests
	for i := 0; i < config.Requests; i++ {
		go func(requestID int) {
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			result := performRequest(client, config, keyData, requestID)
			results <- result

			if config.Delay > 0 && requestID < config.Requests-1 {
				time.Sleep(config.Delay)
			}
		}(i + 1)
	}

	// Collect results
	var successful, failed, banned int
	bannedIPs := make(map[string]bool)

	for i := 0; i < config.Requests; i++ {
		result := <-results

		fmt.Printf("Request %d: %s", result.ID, result.Status)
		if result.Duration > 0 {
			fmt.Printf(" (%.2fs)", result.Duration.Seconds())
		}
		if result.Error != "" {
			fmt.Printf(" - %s", result.Error)
		}
		fmt.Println()

		if result.Banned {
			banned++
			bannedIPs[result.ClientIP] = true
		} else if result.Success {
			successful++
		} else {
			failed++
		}

		// Print rate limiting headers
		if config.Verbose && len(result.Headers) > 0 {
			for header, value := range result.Headers {
				fmt.Printf("  %s: %s\n", header, value)
			}
		}
	}

	// Summary
	fmt.Printf("\n=== Test Summary ===\n")
	fmt.Printf("Total requests: %d\n", config.Requests)
	fmt.Printf("Successful: %d\n", successful)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Rate limited/banned: %d\n", banned)
	if len(bannedIPs) > 0 {
		fmt.Printf("Unique IPs banned: %d\n", len(bannedIPs))
	}

	return nil
}

type TestResult struct {
	ID       int
	Success  bool
	Banned   bool
	Status   string
	Error    string
	Duration time.Duration
	ClientIP string
	Headers  map[string]string
}

func performRequest(client *http.Client, config *Config, keyData []byte, requestID int) TestResult {
	start := time.Now()
	result := TestResult{
		ID:      requestID,
		Headers: make(map[string]string),
	}

	// Create the key upload request
	uploadURL := strings.TrimSuffix(config.Server, "/") + "/pks/add"

	// Prepare form data
	formData := url.Values{}
	formData.Set("keytext", string(keyData))

	req, err := http.NewRequest("POST", uploadURL, strings.NewReader(formData.Encode()))
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.Status = "ERROR"
		return result
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", config.UserAgent)

	resp, err := client.Do(req)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.Status = "ERROR"
		return result
	}
	defer resp.Body.Close()

	// Capture rate limiting headers
	for header, values := range resp.Header {
		headerLower := strings.ToLower(header)
		if strings.Contains(headerLower, "rate") ||
			strings.Contains(headerLower, "limit") ||
			strings.Contains(headerLower, "ban") ||
			strings.Contains(headerLower, "tor") ||
			strings.HasPrefix(headerLower, "x-") {
			result.Headers[header] = strings.Join(values, ", ")
		}
	}

	// Check if we got rate limited
	if resp.StatusCode == 429 || resp.StatusCode == 503 {
		result.Banned = true
		result.Status = fmt.Sprintf("RATE LIMITED (%d)", resp.StatusCode)
	} else if resp.StatusCode >= 400 {
		result.Status = fmt.Sprintf("HTTP %d", resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 100 {
			body = body[:100]
		}
		result.Error = string(body)
	} else {
		result.Success = true
		result.Status = fmt.Sprintf("SUCCESS (%d)", resp.StatusCode)
	}

	return result
}
