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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// fetchTorExitList fetches the Tor exit node list from the specified URL
func fetchTorExitList(url, userAgent string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add User-Agent to be respectful to the service
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "Hockeypuck-KeyServer/1.0 (Tor exit list fetcher)") // Fallback
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Return specific error messages for common rate limiting responses
		switch resp.StatusCode {
		case 429:
			return nil, fmt.Errorf("rate limited by server (HTTP 429): try reducing update frequency")
		case 403:
			return nil, fmt.Errorf("access forbidden (HTTP 403): possibly rate limited or blocked")
		case 503:
			return nil, fmt.Errorf("service unavailable (HTTP 503): server may be overloaded")
		default:
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
		}
	}

	exits := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			exits[line] = true
		}
	}

	return exits, scanner.Err()
}

// loadTorExitCache loads the Tor exit cache from file
func loadTorExitCache(filePath string) (map[string]bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil // Return empty map if file doesn't exist
		}
		return nil, err
	}
	defer file.Close()

	var exits map[string]bool
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&exits); err != nil {
		return nil, err
	}

	return exits, nil
}

// saveTorExitCache saves the Tor exit cache to file
func saveTorExitCache(filePath string, exits map[string]bool) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(exits)
}
