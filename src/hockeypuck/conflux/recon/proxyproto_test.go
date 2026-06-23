/*
   conflux - Distributed database synchronization library
	Based on the algorithm described in
		"Set Reconciliation with Nearly Optimal	Communication Complexity",
			Yaron Minsky, Ari Trachtenberg, and Richard Zippel, 2004.

   Copyright (c) 2012-2015  Casey Marshall <cmars@cmarstech.com>

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

package recon

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func TestParseProxyMatchers(t *testing.T) {
	matchers, err := parseProxyMatchers([]string{"10.0.0.0/8", "192.168.1.1", "::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matchers) != 3 {
		t.Fatalf("expected 3 matchers, got %d", len(matchers))
	}

	if _, err := parseProxyMatchers([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid trusted proxy entry")
	}
}

func TestProxyProtocolPolicy(t *testing.T) {
	addr := func(ipPort string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", ipPort)
		if err != nil {
			t.Fatalf("resolve %q: %v", ipPort, err)
		}
		return a
	}

	// With trusted proxies configured, only listed sources are required to
	// send a header; everyone else is rejected as an untrusted upstream.
	policy, err := proxyProtocolPolicy([]string{"10.0.0.0/8", "192.168.1.1"})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	for _, tc := range []struct {
		src    string
		want   proxyproto.Policy
		reject bool
	}{
		{"10.1.2.3:5555", proxyproto.REQUIRE, false},
		{"192.168.1.1:5555", proxyproto.REQUIRE, false},
		{"192.168.1.2:5555", proxyproto.REJECT, true},
		{"1.2.3.4:5555", proxyproto.REJECT, true},
	} {
		got, gotErr := policy(proxyproto.ConnPolicyOptions{Upstream: addr(tc.src)})
		if got != tc.want {
			t.Errorf("src %s: policy = %v, want %v", tc.src, got, tc.want)
		}
		if tc.reject && !errors.Is(gotErr, proxyproto.ErrInvalidUpstream) {
			t.Errorf("src %s: expected ErrInvalidUpstream, got %v", tc.src, gotErr)
		}
		if !tc.reject && gotErr != nil {
			t.Errorf("src %s: unexpected error %v", tc.src, gotErr)
		}
	}

	// With no trusted proxies, any source must send a valid header.
	openPolicy, err := proxyProtocolPolicy(nil)
	if err != nil {
		t.Fatalf("build open policy: %v", err)
	}
	if got, gotErr := openPolicy(proxyproto.ConnPolicyOptions{Upstream: addr("8.8.8.8:1234")}); got != proxyproto.REQUIRE || gotErr != nil {
		t.Errorf("open policy = (%v, %v), want (REQUIRE, nil)", got, gotErr)
	}
}

// TestProxyProtocolListenerEndToEnd verifies that a trusted, loopback
// connection prefixed with a valid PROXY header surfaces the real client
// address via RemoteAddr(), exactly as the recon accept loop relies on.
func TestProxyProtocolListenerEndToEnd(t *testing.T) {
	settings := DefaultSettings()
	settings.ProxyProtocol = ProxyProtocolConfig{
		Enabled:           true,
		ReconAddr:         "127.0.0.1:0",
		TrustedProxies:    []string{"127.0.0.1/32"},
		HeaderTimeoutSecs: 5,
	}
	p := &Peer{settings: settings}

	ln, err := p.listenProxyProtocol()
	if err != nil {
		t.Fatalf("listenProxyProtocol: %v", err)
	}
	defer ln.Close()

	type result struct {
		ip  net.IP
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		defer conn.Close()
		// Mirrors the accept loop: RemoteAddr triggers header processing.
		resultCh <- result{ip: remoteIP(conn.RemoteAddr())}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// PROXY protocol v1 header advertising a real client of 192.0.2.10.
	if _, err := io.WriteString(conn, "PROXY TCP4 192.0.2.10 192.0.2.20 40000 11372\r\n"); err != nil {
		t.Fatalf("write header: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("accept: %v", res.err)
		}
		if want := net.ParseIP("192.0.2.10"); !res.ip.Equal(want) {
			t.Fatalf("RemoteAddr IP = %v, want %v", res.ip, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for accept")
	}
}

// TestProxyProtocolListenerRequiresHeader verifies that a trusted source which
// fails to send a PROXY header within the timeout does not get to masquerade as
// an arbitrary client; the connection errors rather than yielding a spoofed
// address.
func TestProxyProtocolListenerRequiresHeader(t *testing.T) {
	settings := DefaultSettings()
	settings.ProxyProtocol = ProxyProtocolConfig{
		Enabled:           true,
		ReconAddr:         "127.0.0.1:0",
		TrustedProxies:    []string{"127.0.0.1/32"},
		HeaderTimeoutSecs: 1,
	}
	p := &Peer{settings: settings}

	ln, err := p.listenProxyProtocol()
	if err != nil {
		t.Fatalf("listenProxyProtocol: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		// No header is sent; the first read must fail under REQUIRE.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1)
		_, readErr := conn.Read(buf)
		errCh <- readErr
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case readErr := <-errCh:
		if readErr == nil {
			t.Fatal("expected read error when no PROXY header is sent")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for accept")
	}
}

// TestMatchConnRejectsProxyConnWithoutHeader verifies the fix for the case
// where a trusted source connects to the PROXY listener but sends no (or an
// invalid) header. RemoteAddr() would then fall back to the proxy's own
// address; matchConn must reject the connection up front rather than letting it
// match (here the loopback special case would otherwise match) and proceed to a
// doomed recon attempt.
func TestMatchConnRejectsProxyConnWithoutHeader(t *testing.T) {
	settings := DefaultSettings()
	settings.ProxyProtocol = ProxyProtocolConfig{
		Enabled:           true,
		ReconAddr:         "127.0.0.1:0",
		TrustedProxies:    []string{"127.0.0.1/32"},
		HeaderTimeoutSecs: 2,
	}
	tree := new(MemPrefixTree)
	tree.Init()
	p := NewPeer(settings, tree, nil)
	if p == nil {
		t.Fatal("NewPeer returned nil")
	}

	ln, err := p.listenProxyProtocol()
	if err != nil {
		t.Fatalf("listenProxyProtocol: %v", err)
	}
	defer ln.Close()

	resultCh := make(chan *Partner, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- nil
			return
		}
		defer conn.Close()
		resultCh <- p.matchConn(conn)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Send bytes that are not a PROXY header so parsing fails fast.
	if _, err := io.WriteString(conn, "NOT-A-PROXY-HEADER\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case partner := <-resultCh:
		if partner != nil {
			t.Fatalf("matchConn accepted a headerless PROXY connection: %+v", partner)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for matchConn")
	}
}

func TestRemoteIP(t *testing.T) {
	for _, tc := range []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5}, "1.2.3.4"},
		{&net.UDPAddr{IP: net.ParseIP("::1"), Port: 5}, "::1"},
	} {
		if got := remoteIP(tc.addr); !got.Equal(net.ParseIP(tc.want)) {
			t.Errorf("remoteIP(%v) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
