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
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pires/go-proxyproto"
	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	cf "hockeypuck/conflux"
)

const SERVE = "serve"

var ErrNodeNotFound error = fmt.Errorf("prefix-tree node not found")

var ErrRemoteRejectedConfig error = fmt.Errorf("remote rejected configuration")

type Recover struct {
	Partner        *Partner
	RemoteAddr     net.Addr
	RemoteConfig   *Config
	RemoteElements []cf.Zp
	Done           chan struct{}
}

func (r *Recover) String() string {
	return fmt.Sprintf("%v: %d elements", r.RemoteAddr, len(r.RemoteElements))
}

// RecoverAddr differs in general from both ReconAddr and HTTPAddr.
// It uses the recon host and the HTTP port advertised by the remote recon config.
func (r *Recover) RecoverAddr() (string, error) {
	// Prefer the configured recon address.
	host, _, err1 := net.SplitHostPort(r.Partner.ReconAddr)
	if host == "" {
		// Fall back to the connection IP (if localhost or allowCIDR).
		var err2 error
		host, _, err2 = net.SplitHostPort(r.RemoteAddr.String())
		if err2 != nil {
			log.Errorf("cannot parse remote address from %q: %v, or %q: %v", r.RemoteAddr, err2, r.Partner.ReconAddr, err1)
			return "", errors.WithStack(err2)
		}
	}
	// Append the advertised recovery port.
	return net.JoinHostPort(host, fmt.Sprintf("%d", r.RemoteConfig.HTTPPort)), nil
}

type RecoverChan chan *Recover

type PeerMode string

var (
	PeerModeDefault    = PeerMode("")
	PeerModeGossipOnly = PeerMode("gossip only")
	PeerModeServeOnly  = PeerMode("serve only")
	PeerModeIdle       = PeerMode("idle")
)

type Peer struct {
	settings *Settings
	ptree    PrefixTree
	matcher  IPMatcher
	handler  PartnerEventHandler

	RecoverChan RecoverChan

	muDie sync.Mutex
	t     tomb.Tomb

	cond     *sync.Cond
	mu       sync.RWMutex
	once     *sync.Once
	full     bool
	mutating bool
	readers  int

	muElements     sync.Mutex
	insertElements []cf.Zp
	removeElements []cf.Zp

	mutatedFunc func()
}

func NewPeer(settings *Settings, tree PrefixTree, handler PartnerEventHandler) *Peer {
	p := &Peer{
		RecoverChan: make(RecoverChan),
		settings:    settings,
		once:        &sync.Once{},
		ptree:       tree,
	}
	p.cond = sync.NewCond(&p.mu)

	matcher, err := p.settings.Matcher()
	if err != nil {
		log.Errorf("cannot create matcher: %v", err)
		return nil
	}
	p.matcher = matcher
	p.handler = handler

	registerMetrics()

	return p
}

func NewMemPeer() *Peer {
	settings := DefaultSettings()
	tree := new(MemPrefixTree)
	tree.Init()
	return NewPeer(settings, tree, nil)
}

func (p *Peer) CurrentPartners() []*Partner {
	return p.matcher.CurrentPartners()
}

func (p *Peer) log(label string) *log.Entry {
	return p.logFields(label, log.Fields{})
}

func (p *Peer) logConn(label string, conn net.Conn) *log.Entry {
	return p.logFields(label, log.Fields{"remoteAddr": conn.RemoteAddr()})
}

func (p *Peer) logFields(label string, fields log.Fields) *log.Entry {
	fields["label"] = fmt.Sprintf("%s %s", label, p.settings.ReconAddr)
	return log.WithFields(fields)
}

func (p *Peer) logConnFields(label string, conn net.Conn, fields log.Fields) *log.Entry {
	fields["remoteAddr"] = conn.RemoteAddr()
	return p.logFields(label, fields)
}

func (p *Peer) logErr(label string, err error) *log.Entry {
	return p.logFields(label, log.Fields{"error": fmt.Sprintf("%+v", err)})
}

func (p *Peer) logConnErr(label string, conn net.Conn, err error) *log.Entry {
	return p.logConnFields(label, conn, log.Fields{"error": fmt.Sprintf("%+v", err)})
}

func (p *Peer) StartMode(mode PeerMode) {
	switch mode {
	case PeerModeIdle:
		p.t.Go(p.Idle)
	case PeerModeGossipOnly:
		p.t.Go(p.Gossip)
	case PeerModeServeOnly:
		p.t.Go(p.Serve)
	default:
		p.t.Go(p.Serve)
		p.t.Go(p.Gossip)
	}
}

func (p *Peer) Start() {
	p.t.Go(p.Serve)
	p.t.Go(p.Gossip)
}

func (p *Peer) Stop() error {
	// This lock prevents goroutines from panicking the tomb after the kill.
	p.muDie.Lock()
	p.t.Kill(nil)
	p.flush()
	p.muDie.Unlock()

	return p.t.Wait()
}

func (p *Peer) Flush() {
	p.flush()
}

func (p *Peer) Insert(zs ...cf.Zp) {
	p.muElements.Lock()
	defer p.muElements.Unlock()
	p.insertElements = append(p.insertElements, zs...)
}

func (p *Peer) Remove(zs ...cf.Zp) {
	p.muElements.Lock()
	defer p.muElements.Unlock()
	p.removeElements = append(p.removeElements, zs...)
}

func (p *Peer) SetMutatedFunc(f func()) {
	p.muElements.Lock()
	defer p.muElements.Unlock()
	p.mutatedFunc = f
}

func (p *Peer) readAcquire() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Mutating or outbound recovery channel is full.
	if p.mutating || p.full {
		return false
	}

	p.readers++
	p.once.Do(p.mutate)

	return true
}

func (p *Peer) readRelease() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.readers--
	if p.readers < 0 {
		panic("negative readers")
	}

	p.cond.Signal()
}

func (p *Peer) isDying() bool {
	select {
	case <-p.t.Dying():
		return true
	default:
	}
	return false
}

func (p *Peer) mutate() {
	p.muDie.Lock()
	defer p.muDie.Unlock()
	if p.isDying() {
		return
	}

	p.t.Go(func() error {
		p.mu.Lock()
		for p.readers != 0 {
			p.cond.Wait()
		}
		p.mutating = true
		p.once = &sync.Once{}
		p.mu.Unlock()

		p.flush()

		p.mu.Lock()
		p.mutating = false
		p.full = false
		p.mu.Unlock()

		return nil
	})
}

func (p *Peer) flush() {
	p.muElements.Lock()
	inserted := 0
	removed := 0

	for i := range p.insertElements {
		z := &p.insertElements[i]
		err := p.ptree.Insert(z)
		if err != nil {
			log.Warningf("cannot insert %q (%s) into prefix tree: %v", z, z.FullKeyHash(), err)
		} else {
			inserted++
		}
	}
	if inserted > 0 {
		p.logFields("mutate", log.Fields{"elements": inserted}).Debugf("inserted")
	}

	for i := range p.removeElements {
		z := &p.removeElements[i]
		err := p.ptree.Remove(z)
		if err != nil {
			log.Warningf("cannot remove %q (%s) from prefix tree: %v", z, z.FullKeyHash(), err)
		} else {
			removed++
		}
	}
	if removed > 0 {
		p.logFields("mutate", log.Fields{"elements": removed}).Debugf("removed")
	}

	p.insertElements = nil
	p.removeElements = nil
	if p.mutatedFunc != nil {
		p.mutatedFunc()
	}
	p.muElements.Unlock()
}

// Idle MUST be invoked if we want to defer stopping a peer, without necessarily starting it.
// Otherwise the Tomb will hang forever on exit (https://github.com/go-tomb/tomb/issues/17)
func (p *Peer) Idle() error {
	<-p.t.Dying()
	return nil
}

func (p *Peer) Serve() error {
	// Optionally start an additional listener that expects a PROXY protocol
	// header on every connection (e.g. for inbound recon terminated by a load
	// balancer in TCP mode). This runs alongside the plain listener so that
	// directly-connected peers keep working unchanged.
	if p.settings.ProxyProtocol.Enabled {
		proxyLn, err := p.listenProxyProtocol()
		if err != nil {
			return errors.WithStack(err)
		}
		p.t.Go(func() error {
			return p.acceptLoop(proxyLn)
		})
	}

	addr, err := p.settings.ReconNet.Resolve(p.settings.ReconAddr)
	if err != nil {
		return errors.WithStack(err)
	}

	ln, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		return errors.WithStack(err)
	}
	return p.acceptLoop(ln)
}

// listenProxyProtocol builds the optional PROXY-protocol-aware listener. Only
// sources listed in TrustedProxies (if any) may send a PROXY header; the parsed
// real client address is what the partner matcher subsequently sees.
func (p *Peer) listenProxyProtocol() (net.Listener, error) {
	cfg := p.settings.ProxyProtocol
	addr, err := cfg.ReconNet.Resolve(cfg.ReconAddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	base, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	policy, err := proxyProtocolPolicy(cfg.TrustedProxies)
	if err != nil {
		base.Close()
		return nil, errors.WithStack(err)
	}
	ln := &proxyproto.Listener{
		Listener:          base,
		ConnPolicy:        policy,
		ReadHeaderTimeout: time.Duration(cfg.HeaderTimeoutSecs) * time.Second,
	}
	if len(cfg.TrustedProxies) == 0 {
		log.Warningf("PROXY protocol recon listener on %q has no trustedProxies configured; "+
			"a valid header is required from every source but addresses are not restricted - "+
			"ensure this port is reachable only by your proxy", cfg.ReconAddr)
	}
	log.Infof("listening for PROXY protocol recon on %q (trustedProxies=%v)", cfg.ReconAddr, cfg.TrustedProxies)
	return ln, nil
}

// proxyProtocolPolicy returns a PROXY protocol policy that requires a valid
// header on every accepted connection. When trustedProxies is non-empty, only
// connections originating from those addresses are allowed; all others are
// dropped before the recon handshake (so a forged header cannot be used to
// impersonate a partner). When empty, a valid header is required from every
// source but the source address itself is not restricted.
//
// Note: unlike proxyproto.StrictWhiteListPolicy (which returns USE, making the
// header optional, and REJECT without an error so the connection is still
// handed to the caller), this returns REQUIRE for trusted sources and
// ErrInvalidUpstream for the rest, which causes the listener to close and skip
// untrusted connections immediately.
func proxyProtocolPolicy(trustedProxies []string) (proxyproto.ConnPolicyFunc, error) {
	matchers, err := parseProxyMatchers(trustedProxies)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		if len(matchers) == 0 {
			return proxyproto.REQUIRE, nil
		}
		ip := remoteIP(opts.Upstream)
		if ip == nil {
			return proxyproto.REJECT, proxyproto.ErrInvalidUpstream
		}
		for _, match := range matchers {
			if match(ip) {
				return proxyproto.REQUIRE, nil
			}
		}
		return proxyproto.REJECT, proxyproto.ErrInvalidUpstream
	}, nil
}

// parseProxyMatchers compiles a list of IP / CIDR strings into membership tests.
func parseProxyMatchers(trustedProxies []string) ([]func(net.IP) bool, error) {
	matchers := make([]func(net.IP) bool, 0, len(trustedProxies))
	for _, entry := range trustedProxies {
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			matchers = append(matchers, ipNet.Contains)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			matchers = append(matchers, ip.Equal)
			continue
		}
		return nil, errors.Errorf("invalid trusted proxy %q (want an IP or CIDR)", entry)
	}
	return matchers, nil
}

func (p *Peer) acceptLoop(ln net.Listener) error {
	p.t.Go(func() error {
		<-p.t.Dying()
		return ln.Close()
	})

	for {
		conn, err := ln.Accept()
		if err != nil {
			return errors.WithStack(err)
		}

		p.muDie.Lock()
		if p.isDying() {
			conn.Close()
			p.muDie.Unlock()
			return nil
		}
		// Authorization (and, for a PROXY-protocol connection, parsing the
		// header) happens inside the per-connection goroutine rather than in
		// the accept loop, so that a slow or stalled connection cannot block
		// acceptance of other connections.
		p.t.Go(func() error {
			defer conn.Close()

			partner := p.matchConn(conn)
			if partner == nil {
				return nil
			}

			err := p.Accept(conn, partner)
			start := time.Now()
			recordReconInitiate(conn.RemoteAddr(), SERVER)
			if errors.Is(err, ErrPeerBusy) {
				p.logConnErr(GOSSIP, conn, err).Debug()
				recordReconBusyPeer(conn.RemoteAddr(), SERVER)
			} else if err != nil {
				p.logErr(SERVE, err).Errorf("recon with %v failed", conn.RemoteAddr())
				partner.LastIncomingError = err
				recordReconFailure(conn.RemoteAddr(), time.Since(start), SERVER)
			} else {
				partner.LastIncomingError = nil
				partner.LastIncomingRecon = start
				recordReconSuccess(conn.RemoteAddr(), time.Since(start), SERVER)
			}
			return nil
		})
		p.muDie.Unlock()
	}
}

// matchConn configures keepalive on the underlying TCP connection and resolves
// the connection's remote IP against the partner matcher. It returns nil (and
// logs the rejection) if the connection is unsupported or unauthorized. The
// remote address is taken from conn.RemoteAddr(), which for a PROXY-protocol
// connection reflects the real client address from the parsed header.
func (p *Peer) matchConn(conn net.Conn) *Partner {
	if tcpConn, ok := underlyingTCPConn(conn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	}

	ip := remoteIP(conn.RemoteAddr())
	if ip == nil {
		log.Warningf("unsupported connection from %q", conn.RemoteAddr())
		return nil
	}
	partner := p.matcher.Match(ip)
	if partner == nil {
		log.Warningf("connection rejected from %q", conn.RemoteAddr())
		return nil
	}
	return partner
}

// underlyingTCPConn returns the *net.TCPConn backing conn, unwrapping a
// PROXY-protocol connection if necessary, so that TCP keepalive can be set.
func underlyingTCPConn(conn net.Conn) (*net.TCPConn, bool) {
	switch c := conn.(type) {
	case *net.TCPConn:
		return c, true
	case *proxyproto.Conn:
		return c.TCPConn()
	}
	return nil, false
}

// remoteIP extracts the IP from a net.Addr, tolerating both the structured
// *net.TCPAddr case and string-form addresses.
func remoteIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

var defaultTimeout = 300 * time.Second

func (p *Peer) setReadDeadline(conn net.Conn, d time.Duration) {
	err := conn.SetReadDeadline(time.Now().Add(d))
	if err != nil {
		log.Warningf("failed to set read deadline: %v", err)
	}
}

func (p *Peer) remoteConfig(conn net.Conn, role string, config *Config) (*Config, error) {
	var remoteConfig *Config
	w := bufio.NewWriter(conn)

	ch := make(chan struct{})
	var t tomb.Tomb
	t.Go(func() error {
		<-ch
		return nil
	})
	t.Go(func() error {
		<-ch
		p.logConnFields(role, conn, log.Fields{"config": config}).Debug("writing config")
		err := WriteMsg(w, config)
		if err != nil {
			return errors.WithStack(err)
		}
		err = w.Flush()
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	t.Go(func() error {
		<-ch
		p.logConn(role, conn).Debug("reading remote config")
		var msg ReconMsg
		msg, err := ReadMsg(conn)
		if err != nil {
			return errors.WithStack(err)
		}

		rconf, ok := msg.(*Config)
		if !ok {
			return errors.Errorf("expected remote config, got %+v", msg)
		}

		remoteConfig = rconf
		return nil
	})
	close(ch)
	err := t.Wait()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return remoteConfig, nil
}

func (p *Peer) ackConfig(conn net.Conn) error {
	w := bufio.NewWriter(conn)

	ch := make(chan struct{})
	var t tomb.Tomb
	t.Go(func() error {
		<-ch
		return nil
	})
	t.Go(func() error {
		<-ch
		err := WriteString(w, RemoteConfigPassed)
		if err != nil {
			return errors.WithStack(err)
		}
		err = w.Flush()
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	t.Go(func() error {
		remoteConfigStatus, err := ReadString(conn)
		if err != nil {
			return errors.WithStack(err)
		}
		if remoteConfigStatus != RemoteConfigPassed {
			reason, err := ReadString(conn)
			if err != nil {
				return errors.Wrapf(ErrRemoteRejectedConfig, "remote rejected config: %v", err)
			}
			return errors.Wrap(ErrRemoteRejectedConfig, reason)
		}
		return nil
	})
	close(ch)
	return t.Wait()
}

func (p *Peer) handleConfig(conn net.Conn, role string, failResp string) (_ *Config, _err error) {
	p.setReadDeadline(conn, defaultTimeout)

	config, err := p.settings.Config()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteConfig, err := p.remoteConfig(conn, role, config)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	p.logConnFields(role, conn, log.Fields{"remoteConfig": remoteConfig}).Debug()

	if failResp == "" {
		if remoteConfig.Version != config.Version {
			failResp = "mismatched protocol version"
			p.logConnFields(role, conn, log.Fields{
				"remoteVersion": remoteConfig.Version,
				"localVersion":  config.Version,
			}).Error("mismatched protocol version")
		} else if remoteConfig.BitQuantum != config.BitQuantum {
			failResp = "mismatched bitquantum"
			p.logConnFields(role, conn, log.Fields{
				"remoteBitquantum": remoteConfig.BitQuantum,
				"localBitquantum":  config.BitQuantum,
			}).Error("mismatched BitQuantum values")
		} else if remoteConfig.MBar != config.MBar {
			failResp = "mismatched mbar"
			p.logConnFields(role, conn, log.Fields{
				"remoteMBar": remoteConfig.MBar,
				"localMBar":  config.MBar,
			}).Error("mismatched MBar")
		} else if remoteConfig.Filters != config.Filters {
			// NB: this does not parse Filters, so the filters MUST be sorted
			failResp = "mismatched filters"
			p.logConnFields(role, conn, log.Fields{
				"remoteFilters": remoteConfig.Filters,
				"localFilters":  config.Filters,
			}).Error("mismatched filters")
		}
	}

	w := bufio.NewWriter(conn)
	if failResp != "" {
		err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			p.logConnErr(role, conn, err)
		}

		err = WriteString(w, RemoteConfigFailed)
		if err != nil {
			p.logConnErr(role, conn, err)
		}
		err = WriteString(w, failResp)
		if err != nil {
			p.logConnErr(role, conn, err)
		}
		err = w.Flush()
		if err != nil {
			p.logConnErr(role, conn, err)
		}

		return nil, errors.Errorf("cannot peer: %v", failResp)
	}

	err = p.ackConfig(conn)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return remoteConfig, nil
}

func (p *Peer) Accept(conn net.Conn, partner *Partner) (_err error) {
	p.log(SERVE).Infof("accepted recon from [%s]", partner.String())
	defer func() {
		if _err != nil {
			p.logConnErr(SERVE, conn, _err).Error()
		}
	}()

	var failResp string
	if p.readAcquire() {
		defer p.readRelease()
	} else {
		failResp = "sync not available, currently mutating"
	}

	remoteConfig, err := p.handleConfig(conn, SERVE, failResp)
	if err != nil {
		// Remote peer is responsive but unable to recon
		if p.handler != nil {
			p.handler.ReconUnavailable(partner)
		}
		return errors.WithStack(err)
	}
	if p.handler != nil {
		p.handler.ReconStarted(partner)
	}

	if failResp == "" {
		return p.interactWithClient(conn, remoteConfig, partner, cf.NewBitstring(0))
	}
	return nil
}

type requestEntry struct {
	node PrefixNode
	key  *cf.Bitstring
}

func (r *requestEntry) String() string {
	if r == nil {
		return "nil"
	}
	return fmt.Sprintf("Request entry key=%v", r.key)
}

type bottomEntry struct {
	*requestEntry
	state reconState
}

func (r *bottomEntry) String() string {
	if r == nil {
		return "nil"
	} else if r.requestEntry == nil {
		return fmt.Sprintf("Bottom entry req=nil state=%v", r.state)
	}
	return fmt.Sprintf("Bottom entry key=%v state=%v", r.key, r.state)
}

type reconState uint8

const (
	reconStateBottom     = reconState(iota)
	reconStateFlushEnded = reconState(iota)
)

func (rs reconState) String() string {
	switch rs {
	case reconStateFlushEnded:
		return "Flush Ended"
	case reconStateBottom:
		return "Bottom"
	}
	return "Unknown"
}

const maxRequestQueueLen = 60000

type reconWithClient struct {
	*Peer
	requestQ []*requestEntry
	bottomQ  []*bottomEntry
	rcvrSet  *cf.ZSet
	flushing bool
	conn     net.Conn
	bwr      *bufio.Writer
	messages []ReconMsg
}

func (rwc *reconWithClient) pushBottom(bottom *bottomEntry) {
	rwc.bottomQ = append(rwc.bottomQ, bottom)
}

func (rwc *reconWithClient) prependRequests(req ...*requestEntry) {
	if len(rwc.requestQ) < maxRequestQueueLen {
		rwc.requestQ = append(req, rwc.requestQ...)
	}
}

func (rwc *reconWithClient) pushRequest(req *requestEntry) {
	rwc.requestQ = append(rwc.requestQ, req)
}

func (rwc *reconWithClient) topBottom() *bottomEntry {
	if len(rwc.bottomQ) == 0 {
		return nil
	}
	return rwc.bottomQ[0]
}

func (rwc *reconWithClient) popBottom() *bottomEntry {
	if len(rwc.bottomQ) == 0 {
		return nil
	}
	result := rwc.bottomQ[0]
	rwc.bottomQ = rwc.bottomQ[1:]
	return result
}

func (rwc *reconWithClient) popRequest() *requestEntry {
	if len(rwc.requestQ) == 0 {
		return nil
	}
	result := rwc.requestQ[0]
	rwc.requestQ = rwc.requestQ[1:]
	return result
}

func (rwc *reconWithClient) isDone() bool {
	return len(rwc.requestQ) == 0 && len(rwc.bottomQ) == 0
}

func (rwc *reconWithClient) sendRequest(p *Peer, req *requestEntry) error {
	if req == nil {
		return errors.New("nil request")
	}

	var msg ReconMsg
	if req.node.IsLeaf() || (req.node.Size() < p.settings.MBar) {
		elements, err := req.node.Elements()
		if err != nil {
			return errors.WithStack(err)
		}
		msg = &ReconRqstFull{
			Prefix:   req.key,
			Elements: cf.NewZSetSlice(elements)}
	} else {
		msg = &ReconRqstPoly{
			Prefix:  req.key,
			Size:    req.node.Size(),
			Samples: req.node.SValues()}
	}
	p.logConnFields(SERVE, rwc.conn, log.Fields{"msg": msg}).Debug("sendRequest")
	rwc.messages = append(rwc.messages, msg)
	rwc.pushBottom(&bottomEntry{requestEntry: req})
	return nil
}

func (rwc *reconWithClient) handleReply(msg ReconMsg, req *requestEntry) error {
	rwc.Peer.logConnFields(SERVE, rwc.conn, log.Fields{"msg": msg}).Debug("handleReply")
	switch m := msg.(type) {
	case *SyncFail:
		if req.node.IsLeaf() {
			return errors.New("Syncfail received at leaf node")
		}
		rwc.Peer.logConn(SERVE, rwc.conn).Debug("SyncFail: pushing children")
		children, err := req.node.Children()
		if err != nil {
			return errors.WithStack(err)
		}
		for i, childNode := range children {
			rwc.Peer.logConnFields(SERVE, rwc.conn, log.Fields{"childNode": childNode.Key()}).Debug("push")
			if i == 0 {
				rwc.pushRequest(&requestEntry{key: childNode.Key(), node: childNode})
			} else {
				rwc.prependRequests(&requestEntry{key: childNode.Key(), node: childNode})
			}
		}
	case *Elements:
		rwc.rcvrSet.AddAll(m.ZSet)
	case *FullElements:
		elements, err := req.node.Elements()
		if err != nil {
			return errors.WithStack(err)
		}
		local := cf.NewZSetSlice(elements)
		localNeeds := cf.ZSetDiff(m.ZSet, local)
		remoteNeeds := cf.ZSetDiff(local, m.ZSet)
		elementsMsg := &Elements{ZSet: remoteNeeds}
		rwc.Peer.logConnFields(SERVE, rwc.conn, log.Fields{
			"msg": elementsMsg,
		}).Debug("handleReply: sending")
		rwc.messages = append(rwc.messages, elementsMsg)
		rwc.rcvrSet.AddAll(localNeeds)
	default:
		return errors.Errorf("unexpected message: %v", m)
	}
	return nil
}

func (rwc *reconWithClient) flushQueue() error {
	rwc.Peer.logConn(SERVE, rwc.conn).Debug("flush queue")
	rwc.messages = append(rwc.messages, &Flush{})
	err := WriteMsg(rwc.bwr, rwc.messages...)
	if err != nil {
		return errors.Wrap(err, "error writing messages")
	}
	err = rwc.bwr.Flush()
	if err != nil {
		return errors.WithStack(err)
	}
	rwc.messages = nil
	rwc.pushBottom(&bottomEntry{state: reconStateFlushEnded})
	rwc.flushing = true
	return nil
}

func (p *Peer) interactWithClient(conn net.Conn, remoteConfig *Config, partner *Partner, bitstring *cf.Bitstring) error {
	p.logConn(SERVE, conn).Debug("interacting with client")
	p.setReadDeadline(conn, defaultTimeout)

	recon := reconWithClient{
		Peer:    p,
		conn:    conn,
		bwr:     bufio.NewWriter(conn),
		rcvrSet: cf.NewZSet(),
	}
	root, err := p.ptree.Root()
	if err != nil {
		return errors.WithStack(err)
	}

	defer func() {
		p.sendItems(recon.rcvrSet.Items(), conn, remoteConfig, partner, SERVE)
	}()
	defer func() {
		WriteMsg(recon.bwr, &Done{})
	}()

	recon.pushRequest(&requestEntry{node: root, key: bitstring})
	for !recon.isDone() {
		bottom := recon.topBottom()
		p.logConnFields(SERVE, conn, log.Fields{"bottom": bottom}).Debug("interact")
		switch {
		case bottom == nil:
			req := recon.popRequest()
			p.logConnFields(SERVE, conn, log.Fields{
				"popRequest": req,
			}).Debug("interact: sending...")
			err = recon.sendRequest(p, req)
			if err != nil {
				return errors.WithStack(err)
			}
		case bottom.state == reconStateFlushEnded:
			p.logConn(SERVE, conn).Debug("interact: flush ended, popBottom")
			recon.popBottom()
			recon.flushing = false
		case bottom.state == reconStateBottom:
			p.logConnFields(SERVE, conn, log.Fields{
				"queueLength": len(recon.bottomQ),
			}).Debug()
			var msg ReconMsg
			var hasMsg bool

			// Set a small read timeout to simulate non-blocking I/O
			p.setReadDeadline(conn, time.Millisecond)
			msg, nbErr := ReadMsg(conn)
			hasMsg = (nbErr == nil)

			// Restore blocking I/O
			p.setReadDeadline(conn, defaultTimeout)

			if hasMsg {
				recon.popBottom()
				err = recon.handleReply(msg, bottom.requestEntry)
				if err != nil {
					return errors.WithStack(err)
				}
			} else if len(recon.bottomQ) > p.settings.MaxOutstandingReconRequests ||
				len(recon.requestQ) == 0 {
				if !recon.flushing {
					err = recon.flushQueue()
					if err != nil {
						return errors.WithStack(err)
					}
				} else {
					recon.popBottom()
					p.setReadDeadline(conn, 3*time.Second)
					msg, err = ReadMsg(conn)
					if err != nil {
						return errors.WithStack(err)
					}
					p.logConnFields(SERVE, conn, log.Fields{"msg": msg}).Debug("reply")
					err = recon.handleReply(msg, bottom.requestEntry)
					if err != nil {
						return errors.WithStack(err)
					}
				}
			} else {
				req := recon.popRequest()
				err = recon.sendRequest(p, req)
				if err != nil {
					return errors.WithStack(err)
				}
			}
		default:
			return errors.New("failed to match expected patterns")
		}
	}
	p.logConn(SERVE, conn).Info("reconciliation done")
	return nil
}

func (p *Peer) sendItems(items []cf.Zp, conn net.Conn, remoteConfig *Config, partner *Partner, context string) error {
	if len(items) > 0 && p.t.Alive() {
		done := make(chan struct{})
		select {
		case p.RecoverChan <- &Recover{
			Partner:        partner,
			RemoteAddr:     conn.RemoteAddr(),
			RemoteConfig:   remoteConfig,
			RemoteElements: items,
			Done:           done,
		}:
			p.logConn(context, conn).Infof("recovering %d items", len(items))
			<-done
			p.logConn(context, conn).Info("recovery complete")
			recordItemsRecovered(conn.RemoteAddr(), len(items))
		default:
			p.mu.Lock()
			p.full = true
			p.mu.Unlock()
		}
	}
	return nil
}
