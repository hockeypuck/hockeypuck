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

// Package recon provides the SKS reconciliation protocol, prefix tree interface
// and an in-memory prefix-tree implementation.
//
// The Conflux recon API is versioned with gopkg. Use in your projects with:
//
// import "hockeypuck/conflux/recon"
package recon

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmcvetta/randutil"
	"github.com/pkg/errors"
)

type PartnerMap map[string]Partner

type PTreeConfig struct {
	ThreshMult int `toml:"threshMult"`
	BitQuantum int `toml:"bitQuantum"`
	MBar       int `toml:"mBar"`
}

// Settings holds the configuration settings for the local reconciliation peer.
type Settings struct {
	PTreeConfig

	Version       string
	LogName       string     `toml:"logname" json:"-"`
	HTTPAddr      string     `toml:"httpAddr"`
	HTTPNet       netType    `toml:"httpNet" json:"-"`
	ReconAddr     string     `toml:"reconAddr"`
	ReconNet      netType    `toml:"reconNet" json:"-"`
	SeenCacheSize int        `toml:"seenCacheSize" json:"-"`
	Partners      PartnerMap `toml:"partner"`
	AllowCIDRs    []string   `toml:"allowCIDRs"`
	Filters       []string   `toml:"filters"`

	// Backwards-compatible keys
	CompatHTTPPort     int      `toml:"httpPort" json:"-"`
	CompatReconPort    int      `toml:"reconPort" json:"-"`
	CompatPartnerAddrs []string `toml:"partners" json:"-"`

	GossipIntervalSecs          int `toml:"gossipIntervalSecs" json:"-"`
	MaxOutstandingReconRequests int `toml:"maxOutstandingReconRequests" json:"-"`
}

type Partner struct {
	HTTPAddr  string  `toml:"httpAddr"`
	HTTPNet   netType `toml:"httpNet" json:"-"`
	ReconAddr string  `toml:"reconAddr"`
	ReconNet  netType `toml:"reconNet" json:"-"`
	Weight    int     `toml:"weight"`
	// WebAddr overwrites HTTPAddr on stats page where the server is supposed
	// to be accessed via a different domain/port than hockeypuck process.
	// e.g., when there is a reverse proxy or load balancer
	WebAddr string `toml:"webAddr"`
	// StatsPath is the endpoint of stats page on this peer
	StatsPath string `toml:"statsPath"`
	// Mask the HTTPAddr and ReconAddr shown in stats page
	Mask bool `toml:"mask"`
	// Name is a copy of the key used in the Settings map
	Name string
	// Addr is the resolved address last used by outgoing recon
	Addr net.Addr
	// IPs is the set of source IPs allowed for incoming recon
	IPs []net.IP
	// Log of successes and failures
	ReconStarted      time.Time
	LastIncomingRecon time.Time
	LastIncomingError error
	LastOutgoingRecon time.Time
	LastOutgoingError error
	// These are not used by conflux, but are provided so the caller can store recovery logs in a convenient place.
	LastRecovery      time.Time
	LastRecoveryError error
}

func (p *Partner) String() string {
	return fmt.Sprintf("recon=%s, http=%s, weight=%d, addr=%v, ips=%v", p.ReconAddr, p.HTTPAddr, p.Weight, p.Addr, p.IPs)
}

type matchAccessType uint8

const (
	matchAllowAccess matchAccessType = iota
)

type IPMatcher interface {
	Match(ip net.IP) *Partner
	RandomPartner() (*Partner, []error)
	CurrentPartners() []*Partner
}

type ipMatcher struct {
	nets     []*net.IPNet
	partners []*Partner
}

func (m *ipMatcher) CurrentPartners() []*Partner {
	return m.partners
}

func newIPMatcher() *ipMatcher {
	return &ipMatcher{}
}

func (m *ipMatcher) allow(name string, partner Partner) error {
	partner.updateIPs()
	partner.Name = name
	partner.ReconStarted = time.Now()
	m.partners = append(m.partners, &partner)
	return nil
}

func (partner *Partner) updateIPs() {
	if partner.ReconNet != NetworkDefault && partner.ReconNet != NetworkTCP {
		return
	}
	reconHostname, _, _ := net.SplitHostPort(partner.ReconAddr)
	ips, err := net.LookupIP(reconHostname)
	if err != nil {
		return
	}
	if partner.HTTPNet == NetworkDefault || partner.HTTPNet == NetworkTCP {
		httpHostname, _, err := net.SplitHostPort(partner.HTTPAddr)
		if err == nil {
			if reconHostname != httpHostname {
				httpIPs, err := net.LookupIP(httpHostname)
				if err == nil && reconHostname != httpHostname {
					ips = append(ips, httpIPs...)
				}
			}
		}
	}
	if len(ips) != 0 {
		partner.IPs = ips
	}
}

func (m *ipMatcher) allowCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return errors.WithStack(err)
	}
	m.nets = append(m.nets, ipnet)
	return nil
}

func (m *ipMatcher) Match(ip net.IP) *Partner {
	if ip.IsLoopback() {
		return &Partner{IPs: []net.IP{ip}, Addr: &net.IPAddr{IP: ip, Zone: ""}}
	}
	for _, matchNet := range m.nets {
		if matchNet.Contains(ip) {
			return &Partner{IPs: []net.IP{ip}, Addr: &net.IPAddr{IP: ip, Zone: ""}}
		}
	}
	for _, matchPartner := range m.partners {
		for _, matchIP := range matchPartner.IPs {
			if matchIP.Equal(ip) {
				return matchPartner
			}
		}
	}
	return nil
}

func (s *Settings) Matcher() (IPMatcher, error) {
	m := newIPMatcher()
	for _, allowCIDR := range s.AllowCIDRs {
		err := m.allowCIDR(allowCIDR)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	for k, partner := range s.Partners {
		err := m.allow(k, partner)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return m, nil
}

type netType string

const (
	NetworkDefault = netType("")
	NetworkTCP     = netType("tcp")
	NetworkUnix    = netType("unix")
)

// String implements the fmt.Stringer interface.
func (n netType) String() string {
	if n == "" {
		return string(NetworkTCP)
	}
	return string(n)
}

func (n netType) Resolve(addr string) (net.Addr, error) {
	switch n {
	case NetworkDefault, NetworkTCP:
		return net.ResolveTCPAddr("tcp", addr)
	case NetworkUnix:
		return net.ResolveUnixAddr("unix", addr)
	}
	return nil, errors.Errorf("don't know how to resolve network %q address %q", n, addr)
}

const (
	DefaultVersion                     = "1.1.6"
	DefaultLogName                     = "conflux.recon"
	DefaultHTTPAddr                    = ":11371"
	DefaultReconAddr                   = ":11370"
	DefaultSeenCacheSize               = 256
	DefaultGossipIntervalSecs          = 60
	DefaultMaxOutstandingReconRequests = 100

	DefaultThreshMult = 10
	DefaultBitQuantum = 2
	DefaultMBar       = 5
)

var defaultPTreeConfig = PTreeConfig{
	ThreshMult: DefaultThreshMult,
	BitQuantum: DefaultBitQuantum,
	MBar:       DefaultMBar,
}

var defaultFilters = []string{}

var defaultSettings = Settings{
	PTreeConfig: defaultPTreeConfig,

	Version:       DefaultVersion,
	LogName:       DefaultLogName,
	HTTPAddr:      DefaultHTTPAddr,
	ReconAddr:     DefaultReconAddr,
	SeenCacheSize: DefaultSeenCacheSize,
	Filters:       defaultFilters,

	GossipIntervalSecs:          DefaultGossipIntervalSecs,
	MaxOutstandingReconRequests: DefaultMaxOutstandingReconRequests,
}

// Resolve resolves network addresses and backwards-compatible settings. Use
// Resolve after decoding from TOML.
func (s *Settings) Resolve() error {
	if s.CompatHTTPPort != 0 {
		s.HTTPAddr = fmt.Sprintf(":%d", s.CompatHTTPPort)
	}
	if s.CompatReconPort != 0 {
		s.ReconAddr = fmt.Sprintf(":%d", s.CompatReconPort)
	}
	if len(s.CompatPartnerAddrs) > 0 {
		s.Partners = PartnerMap{}
		for _, partnerAddr := range s.CompatPartnerAddrs {
			host, _, err := net.SplitHostPort(partnerAddr)
			if err != nil {
				return errors.Wrapf(err, "invalid 'partners' address %q", partnerAddr)
			}
			p := Partner{
				HTTPAddr:  fmt.Sprintf("%s:11371", host),
				ReconAddr: partnerAddr,
			}
			s.Partners[host] = p
		}
	}

	_, err := s.HTTPNet.Resolve(s.HTTPAddr)
	if err != nil {
		return errors.Wrapf(err, "invalid httpNet %q httpAddr %q", s.HTTPNet, s.HTTPAddr)
	}
	if s.ReconAddr != "none" {
		_, err = s.ReconNet.Resolve(s.ReconAddr)
		if err != nil {
			return errors.Wrapf(err, "invalid reconNet %q reconAddr %q", s.ReconNet, s.ReconAddr)
		}
	}

	return nil
}

func (s *Settings) AddFilters(newFilters []string) error {
	// Site-defined filters are combined with the defaults
	s.Filters = append(s.Filters, newFilters...)
	sort.Strings(s.Filters)
	// Remove adjacent duplicates from sorted slice (https://codereview.stackexchange.com/a/241735)
	// Stop one before the end because we use a lookahead
	for i := 0; i < len(s.Filters)-1; {
		if s.Filters[i] == s.Filters[i+1] {
			// If lookahead sees a duplicate, remove the CURRENT item and *don't* increment the counter
			s.Filters = append(s.Filters[:i], s.Filters[i+1:]...)
		} else {
			i++
		}
	}
	return nil
}

// ParseSettings parses a TOML-formatted string representation into Settings.
func ParseSettings(data string) (*Settings, error) {
	var doc struct {
		Conflux struct {
			Recon Settings `toml:"recon"`
		} `toml:"conflux"`
	}
	defaults := DefaultSettings()
	doc.Conflux.Recon = *defaults
	_, err := toml.Decode(data, &doc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	settings := &doc.Conflux.Recon
	err = settings.Resolve()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sort.Strings(settings.Filters)
	return settings, nil
}

// DefaultSettings returns default peer configuration settings.
func DefaultSettings() *Settings {
	settings := defaultSettings
	settings.Partners = make(PartnerMap)
	sort.Strings(settings.Filters)
	return &settings
}

func resolveHTTPPortTCP(addr net.Addr) (int, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return 0, false
	}
	return tcpAddr.Port, true
}

var resolveHTTPPort = resolveHTTPPortTCP

// Config returns a recon protocol config message that described this
// peer's configuration settings.
func (s *Settings) Config() (*Config, error) {
	config := &Config{
		Version:    s.Version,
		BitQuantum: s.BitQuantum,
		MBar:       s.MBar,
		Filters:    strings.Join(s.Filters, ","),
	}

	// Try to obtain httpPort
	addr, err := s.HTTPNet.Resolve(s.HTTPAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid httpNet %q httpAddr %q", s.HTTPNet, s.HTTPAddr)
	}
	port, ok := resolveHTTPPort(addr)
	if !ok {
		return nil, errors.Errorf("cannot determine httpPort from httpNet %q httpAddr %q", s.HTTPNet, s.HTTPAddr)
	}
	config.HTTPPort = port
	return config, nil
}

// SplitThreshold returns the maximum number of elements a prefix tree node may
// contain before creating child nodes and distributing the elements among them.
func (c *PTreeConfig) SplitThreshold() int {
	return c.ThreshMult * c.MBar
}

// JoinThreshold returns the minimum cumulative number of elements under a
// prefix tree parent node, below which all child nodes are merged into the
// parent.
func (c *PTreeConfig) JoinThreshold() int {
	return c.SplitThreshold() / 2
}

// NumSamples returns the number of sample points used for interpolation.
// This must match among all reconciliation peers.
func (c *PTreeConfig) NumSamples() int {
	return c.MBar + 1
}

// RandomPartner returns a weighted-random chosen ip-resolved Partner.
func (m *ipMatcher) RandomPartner() (*Partner, []error) {
	var choices []randutil.Choice
	var errorList []error
	for index, partner := range m.partners {
		addr, err := partner.ReconNet.Resolve(partner.ReconAddr)
		if err == nil {
			// Freshen resolved IPs regularly
			m.partners[index].Addr = addr
			m.partners[index].updateIPs()
			weight := partner.Weight
			if weight == 0 {
				weight = 100
			}
			if weight > 0 {
				choices = append(choices, randutil.Choice{Weight: weight, Item: partner})
			}
		} else {
			errorList = append(errorList, err)
		}
	}
	if len(choices) == 0 {
		return nil, errorList
	}
	choice, err := randutil.WeightedChoice(choices)
	if err != nil {
		errorList = append(errorList, err)
		return nil, errorList
	}
	return choice.Item.(*Partner), errorList
}
