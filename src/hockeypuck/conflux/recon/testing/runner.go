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

// Package testing provides some unit-testing support functions.
package testing

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	gc "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"

	cf "hockeypuck/conflux"
	"hockeypuck/conflux/recon"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

var ShortDelay = time.Duration(30 * time.Millisecond)
var LongTimeout = time.Duration(30 * time.Second)

type Cleanup func()

type PtreeFactory func() (recon.PrefixTree, Cleanup, error)

type ReconSuite struct {
	Factory PtreeFactory

	sock string
}

func NewReconSuite(factory PtreeFactory) *ReconSuite {
	return &ReconSuite{
		Factory: factory,
	}
}

func (s *ReconSuite) pollRootConvergence(c *gc.C, peer1, peer2 *recon.Peer, ptree1, ptree2 recon.PrefixTree) error {
	var t tomb.Tomb
	var mu sync.Mutex
	zs1 := cf.NewZSet()
	zs2 := cf.NewZSet()
	defer peer1.Stop()
	peer1.SetMutatedFunc(func() {
		mu.Lock()
		root1, err := ptree1.Root()
		c.Assert(err, gc.IsNil)
		newZs := cf.NewZSetSlice(recon.MustElements(root1))
		*zs1 = *newZs
		c.Logf("peer1 now has %q", zs1)
		mu.Unlock()
	})
	defer peer2.Stop()
	peer2.SetMutatedFunc(func() {
		mu.Lock()
		root2, err := ptree2.Root()
		c.Assert(err, gc.IsNil)
		newZs := cf.NewZSetSlice(recon.MustElements(root2))
		*zs2 = *newZs
		c.Logf("peer2 now has %q", zs2)
		mu.Unlock()
	})
	t.Go(func() error {
		for {
			select {
			case r1, ok := <-peer1.RecoverChan:
				if !ok {
					return nil
				}
				c.Logf("peer1 recover: %v", r1)
				for _, zp := range r1.RemoteElements {
					c.Assert(zp, gc.NotNil)
					peer1.Insert(zp)
				}
				close(r1.Done)
			case <-time.After(ShortDelay):
				mu.Lock()
				if zs1.Len() > 0 && zs1.Equal(zs2) {
					c.Logf("done: peer1 has %q, peer2 has %q", zs1, zs2)
					t.Kill(nil)
					mu.Unlock()
					return nil
				} else {
					c.Logf("reconciling: peer1 has %q, peer2 has %q", zs1, zs2)
				}
				mu.Unlock()
			case <-t.Dying():
				return nil
			}
		}
	})
	t.Go(func() error {
		for {
			select {
			case r2, ok := <-peer2.RecoverChan:
				if !ok {
					return nil
				}
				c.Logf("peer2 recover: %v", r2)
				for _, zp := range r2.RemoteElements {
					c.Assert(zp, gc.NotNil)
					peer2.Insert(zp)
				}
				close(r2.Done)
			case <-time.After(ShortDelay):
				mu.Lock()
				if zs1.Len() > 0 && zs1.Equal(zs2) {
					c.Logf("done: peer1 has %q, peer2 has %q", zs1, zs2)
					t.Kill(nil)
					mu.Unlock()
					return nil
				} else {
					c.Logf("reconciling: peer1 has %q, peer2 has %q", zs1, zs2)
				}
				mu.Unlock()
			case <-t.Dying():
				return nil
			}
		}
	})
	t.Go(func() error {
		select {
		case <-time.After(LongTimeout):
			panic("timeout waiting for convergence")
		case <-t.Dying():
			return nil
		}
	})
	return t.Wait()
}

func (s *ReconSuite) pollConvergence(c *gc.C, peer1, peer2 *recon.Peer, peer1Needs, peer2Needs *cf.ZSet, timeout time.Duration) error {
	var t tomb.Tomb
	timer := time.NewTimer(timeout)
	defer peer1.Stop()
	defer peer2.Stop()
	t.Go(func() error {
	POLLING:
		for {
			select {
			case r1, ok := <-peer1.RecoverChan:
				if !ok {
					break POLLING
				}
				c.Logf("peer1 recover: %v", r1)
				peer1.Insert(r1.RemoteElements...)
				peer1Needs.RemoveSlice(r1.RemoteElements)
				close(r1.Done)
			case <-timer.C:
				c.Log("peer1 still needed ", peer1Needs.Len(), ":", peer1Needs)
				return fmt.Errorf("timeout waiting for convergence")
			case <-time.After(ShortDelay):
				if peer2Needs.Len() == 0 {
					c.Log("all done!")
					return nil
				}
			}
		}
		return fmt.Errorf("set reconciliation did not converge")
	})
	t.Go(func() error {
	POLLING:
		for {
			select {
			case r2, ok := <-peer2.RecoverChan:
				if !ok {
					break POLLING
				}
				c.Logf("peer2 recover: %v", r2)
				peer2.Insert(r2.RemoteElements...)
				peer2Needs.RemoveSlice(r2.RemoteElements)
				close(r2.Done)
			case <-timer.C:
				c.Log("peer2 still needed ", peer2Needs.Len(), ":", peer2Needs)
				return fmt.Errorf("timeout waiting for convergence")
			case <-time.After(ShortDelay):
				if peer2Needs.Len() == 0 {
					c.Log("all done!")
					return nil
				}
			}
		}
		return fmt.Errorf("set reconciliation did not converge")
	})
	return t.Wait()
}

func portPair(c *gc.C) (int, int) {
	l1, err := net.Listen("tcp", ":0")
	c.Assert(err, gc.IsNil)
	l2, err := net.Listen("tcp", ":0")
	c.Assert(err, gc.IsNil)
	c.Assert(l1.Close(), gc.IsNil)
	c.Assert(l2.Close(), gc.IsNil)
	p1, p2 := l1.Addr().(*net.TCPAddr).Port, l2.Addr().(*net.TCPAddr).Port
	c.Assert(p1, gc.Not(gc.Equals), p2)
	return p1, p2
}

func (s *ReconSuite) newPeer(listenPort, partnerPort int, mode recon.PeerMode, ptree recon.PrefixTree) *recon.Peer {
	settings := recon.DefaultSettings()
	settings.ReconAddr = fmt.Sprintf(":%d", listenPort)
	partnerAddr := fmt.Sprintf("localhost:%d", partnerPort)
	settings.Partners[partnerAddr] = recon.Partner{
		ReconAddr: partnerAddr,
	}
	settings.AllowCIDRs = []string{"0.0.0.0/0"}
	settings.GossipIntervalSecs = 2
	peer := recon.NewPeer(settings, ptree)
	peer.StartMode(mode)
	return peer
}

// Test full node sync.
func (s *ReconSuite) TestFullSync(c *gc.C) {
	ptree1, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	ptree2, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	ptree1.Insert(cf.Zi(cf.P_SKS, 65537))
	ptree1.Insert(cf.Zi(cf.P_SKS, 65539))
	root, _ := ptree1.Root()
	c.Log("peer1:", recon.MustElements(root))

	ptree2.Insert(cf.Zi(cf.P_SKS, 65537))
	ptree2.Insert(cf.Zi(cf.P_SKS, 65541))
	root, _ = ptree2.Root()
	c.Log("peer2:", recon.MustElements(root))

	port1, port2 := portPair(c)
	peer1 := s.newPeer(port1, port2, recon.PeerModeGossipOnly, ptree1)
	peer2 := s.newPeer(port2, port1, recon.PeerModeServeOnly, ptree2)

	err = s.pollRootConvergence(c, peer1, peer2, ptree1, ptree2)
	c.Assert(err, gc.IsNil)
}

// Test sync with polynomial interpolation.
func (s *ReconSuite) TestPolySyncMBar(c *gc.C) {
	ptree1, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	ptree2, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	onlyInPeer1 := cf.NewZSet()
	// Load up peer 1 with items
	for i := 1; i < 100; i++ {
		ptree1.Insert(cf.Zi(cf.P_SKS, 65537*i))
	}
	// Four extra samples
	for i := 1; i < 5; i++ {
		z := cf.Zi(cf.P_SKS, 68111*i)
		ptree1.Insert(z)
		onlyInPeer1.Add(z)
	}
	root, _ := ptree1.Root()
	c.Log("peer1:", recon.MustElements(root))

	onlyInPeer2 := cf.NewZSet()
	// Load up peer 2 with items
	for i := 1; i < 100; i++ {
		ptree2.Insert(cf.Zi(cf.P_SKS, 65537*i))
	}
	// One extra sample
	for i := 1; i < 2; i++ {
		z := cf.Zi(cf.P_SKS, 70001*i)
		ptree2.Insert(z)
		onlyInPeer2.Add(z)
	}
	root, _ = ptree2.Root()
	c.Log("peer2:", recon.MustElements(root))

	port1, port2 := portPair(c)
	peer1 := s.newPeer(port1, port2, recon.PeerModeGossipOnly, ptree1)
	peer2 := s.newPeer(port2, port1, recon.PeerModeServeOnly, ptree2)

	err = s.pollConvergence(c, peer1, peer2, onlyInPeer2, onlyInPeer1, LongTimeout)
	c.Assert(err, gc.IsNil)
}

// Test sync with polynomial interpolation.
func (s *ReconSuite) TestPolySyncLowMBar(c *gc.C) {
	ptree1, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	ptree2, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	onlyInPeer1 := cf.NewZSet()
	for i := 1; i < 100; i++ {
		ptree1.Insert(cf.Zi(cf.P_SKS, 65537*i))
	}
	// extra samples
	for i := 1; i < 50; i++ {
		z := cf.Zi(cf.P_SKS, 68111*i)
		onlyInPeer1.Add(z)
		ptree1.Insert(z)
	}
	root1, _ := ptree1.Root()
	c.Log("peer1:", recon.MustElements(root1))

	onlyInPeer2 := cf.NewZSet()
	for i := 1; i < 100; i++ {
		ptree2.Insert(cf.Zi(cf.P_SKS, 65537*i))
	}
	// extra samples
	for i := 1; i < 20; i++ {
		z := cf.Zi(cf.P_SKS, 70001*i)
		onlyInPeer2.Add(z)
		ptree2.Insert(z)
	}
	root2, _ := ptree2.Root()
	c.Log("peer2:", recon.MustElements(root2))

	port1, port2 := portPair(c)
	peer1 := s.newPeer(port1, port2, recon.PeerModeGossipOnly, ptree1)
	peer2 := s.newPeer(port2, port1, recon.PeerModeServeOnly, ptree2)

	err = s.pollConvergence(c, peer1, peer2, onlyInPeer2, onlyInPeer1, LongTimeout)
	c.Assert(err, gc.IsNil)
}

func (s *ReconSuite) RunOneSided(c *gc.C, n int, serverHas bool, timeout time.Duration) {
	ptree1, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	ptree2, cleanup, err := s.Factory()
	c.Assert(err, gc.IsNil)
	defer cleanup()

	expected := cf.NewZSet()

	for i := 1; i < n; i++ {
		z := cf.Zi(cf.P_SKS, 65537*i)
		ptree2.Insert(z)
		expected.Add(z)
	}

	port1, port2 := portPair(c)
	var peer1Mode recon.PeerMode
	var peer2Mode recon.PeerMode
	if serverHas {
		peer1Mode = recon.PeerModeGossipOnly
		peer2Mode = recon.PeerModeServeOnly
	} else {
		peer1Mode = recon.PeerModeServeOnly
		peer2Mode = recon.PeerModeGossipOnly
	}

	peer1 := s.newPeer(port1, port2, peer1Mode, ptree1)
	peer2 := s.newPeer(port2, port1, peer2Mode, ptree2)

	err = s.pollConvergence(c, peer1, peer2, expected, cf.NewZSet(), timeout)
	c.Assert(err, gc.IsNil)
}
