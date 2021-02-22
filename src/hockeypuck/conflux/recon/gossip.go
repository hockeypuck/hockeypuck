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
	"math/rand"
	"net"
	"time"

	"github.com/pkg/errors"
	log "hockeypuck/logrus"

	cf "hockeypuck/conflux"
)

const GOSSIP = "gossip"

// skewedGossipInterval returns the configured gossip interval
// with a randomised skew of between +/-10%, giving 90% to 110%
// of the configured interval.
func (p *Peer) skewedGossipInterval() time.Duration {
	interval := float32(p.settings.GossipIntervalSecs)
	base := time.Duration(interval * 0.9)
	skew := time.Duration(rand.Intn(int(interval*0.2) + 1))
	return (base + skew) * time.Second
}

// Gossip with remote servers, acting as a client.
func (p *Peer) Gossip() error {
	rand.Seed(time.Now().UnixNano())
	timer := time.NewTimer(p.skewedGossipInterval())
	for {
		select {
		case <-p.t.Dying():
			return nil
		case <-timer.C:

			if p.readAcquire() {
				peer, err := p.choosePartner()
				if err != nil {
					if errors.Is(err, ErrNoPartners) {
						p.log(GOSSIP).Debug("no partners to gossip with")
					} else {
						p.logErr(GOSSIP, err).Error("choosePartner")
					}
				} else {
					start := time.Now()
					recordReconInitiate(peer, CLIENT)
					err = p.InitiateRecon(peer)
					if errors.Is(err, ErrPeerBusy) {
						p.logErr(GOSSIP, err).Debug()
						recordReconBusyPeer(peer, CLIENT)
					} else if err != nil {
						p.logErr(GOSSIP, err).Errorf("recon with %v failed", peer)
						recordReconFailure(peer, time.Since(start), CLIENT)
					} else {
						recordReconSuccess(peer, time.Since(start), CLIENT)
					}
				}

				p.readRelease()
			}

			delay := p.skewedGossipInterval()
			p.log(GOSSIP).Infof("waiting %s for next gossip attempt", delay)
			timer.Reset(delay)
		}
	}
}

var ErrNoPartners error = fmt.Errorf("no recon partners configured")
var ErrIncompatiblePeer error = fmt.Errorf("remote peer configuration is not compatible")
var ErrPeerBusy error = fmt.Errorf("peer is busy handling another request")
var ErrReconDone = fmt.Errorf("reconciliation done")

func (p *Peer) choosePartner() (net.Addr, error) {
	partner, err := p.settings.RandomPartnerAddr()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if partner == nil {
		return nil, errors.WithStack(ErrNoPartners)
	}
	return partner, nil
}

func (p *Peer) InitiateRecon(addr net.Addr) error {
	p.log(GOSSIP).Debugf("initiating recon with peer %v", addr)
	conn, err := net.DialTimeout(addr.Network(), addr.String(), 30*time.Second)
	if err != nil {
		return errors.WithStack(err)
	}
	defer conn.Close()

	remoteConfig, err := p.handleConfig(conn, GOSSIP, "")
	if err != nil {
		return errors.WithStack(err)
	}

	// Interact with peer
	return p.clientRecon(conn, remoteConfig)
}

type msgProgress struct {
	elements *cf.ZSet
	err      error
	flush    bool
	messages []ReconMsg
}

func (mp *msgProgress) String() string {
	if mp.err != nil {
		return fmt.Sprintf("err=%v", mp.err)
	}
	return fmt.Sprintf("nelements=%d flush=%v messages=%+v",
		mp.elements.Len(), mp.flush, msgTypes(mp.messages))
}

func msgTypes(messages []ReconMsg) []string {
	var result []string
	for _, msg := range messages {
		result = append(result, msg.MsgType().String())
	}
	return result
}

type msgProgressChan chan *msgProgress

func (p *Peer) clientRecon(conn net.Conn, remoteConfig *Config) error {
	w := bufio.NewWriter(conn)
	respSet := cf.NewZSet()
	defer func() {
		p.sendItems(respSet.Items(), conn, remoteConfig)
	}()

	var pendingMessages []ReconMsg
	for step := range p.interactWithServer(conn) {
		if step.err != nil {
			if errors.Is(step.err, ErrReconDone) {
				p.logConn(GOSSIP, conn).Info("reconcilation done")
				break
			} else {
				err := WriteMsg(w, &Error{&textMsg{Text: step.err.Error()}})
				if err != nil {
					p.logConnErr(GOSSIP, conn, err).Error()
				}
				p.logConnErr(GOSSIP, conn, step.err).Error("step error")
				break
			}
		} else {
			pendingMessages = append(pendingMessages, step.messages...)
			if step.flush {
				for _, msg := range pendingMessages {
					err := WriteMsg(w, msg)
					if err != nil {
						return errors.WithStack(err)
					}
				}
				pendingMessages = nil

				err := w.Flush()
				if err != nil {
					return errors.WithStack(err)
				}
			}
		}
		p.logConn(GOSSIP, conn).Debugf("add step: %v", step)
		respSet.AddAll(step.elements)
		p.logConn(GOSSIP, conn).Debugf("recover set now %d elements", respSet.Len())
	}
	return nil
}

func (p *Peer) interactWithServer(conn net.Conn) msgProgressChan {
	out := make(msgProgressChan)
	go func() {
		defer close(out)

		var resp *msgProgress
		var n int
		for resp == nil || resp.err == nil {
			p.setReadDeadline(conn, defaultTimeout)
			msg, err := ReadMsg(conn)
			if err != nil {
				p.logConnErr(GOSSIP, conn, err).Error("interact: read msg")
				out <- &msgProgress{err: err}
				return
			}
			p.logConnFields(GOSSIP, conn, log.Fields{"msg": msg}).Debug("interact")
			switch m := msg.(type) {
			case *ReconRqstPoly:
				resp = p.handleReconRqstPoly(m, conn)
			case *ReconRqstFull:
				resp = p.handleReconRqstFull(m, conn)
			case *Elements:
				p.logConnFields(GOSSIP, conn, log.Fields{"nelements": m.ZSet.Len()}).Debug()
				resp = &msgProgress{elements: m.ZSet}
			case *Done:
				resp = &msgProgress{err: ErrReconDone}
			case *Flush:
				resp = &msgProgress{elements: cf.NewZSet(), flush: true}
			default:
				resp = &msgProgress{err: errors.Errorf("unexpected message: %v", m)}
			}
			n += resp.elements.Len()
			out <- resp
		}
	}()
	return out
}

var ErrReconRqstPolyNotFound = fmt.Errorf(
	"peer should not receive a request for a non-existant node in ReconRqstPoly")

func (p *Peer) handleReconRqstPoly(rp *ReconRqstPoly, conn net.Conn) *msgProgress {
	remoteSize := rp.Size
	points := p.ptree.Points()
	remoteSamples := rp.Samples
	node, err := p.ptree.Node(rp.Prefix)
	if errors.Is(err, ErrNodeNotFound) {
		return &msgProgress{err: ErrReconRqstPolyNotFound}
	}
	localSamples := node.SValues()
	localSize := node.Size()
	remoteSet, localSet, err := p.solve(
		remoteSamples, localSamples, remoteSize, localSize, points, conn)
	if errors.Is(err, cf.ErrLowMBar) {
		p.logConn(GOSSIP, conn).Debug("ReconRqstPoly: low MBar")
		if node.IsLeaf() || node.Size() < (p.settings.ThreshMult*p.settings.MBar) {
			p.logConnFields(GOSSIP, conn, log.Fields{
				"node": node.Key(),
			}).Debug("sending full elements")
			elements, err := node.Elements()
			if err != nil {
				return &msgProgress{err: errors.WithStack(err)}
			}
			return &msgProgress{elements: cf.NewZSet(), messages: []ReconMsg{
				&FullElements{ZSet: cf.NewZSetSlice(elements)}}}
		} else {
			err = errors.Wrapf(err, "bs=%v leaf=%v size=%d", node.Key(), node.IsLeaf(), node.Size())
		}
	}
	if err != nil {
		p.logConnErr(GOSSIP, conn, err).Debug("ReconRqstPoly: sending SyncFail")
		return &msgProgress{elements: cf.NewZSet(), messages: []ReconMsg{&SyncFail{}}}
	}
	p.logConnFields(GOSSIP, conn, log.Fields{"localSet": localSet, "remoteSet": remoteSet}).Debug("ReconRqstPoly: solved")
	return &msgProgress{elements: remoteSet, messages: []ReconMsg{&Elements{ZSet: localSet}}}
}

func (p *Peer) solve(remoteSamples, localSamples []cf.Zp, remoteSize, localSize int, points []cf.Zp, conn net.Conn) (*cf.ZSet, *cf.ZSet, error) {
	values := make([]cf.Zp, len(remoteSamples))
	for i := range remoteSamples {
		values[i].Div(&remoteSamples[i], &localSamples[i])
	}
	p.logConnFields(GOSSIP, conn, log.Fields{
		"values":  values,
		"points":  points,
		"degDiff": remoteSize - localSize,
	}).Debug("reconcile")
	return cf.Reconcile(values, points, remoteSize-localSize)
}

func (p *Peer) handleReconRqstFull(rf *ReconRqstFull, conn net.Conn) *msgProgress {
	var localset *cf.ZSet
	node, err := p.ptree.Node(rf.Prefix)
	if errors.Is(err, ErrNodeNotFound) {
		localset = cf.NewZSet()
	} else if err != nil {
		return &msgProgress{err: err}
	} else {
		elements, err := node.Elements()
		if err != nil {
			return &msgProgress{err: err}
		}
		localset = cf.NewZSetSlice(elements)
	}
	localNeeds := cf.ZSetDiff(rf.Elements, localset)
	remoteNeeds := cf.ZSetDiff(localset, rf.Elements)
	p.logConnFields(GOSSIP, conn, log.Fields{
		"localNeeds":  localNeeds.Len(),
		"remoteNeeds": remoteNeeds.Len(),
	}).Debug("ReconRqstFull")
	return &msgProgress{elements: localNeeds, messages: []ReconMsg{&Elements{ZSet: remoteNeeds}}}
}
