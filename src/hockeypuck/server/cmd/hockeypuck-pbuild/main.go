package main

import (
	"flag"

	"github.com/pkg/errors"

	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
	"hockeypuck/server/cmd"

	log "github.com/sirupsen/logrus"
)

func main() {
	flag.Parse()
	settings := cmd.Init(false)
	cmd.HandleSignals()
	err := pbuild(settings)
	cmd.Die(err)
}

func pbuild(settings *server.Settings) error {
	policyOptions := server.PolicyOptions(settings)
	policy, err := openpgp.NewPolicy(policyOptions...)
	if err != nil {
		return err
	}
	st, err := server.DialStorage(settings, policy)
	if err != nil {
		return errors.WithStack(err)
	}
	defer st.Close()

	// Instantiate an sks.Peer to handle KeyChange events, but don't Start() it
	peer, err := sks.NewPeer(st, settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings, nil, "", nil, policy)
	if err != nil {
		return errors.WithStack(err)
	}
	peer.Idle()
	defer peer.Stop()

	var n int
	st.Subscribe(func(kc storage.KeyChange) error {
		_, ok := kc.(storage.KeyAdded)
		if ok {
			n++
			if n%5000 == 0 {
				log.Infof("%d keys added", n)
			}
			return nil
		}
		return errors.Errorf("KeyChange event type not supported")
	})

	err = st.RenotifyAll()
	return errors.WithStack(err)
}
