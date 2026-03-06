package main

import (
	"flag"
	"time"

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
	err := reload(settings)
	cmd.Die(err)
}

func reload(settings *server.Settings) error {
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

	t := time.Now()
	u, d, err := st.Reload()
	if err != nil {
		log.Errorf("some keys failed to update: %v", err)
		if hke, ok := err.(storage.InsertError); ok {
			for _, err := range hke.Errors {
				log.Errorf("update error: %v", err)
			}
		}
	}
	if u > 0 {
		log.Infof("reloaded %d keys and deleted %d in %v", u, d, time.Since(t))
	}

	return nil
}
