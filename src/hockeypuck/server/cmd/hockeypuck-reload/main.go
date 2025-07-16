package main

import (
	"flag"
	"time"

	"github.com/pkg/errors"

	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/server"
	"hockeypuck/server/cmd"

	log "github.com/sirupsen/logrus"
)

func main() {
	flag.Parse()
	settings := cmd.Init()
	err := reload(settings)
	cmd.Die(err)
}

func reload(settings *server.Settings) error {
	st, err := server.DialStorage(settings)
	if err != nil {
		return errors.WithStack(err)
	}
	defer st.Close()

	// Instantiate an sks.Peer to handle KeyChange events, but don't Start() it
	peer, err := sks.NewPeer(st, settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings, nil, "", nil)
	if err != nil {
		return errors.WithStack(err)
	}
	defer peer.Stop()

	t := time.Now()
	u, err := st.Reload()
	if err != nil {
		log.Errorf("some keys failed to update: %v", err)
		if hke, ok := err.(storage.InsertError); ok {
			for _, err := range hke.Errors {
				log.Errorf("update error: %v", err)
			}
		}
	}
	if u > 0 {
		log.Infof("updated %d keys in %v", u, time.Since(t))
	}

	return nil
}
