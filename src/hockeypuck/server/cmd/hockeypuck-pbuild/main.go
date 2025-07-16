package main

import (
	"flag"

	"github.com/pkg/errors"

	cf "hockeypuck/conflux"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/server"
	"hockeypuck/server/cmd"

	log "github.com/sirupsen/logrus"
)

func main() {
	flag.Parse()
	settings := cmd.Init()
	err := pbuild(settings)
	cmd.Die(err)
}

func pbuild(settings *server.Settings) error {
	st, err := server.DialStorage(settings)
	if err != nil {
		return errors.WithStack(err)
	}
	defer st.Close()

	ptree, err := sks.NewPrefixTree(settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings)
	if err != nil {
		return errors.WithStack(err)
	}
	err = ptree.Create()
	if err != nil {
		return errors.WithStack(err)
	}
	defer ptree.Close()

	stats := sks.NewStats()

	var n int
	st.Subscribe(func(kc storage.KeyChange) error {
		ka, ok := kc.(storage.KeyAdded)
		if ok {
			var digestZp cf.Zp
			err := sks.DigestZp(ka.Digest, &digestZp)
			if err != nil {
				return errors.Wrapf(err, "bad digest %q", ka.Digest)
			}
			err = ptree.Insert(&digestZp)
			if err != nil {
				return errors.Wrapf(err, "failed to insert digest %q", ka.Digest)
			}

			stats.Update(kc)

			n++
			if n%5000 == 0 {
				log.Infof("%d keys added", n)
			}
			return nil
		}
		return errors.Errorf("KeyChange event type not supported")
	})

	defer func() {
		err := stats.WriteFile(sks.StatsFilename(settings.Conflux.Recon.LevelDB.Path))
		if err != nil {
			log.Warningf("error writing stats: %v", err)
		}
	}()
	err = st.RenotifyAll()
	return errors.WithStack(err)
}
