package main

import (
	"flag"
	"time"

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
	err := reload(settings)
	cmd.Die(err)
}

func reload(settings *server.Settings) error {
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

	statsFilename := sks.StatsFilename(settings.Conflux.Recon.LevelDB.Path)
	stats := sks.NewStats()
	err = stats.ReadFile(statsFilename)
	if err != nil {
		log.Warningf("failed to open stats file %q: %v", statsFilename, err)
		stats = sks.NewStats()
	}
	defer stats.WriteFile(statsFilename)

	st.Subscribe(func(kc storage.KeyChange) error {
		stats.Update(kc)
		ka, ok := kc.(storage.KeyAdded)
		if ok {
			var digestZp cf.Zp
			err := sks.DigestZp(ka.Digest, &digestZp)
			if err != nil {
				return errors.Wrapf(err, "bad digest %q", ka.Digest)
			}
			return ptree.Insert(&digestZp)
		}
		return nil
	})

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
