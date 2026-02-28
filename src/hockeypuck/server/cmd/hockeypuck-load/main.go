package main

import (
	"flag"
	"os"
	"path/filepath"
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
	args := flag.Args()
	if len(args) == 0 {
		log.Errorf("usage: %s [flags] <file1> [file2 .. fileN]", os.Args[0])
		cmd.Die(errors.New("missing PGP key file arguments"))
	}

	settings := cmd.Init(false)
	cmd.HandleSignals()
	err := load(settings, args)
	cmd.Die(err)
}

func load(settings *server.Settings, args []string) error {
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

	keyReaderOptions := server.KeyReaderOptions(settings)

	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil {
			log.Errorf("failed to match %q: %v", arg, err)
			continue
		}
		for _, file := range matches {
			log.Infof("processing file %q...", file)
			f, err := os.Open(file)
			if err != nil {
				log.Errorf("failed to open %q for reading: %v", file, err)
			}
			kr := openpgp.NewKeyReader(f, keyReaderOptions...)
			keys, err := kr.Read()
			if err != nil {
				log.Errorf("error reading key: %v", err)
				continue
			}
			log.Infof("found %d keys in %q...", len(keys), file)
			t := time.Now()
			goodKeys := make([]*openpgp.PrimaryKey, 0, len(keys))
			for _, key := range keys {
				err = policy.ValidSelfSigned(key, false)
				if err != nil {
					log.Errorf("validation error, ignoring: %v", err)
					continue
				}
				goodKeys = append(goodKeys, key)
			}
			u, n, err := st.Insert(goodKeys)
			if err != nil {
				log.Errorf("some keys failed to insert from %q: %v", file, err)
				if hke, ok := err.(storage.InsertError); ok {
					for _, err := range hke.Errors {
						log.Errorf("insert error: %v", err)
					}
				}
			}
			if n > 0 || u > 0 {
				log.Infof("inserted %d, updated %d keys from %q in %v", n, u, file, time.Since(t))
			}
		}
	}

	return nil
}
