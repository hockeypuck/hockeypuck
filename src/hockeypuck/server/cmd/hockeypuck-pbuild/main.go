package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	cf "hockeypuck/conflux"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/server"
	"hockeypuck/server/cmd"
)

var (
	configFile = flag.String("config", "", "config file")
	cpuProf    = flag.Bool("cpuprof", false, "enable CPU profiling")
	memProf    = flag.Bool("memprof", false, "enable mem profiling")
)

func main() {
	flag.Parse()

	var (
		settings *server.Settings
		err      error
	)
	if configFile != nil {
		conf, err := ioutil.ReadFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration file '%s'.\n", *configFile)
			cmd.Die(errors.WithStack(err))
		}
		settings, err = server.ParseSettings(string(conf))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing configuration file '%s'.\n", *configFile)
			cmd.Die(errors.WithStack(err))
		}
	}

	cpuFile := cmd.StartCPUProf(*cpuProf, nil)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR2)
	go func() {
		for {
			select {
			case sig := <-c:
				switch sig {
				case syscall.SIGUSR2:
					cpuFile = cmd.StartCPUProf(*cpuProf, cpuFile)
					cmd.WriteMemProf(*memProf)
				}
			}
		}
	}()

	err = pbuild(settings)
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
		}
		return nil
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
