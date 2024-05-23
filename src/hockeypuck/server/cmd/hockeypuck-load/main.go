package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"

	cf "hockeypuck/conflux"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	log "hockeypuck/logrus"
	"hockeypuck/openpgp"
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
		conf, err := os.ReadFile(*configFile)
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

	args := flag.Args()
	if len(args) == 0 {
		log.Errorf("usage: %s [flags] <file1> [file2 .. fileN]", os.Args[0])
		cmd.Die(errors.New("missing PGP key file arguments"))
	}

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

	err = load(settings, flag.Args())
	cmd.Die(err)
}

func load(settings *server.Settings, args []string) error {
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
			goodKeys := make([]*openpgp.PrimaryKey, 0)
			for _, key := range keys {
				err = openpgp.ValidSelfSigned(key, false)
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
