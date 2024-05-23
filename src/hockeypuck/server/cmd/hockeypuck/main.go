package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"

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

	if len(flag.Args()) != 0 {
		flag.Usage()
		cmd.Die(errors.New("unexpected command line arguments"))
	}

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

	srv, err := server.NewServer(settings)
	if err != nil {
		cmd.Die(err)
	}

	srv.Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		// BEWARE: go-staticcheck will suggest that you replace the following with `for range`.
		// This is not how signal handling works (it is SUPPOSED to loop forever).
		// Please DO NOT change this function unless you can explain how it works. :-)
		for {
			select {
			case sig := <-c:
				switch sig {
				case syscall.SIGINT, syscall.SIGTERM:
					srv.Stop()
				case syscall.SIGUSR1:
					srv.LogRotate()
				case syscall.SIGUSR2:
					cpuFile = cmd.StartCPUProf(*cpuProf, cpuFile)
					cmd.WriteMemProf(*memProf)
				}
			}
		}
	}()

	err = srv.Wait()
	if err != server.ErrStopping {
		cmd.Die(err)
	}
	cmd.Die(nil)
}
