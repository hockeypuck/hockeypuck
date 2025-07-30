package main

import (
	"flag"
	"syscall"

	"github.com/pkg/errors"

	"hockeypuck/server"
	"hockeypuck/server/cmd"
)

func main() {
	flag.Parse()

	if len(flag.Args()) != 0 {
		flag.Usage()
		cmd.Die(errors.New("unexpected command line arguments"))
	}

	settings := cmd.Init(true)

	srv, err := server.NewServer(settings)
	if err != nil {
		cmd.Die(err)
	}

	srv.Start()

	cmd.Sigmap[syscall.SIGINT] = srv.Stop
	cmd.Sigmap[syscall.SIGTERM] = srv.Stop
	cmd.Sigmap[syscall.SIGUSR1] = srv.LogRotate
	cmd.HandleSignals()

	err = srv.Wait()
	if err != server.ErrStopping {
		cmd.Die(err)
	}
	cmd.Die(nil)
}
