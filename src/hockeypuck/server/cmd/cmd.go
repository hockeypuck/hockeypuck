package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

// Die prints the error and exits with a non-zero exit code
func Die(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func StartCPUProf(cpuProf bool, prior *os.File) *os.File {
	if prior != nil {
		pprof.StopCPUProfile()
		log.Infof("CPU profile written to %q", prior.Name())
		prior.Close()
		os.Rename(filepath.Join(os.TempDir(), "hockeypuck-cpu.prof.part"),
			filepath.Join(os.TempDir(), "hockeypuck-cpu.prof"))
	}
	if cpuProf {
		profName := filepath.Join(os.TempDir(), "hockeypuck-cpu.prof.part")
		f, err := os.Create(profName)
		if err != nil {
			Die(errors.WithStack(err))
		}
		pprof.StartCPUProfile(f)
		return f
	}
	return nil
}

func WriteMemProf(memProf bool) {
	if memProf {
		tmpName := filepath.Join(os.TempDir(), fmt.Sprintf("hockeypuck-mem.prof.%d", time.Now().Unix()))
		profName := filepath.Join(os.TempDir(), "hockeypuck-mem.prof")
		f, err := os.Create(tmpName)
		if err != nil {
			Die(errors.WithStack(err))
		}
		err = pprof.WriteHeapProfile(f)
		f.Close()
		if err != nil {
			log.Warningf("failed to write heap profile: %v", err)
			return
		}
		log.Infof("Heap profile written to %q", f.Name())
		os.Rename(tmpName, profName)
	}
}
