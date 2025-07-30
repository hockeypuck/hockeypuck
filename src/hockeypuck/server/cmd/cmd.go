package cmd

import (
	"flag"
	"fmt"
	"hockeypuck/server"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

var (
	configFile = flag.String("config", "", "config file")
	logLevel   = flag.String("log", "", "log level")
	cpuProf    = flag.Bool("cpuprof", false, "enable CPU profiling")
	memProf    = flag.Bool("memprof", false, "enable mem profiling")
)

var cpuFile *os.File

var Sigmap = map[os.Signal]func(){
	syscall.SIGUSR2: func() {
		cpuFile = StartCPUProf(*cpuProf, cpuFile)
		WriteMemProf(*memProf)
	},
}

// Init handles common command line flags, logging, profiling etc. for all CLI commands.
// The caller MUST import "flag" and call flag.Parse() before calling Init().
func Init(isServer bool) (settings *server.Settings) {
	if configFile != nil {
		conf, err := os.ReadFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration file '%s'.\n", *configFile)
			Die(errors.WithStack(err))
		}
		settings, err = server.ParseSettings(string(conf))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing configuration file '%s'.\n", *configFile)
			Die(errors.WithStack(err))
		}
	}

	if *logLevel != "" {
		settings.LogLevel = *logLevel
	}
	if !isServer {
		level, err := log.ParseLevel(strings.ToLower(settings.LogLevel))
		if err != nil {
			log.Warningf("invalid LogLevel=%q: %v", settings.LogLevel, err)
		} else {
			log.SetLevel(level)
		}
	}

	cpuFile = StartCPUProf(*cpuProf, nil)
	return
}

func HandleSignals() {
	c := make(chan os.Signal, 1)
	keys := make([]os.Signal, len(Sigmap))
	i := 0
	for k := range Sigmap {
		keys[i] = k
		i++
	}
	signal.Notify(c, keys...)
	go func() {
		// BEWARE: go-staticcheck will suggest that you replace the following with `for range`.
		// This is not how signal handling works (it is SUPPOSED to loop forever).
		// Please DO NOT change this function unless you can explain how it works. :-)
		for {
			select {
			case sig := <-c:
				if Sigmap[sig] != nil {
					Sigmap[sig]()
				}
			}
		}
	}()
}

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
