// Package pgtest starts and stops a postgres server, quickly
// and conveniently, for gocheck unit tests.
package pgtest

import (
	"bytes"
	"database/sql"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"text/template"
	"time"

	gc "gopkg.in/check.v1"
)

var conf = template.Must(template.New("t").Parse(`
fsync = off
listen_addresses = ''

{{if .Plural}}
unix_socket_directories = '{{.ConfDir}}'
{{else}}
unix_socket_directory = '{{.ConfDir}}'
{{end}}

`))

var pgtestdata = filepath.Join(os.TempDir(), "pgtestdata1")

var (
	postgres string
	initdbOk = false
	once     sync.Once
)

type PGSuite struct {
	URL string // Connection URL for sql.Open.
	Dir string

	cmd *exec.Cmd
}

// SetUpTest runs postgres in a temporary directory,
// with a default file set produced by initdb.
// If an error occurs, the test will fail.
func (s *PGSuite) SetUpTest(c *gc.C) {
	once.Do(func() { maybeInitdb(c) })
	if !initdbOk {
		c.Fatal("prior initdb attempt failed")
	}
	var err error
	s.Dir, err = ioutil.TempDir("", "pgtest")
	c.Assert(err, gc.IsNil)

	err = exec.Command("cp", "-a", pgtestdata+"/.", s.Dir).Run()
	c.Assert(err, gc.IsNil)

	path := filepath.Join(s.Dir, "postgresql.conf")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
	c.Assert(err, gc.IsNil)

	plural := !contains("unix_socket_directory", path)
	err = conf.Execute(f, struct {
		ConfDir string
		Plural  bool
	}{s.Dir, plural})
	c.Assert(err, gc.IsNil)

	err = f.Close()
	c.Assert(err, gc.IsNil)

	s.URL = "host=" + s.Dir + " dbname=postgres sslmode=disable"
	s.cmd = exec.Command(postgres, "-D", s.Dir)
	err = s.cmd.Start()
	c.Assert(err, gc.IsNil, gc.Commentf("starting postgres"))

	c.Log("starting postgres in", s.Dir)
	sock := filepath.Join(s.Dir, ".s.PGSQL.5432")
	for n := 0; n < 20; n++ {
		if _, err := os.Stat(sock); err == nil {
			if db, err := sql.Open("postgres", s.URL); err == nil {
				if _, err = db.Exec("SELECT 1"); err == nil {
					return
				}
				c.Logf("database connection failed, not ready: %v", err)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.Fatal("timeout waiting for postgres to start")
	panic("unreached")
}

// TearDownTest stops the running postgres process and removes its
// temporary data directory.
// If an error occurs, the test will fail.
func (s *PGSuite) TearDownTest(c *gc.C) {
	if s.cmd == nil {
		return
	}
	err := s.cmd.Process.Signal(os.Interrupt)
	c.Assert(err, gc.IsNil)
	err = s.cmd.Wait()
	c.Assert(err, gc.IsNil)
	err = os.RemoveAll(s.Dir)
	c.Assert(err, gc.IsNil)
}

func maybeInitdb(c *gc.C) {
	out, err := exec.Command("pg_config", "--bindir").Output()
	gcComment := "pg_config"
	if exitErr, ok := err.(*exec.ExitError); ok {
		// pg_config prints a hint on failure, so let's report it.
		gcComment = gcComment + ": " + string(exitErr.Stderr)
	}
	c.Assert(err, gc.IsNil, gc.Commentf(gcComment))

	bindir := string(bytes.TrimSpace(out))
	postgres = filepath.Join(bindir, "postgres")
	initdb := filepath.Join(bindir, "initdb")
	err = os.Mkdir(pgtestdata, 0777)
	if os.IsExist(err) {
		initdbOk = true
		return
	}
	c.Assert(err, gc.IsNil)
	err = exec.Command(initdb, "-D", pgtestdata).Run()
	if err != nil {
		os.RemoveAll(pgtestdata)
		c.Fatal("initdb", err)
	}
	initdbOk = true
}

func contains(substr, name string) bool {
	b, err := ioutil.ReadFile(name)
	return err == nil && bytes.Contains(b, []byte(substr))
}
