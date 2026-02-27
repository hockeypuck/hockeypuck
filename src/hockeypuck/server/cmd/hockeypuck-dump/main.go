package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
	"hockeypuck/server/cmd"
)

var (
	outputDir = flag.String("path", ".", "output path")
	count     = flag.Int("count", 15000, "keys per file")
)

func main() {
	flag.Parse()
	settings := cmd.Init(false)
	cmd.HandleSignals()
	err := dump(settings)
	cmd.Die(err)
}

func dump(settings *server.Settings) error {
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

	ptree, err := sks.NewPrefixTree(settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings)
	if err != nil {
		return errors.WithStack(err)
	}
	err = ptree.Create()
	if err != nil {
		return errors.WithStack(err)
	}
	defer ptree.Close()

	root, err := ptree.Root()
	if err != nil {
		return errors.WithStack(err)
	}

	var t tomb.Tomb
	ch := make(chan string)

	t.Go(func() error {
		var i int
		var digests []string
		defer func() {
			for range ch {
			}
		}() // drain if early return on error
		for digest := range ch {
			digests = append(digests, digest)
			if len(digests) >= *count {
				err := writeKeys(st, digests, i, settings.OpenPGP.DB.RequestQueryLimit)
				if err != nil {
					return errors.WithStack(err)
				}
				i++
				digests = nil
			}
		}
		if len(digests) > 0 {
			err := writeKeys(st, digests, i, settings.OpenPGP.DB.RequestQueryLimit)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
	t.Go(func() error {
		return traverse(root, ch)
	})
	return t.Wait()
}

func traverse(root recon.PrefixNode, ch chan string) error {
	defer close(ch)
	// Depth-first walk of the prefix tree
	nodes := []recon.PrefixNode{root}
	for len(nodes) > 0 {
		node := nodes[0]
		nodes = nodes[1:]

		if node.IsLeaf() {
			elements, err := node.Elements()
			if err != nil {
				return errors.WithStack(err)
			}
			for _, element := range elements {
				zb := element.Bytes()
				ch <- strings.ToLower(hex.EncodeToString(zb))
			}
		} else {
			children, err := node.Children()
			if err != nil {
				return errors.WithStack(err)
			}
			nodes = append(nodes, children...)
		}
	}
	return nil
}

func writeKeys(st storage.Queryer, digests []string, num, chunksize int) error {
	f, err := os.Create(filepath.Join(*outputDir, fmt.Sprintf("hkp-dump-%04d.pgp", num)))
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	for len(digests) > 0 {
		var chunk []string
		if len(digests) > chunksize {
			chunk = digests[:chunksize]
			digests = digests[chunksize:]
		} else {
			chunk = digests
			digests = nil
		}

		records, err := st.FetchRecordsByMD5(chunk)
		if err != nil {
			return errors.WithStack(err)
		}
		for _, record := range records {
			if record.PrimaryKey != nil {
				err := openpgp.WritePackets(f, record.PrimaryKey)
				if err != nil {
					return errors.WithStack(err)
				}
			}
		}
	}
	return nil
}
