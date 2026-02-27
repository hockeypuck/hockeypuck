package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"strings"

	xopenpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/pkg/errors"

	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"
)

func main() {
	var matches, misses int
	var n int
	for _, ocert := range openpgp.MustReadOpaqueCerts(os.Stdin) {
		match, miss, err := testCert(ocert)
		if err != nil {
			log.Errorf("key#%d: %+v", n, err)
		}
		matches += match
		misses += miss
	}
	log.Infof("matches=%d misses=%d\n", matches, misses)
}

func testCert(ocert *openpgp.OpaqueCert) (int, int, error) {
	var policy openpgp.Policy
	var buf bytes.Buffer
	for _, op := range ocert.Packets {
		err := op.Serialize(&buf)
		if err != nil {
			return 0, 0, errors.WithStack(err)
		}
	}
	pk, err := ocert.Parse()
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}
	dupDigest, err := openpgp.SksDigest(pk, md5.New())
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}

	err = policy.ValidSelfSigned(pk, false)
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}

	dedupDigest, err := openpgp.SksDigest(pk, md5.New())
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}
	cmd := exec.Command("./sks_hash")
	var out bytes.Buffer
	cmd.Stdin = bytes.NewBuffer(buf.Bytes())
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}
	sksDigest := strings.ToLower(strings.TrimSpace(out.String()))
	if dedupDigest != sksDigest {
		log.Warningf("hkp=%q hkp_dedup=%q sks=%q", dupDigest, dedupDigest, sksDigest)
		var out bytes.Buffer
		armw, err := armor.Encode(&out, xopenpgp.PublicKeyType, nil)
		if err != nil {
			return 0, 1, errors.WithStack(err)
		}
		armw.Write(buf.Bytes())
		armw.Close()
		fmt.Println(out.String())
		return 0, 1, nil
	}
	return 1, 0, nil
}
