/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pks

import (
	"bytes"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	log "github.com/sirupsen/logrus"
	"hockeypuck/openpgp"

	"hockeypuck/hkp/storage"
)

// Max delay backoff multiplier when there are SMTP errors.
const maxDelay = 60

// Status of PKS synchronization
type Status struct {
	// Email address of the PKS server.
	Addr string
	// Timestamp of the last sync to this server.
	LastSync time.Time
}

type Config struct {
	From string     `toml:"from"`
	To   []string   `toml:"to"`
	SMTP SMTPConfig `toml:"smtp"`
}

const (
	DefaultSMTPHost = "localhost:25"
)

type SMTPConfig struct {
	Host     string `toml:"host"`
	ID       string `toml:"id"`
	User     string `toml:"user"`
	Password string `toml:"pass"`
}

type Storage interface {
	Init(addr string) error
	All() ([]Status, error)
	Update(status Status) error
}

// Basic implementation of outbound PKS synchronization
type Sender struct {
	config     *Config
	hkpStorage storage.Storage
	pksStorage Storage
	smtpAuth   smtp.Auth
	lastStatus []Status

	t tomb.Tomb
}

// Initialize from command line switches if fields not set.
func NewSender(hkpStorage storage.Storage, pksStorage Storage, config *Config) (*Sender, error) {
	if config == nil {
		return nil, errors.New("PKS mail synchronization not configured")
	}

	sender := &Sender{
		config:     config,
		hkpStorage: hkpStorage,
		pksStorage: pksStorage,
	}

	var err error
	authHost := sender.config.SMTP.Host
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost, _, err = net.SplitHostPort(authHost)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	sender.smtpAuth = smtp.PlainAuth(
		sender.config.SMTP.ID,
		sender.config.SMTP.User,
		sender.config.SMTP.Password, authHost)

	err = sender.initStatus()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sender, nil
}

func (sender *Sender) initStatus() error {
	for _, emailAddr := range sender.config.To {
		err := sender.pksStorage.Init(emailAddr)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func (sender *Sender) SendKeys(status Status) error {
	uuids, err := sender.hkpStorage.ModifiedSince(status.LastSync)
	if err != nil {
		return errors.WithStack(err)
	}

	keys, err := sender.hkpStorage.FetchKeyrings(uuids)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, key := range keys {
		// Send key email
		log.Debugf("sending key %q to PKS %s", key.PrimaryKey.Fingerprint(), status.Addr)
		err = sender.SendKey(status.Addr, key.PrimaryKey)
		if err != nil {
			log.Errorf("error sending key to PKS %s: %v", status.Addr, err)
			return errors.WithStack(err)
		}
		// Send successful, update the timestamp accordingly
		status.LastSync = key.MTime
		err = sender.pksStorage.Update(status)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// Email an updated public key to a PKS server.
func (sender *Sender) SendKey(addr string, key *openpgp.PrimaryKey) error {
	var msg bytes.Buffer
	msg.WriteString("Subject: ADD\n\n")
	openpgp.WriteArmoredPackets(&msg, []*openpgp.PrimaryKey{key})
	return smtp.SendMail(sender.config.SMTP.Host, sender.smtpAuth,
		sender.config.From, []string{addr}, msg.Bytes())
}

// Poll PKS downstream servers
func (sender *Sender) run() error {
	delay := 1
	timer := time.NewTimer(time.Duration(delay) * time.Minute)
	for {
		select {
		case <-sender.t.Dying():
			return nil
		case <-timer.C:
		}

		statuses, err := sender.pksStorage.All()
		if err != nil {
			log.Errorf("failed to obtain PKS sync status: %v", err)
			goto DELAY
		}
		for _, status := range statuses {
			err = sender.SendKeys(status)
			if err != nil {
				// Increase delay backoff
				delay++
				if delay > maxDelay {
					delay = maxDelay
				}
				break
			} else {
				// Successful mail sent, reset delay
				delay = 1
			}
		}

	DELAY:
		toSleep := time.Duration(delay) * time.Minute
		if delay > 1 {
			// log delay if we had an error
			log.Debugf("PKS sleeping %d minute(s)", toSleep)
		}
		timer.Reset(toSleep)
	}
}

// Start PKS synchronization
func (sender *Sender) Start() {
	sender.t.Go(sender.run)
}

func (sender *Sender) Stop() error {
	sender.t.Kill(nil)
	return sender.t.Wait()
}
