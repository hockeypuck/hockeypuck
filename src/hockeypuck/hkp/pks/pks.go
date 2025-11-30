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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	"hockeypuck/conflux/recon"
	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"

	"hockeypuck/hkp/pks/storage"
	hkpstorage "hockeypuck/hkp/storage"
)

// Max delay backoff multiplier (in seconds) when there are SMTP errors.
const maxDelay = 60

// Delay (in seconds) between successive PKS requests to the same recipient.
const repeatDelay = 10

// Max days in the past to search for updates.
const maxHistoryDays = 1

type Settings struct {
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

func DefaultSettings() *Settings {
	return &Settings{
		SMTP: SMTPConfig{
			Host: DefaultSMTPHost,
		},
	}
}

type VKSRequest struct {
	Keytext string `json:"keytext"`
}

// There is an in-DB copy of the PKS status of each peer, an on-disk copy of the configured (default) PKS peer list,
// and an in-memory copy of the running PKS peer list. PKSFailoverHandler does not assume that these are in sync.
// This is because hockeypuck may just have been restarted with a modified config, and/or the DB may have been
// modified externally. The handler routines are therefore noisier than might be expected; this is intentional.

type PKSFailoverHandler struct {
	Sender *Sender
}

func (h PKSFailoverHandler) ReconStarted(p *recon.Partner) {
	if p.PKSFailover {
		pksAddr := fmt.Sprintf("hkp://%s", p.HTTPAddr)
		log.Infof("removing any copies of %s from PKS target list", pksAddr)
		// Don't remove PKS status from DB, in case it is flappy on timescales < maxHistoryDays
		//		err := h.Sender.storage.PKSRemove(pksAddr)
		//		if err != nil {
		//			log.Errorf("could not remove PKS status of %s from DB: %v", pksAddr, err)
		//		}
		// Update the in-memory PKS peer list
		h.Sender.settings.To = slices.DeleteFunc(h.Sender.settings.To, func(s string) bool { return s == pksAddr })
	}
}

func (h PKSFailoverHandler) ReconUnavailable(p *recon.Partner) {
	if p.PKSFailover {
		pksAddr := fmt.Sprintf("hkp://%s", p.HTTPAddr)
		log.Infof("temporarily adding %s to PKS target list", pksAddr)
		err := h.Sender.storage.PKSInit(pksAddr, p.LastRecovery)
		if err != nil {
			log.Errorf("could not add PKS status of %s to DB: %v", pksAddr, err)
		}
		// Update the in-memory PKS peer list
		if !slices.Contains(h.Sender.settings.To, pksAddr) {
			h.Sender.settings.To = append(h.Sender.settings.To, pksAddr)
		}
	}
}

func (PKSFailoverHandler) ConnectionFailed(*recon.Partner) {
	// Do nothing on connection failures
}

// Basic implementation of outbound PKS synchronization
type Sender struct {
	hkpStorage hkpstorage.Storage
	storage    storage.Storage
	settings   *Settings
	smtpAuth   smtp.Auth

	t tomb.Tomb
}

// Initialize from command line switches if fields not set.
func NewSender(hkpStorage hkpstorage.Storage, Storage storage.Storage, settings *Settings) (*Sender, error) {
	if settings == nil {
		return nil, errors.New("PKS synchronization not configured")
	}

	sender := &Sender{
		hkpStorage: hkpStorage,
		storage:    Storage,
		settings:   settings,
	}

	var err error
	authHost := sender.settings.SMTP.Host
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost, _, err = net.SplitHostPort(authHost)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	sender.smtpAuth = smtp.PlainAuth(
		sender.settings.SMTP.ID,
		sender.settings.SMTP.User,
		sender.settings.SMTP.Password, authHost)

	err = sender.initStatus()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sender, nil
}

func (sender *Sender) initStatus() error {
	for _, addr := range sender.settings.To {
		err := sender.storage.PKSInit(addr, time.Now())
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func (sender *Sender) SendKeys(status *storage.Status) error {
	// Don't flood the remote server if lastSync is in the distant past
	lastSync := status.LastSync
	if lastSync.AddDate(0, 0, maxHistoryDays).Before(time.Now()) {
		lastSync = time.Now().AddDate(0, 0, -maxHistoryDays)
	}

	// TODO: ModifiedSince does not return keys in any particular sort order (FIXME!),
	// so we explicitly compare timestamps instead of assuming monotonicity.
	fps, err := sender.hkpStorage.ModifiedSinceToFp(lastSync)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(fps) == 0 {
		return nil
	}

	records, err := sender.hkpStorage.FetchRecordsByFp(fps)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, record := range records {
		// Take care, because FetchRecords can return nils
		if record.PrimaryKey == nil {
			continue
		}
		log.Debugf("sending key %q to PKS %s", record.Fingerprint, status.Addr)
		err = sender.SendKey(status.Addr, record.PrimaryKey)
		status.LastError = err
		if err != nil {
			log.Errorf("error sending key to PKS %s: %v", status.Addr, err)
			storageErr := sender.storage.PKSUpdate(status)
			if storageErr != nil {
				return errors.WithStack(storageErr)
			}
			return errors.WithStack(err)
		}
		// Send successful, update the timestamp accordingly
		// (FIXME) Can't trust MTime to be monotonically increasing, so compare as we go.
		if status.LastSync.Before(record.MTime) {
			status.LastSync = record.MTime
		}
		err = sender.storage.PKSUpdate(status)
		if err != nil {
			return errors.WithStack(err)
		}
		// Rate limit ourselves to prevent being blocked
		time.Sleep(time.Second * repeatDelay)
	}
	return nil
}

// Send an updated public key to a PKS server.
func (sender *Sender) SendKey(addr string, key *openpgp.PrimaryKey) error {
	var msg bytes.Buffer
	var err error
	emailMatch := regexp.MustCompile(`^mailto:([^@]+@[^@]+)$`)
	matches := emailMatch.FindStringSubmatch(addr)
	if matches != nil && matches[1] != "" {
		emailAddr := matches[1]
		_, err = msg.WriteString("Subject: ADD\n\n")
		if err != nil {
			return err
		}
		err = openpgp.WriteArmoredPackets(&msg, []*openpgp.PrimaryKey{key})
		if err != nil {
			return err
		}
		return smtp.SendMail(sender.settings.SMTP.Host, sender.smtpAuth,
			sender.settings.From, []string{emailAddr}, msg.Bytes())
	}
	urlMatch := regexp.MustCompile(`^(hkps?|vks)://(([^:]+)|\[([0-9A-Fa-f:]+)\])(:(\d+))?$`)
	matches = urlMatch.FindStringSubmatch(addr)
	if matches != nil && matches[3] != "" {
		pksProtocol := matches[1]
		host := matches[3]
		port := "443"
		httpProtocol := "https"
		path := "pks/add"
		if pksProtocol == "hkp" {
			httpProtocol = "http"
			port = "11371"
		} else if pksProtocol == "vks" {
			path = "vks/v1/upload"
		}
		if matches[6] != "" {
			port = matches[6]
		}
		pksUrl := fmt.Sprintf("%s://%s:%s/%s", httpProtocol, host, port, path)

		err = openpgp.WriteArmoredPackets(&msg, []*openpgp.PrimaryKey{key})
		if err != nil {
			return err
		}
		var resp *http.Response
		if pksProtocol == "vks" {
			var vksJson []byte
			vksJson, err = json.Marshal(VKSRequest{Keytext: msg.String()})
			if err != nil {
				return err
			}
			resp, err = http.Post(pksUrl, "application/json", bytes.NewBuffer(vksJson))
		} else {
			resp, err = http.PostForm(pksUrl, url.Values{"keytext": {msg.String()}})
		}
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return errors.Errorf("Status code %d when sending key to '%s'", resp.StatusCode, pksUrl)
		}
		return nil
	}
	return errors.Errorf("PKS address '%s' not supported", addr)
}

// Notify PKS downstream servers
func (sender *Sender) run() error {
	delay := 1
	timer := time.NewTimer(time.Duration(delay) * time.Minute)
	for {
		select {
		case <-sender.t.Dying():
			return nil
		case <-timer.C:
		}

		// There may be PKS statuses in the DB that are not in our running config,
		// e.g. after a restart. Always iterate over the in-memory list.
		for _, addr := range sender.settings.To {
			status, err := sender.storage.PKSGet(addr)
			if err != nil {
				log.Errorf("failed to obtain PKS sync status: %v", err)
				goto DELAY
			}
			err = sender.SendKeys(status)
			if err != nil {
				// Increase delay backoff
				delay++
				if delay > maxDelay {
					delay = maxDelay
				}
				break
			} else {
				// Success, reset delay
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

// Report status of all PKS peers
func (sender *Sender) Status() ([]*storage.Status, error) {
	statuses, err := sender.storage.PKSAll()
	if err != nil {
		return nil, errors.Errorf("failed to obtain PKS sync status: %v", err)
	}
	return statuses, nil
}

// Start PKS synchronization
func (sender *Sender) Start() {
	sender.t.Go(sender.run)
}

func (sender *Sender) Stop() error {
	sender.t.Kill(nil)
	return sender.t.Wait()
}
