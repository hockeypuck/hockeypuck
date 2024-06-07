// Package metrics provides a simple HTTP server that exposes Prometheus metrics.
package metrics

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/tomb.v2"

	log "github.com/sirupsen/logrus"
)

type Metrics struct {
	s   *Settings
	srv *http.Server
	t   tomb.Tomb
}

type Settings struct {
	MetricsAddr string `toml:"metricsAddr"`
	MetricsPath string `toml:"metricsPath"`
}

var defaultSettings = Settings{
	MetricsAddr: ":9626",
	MetricsPath: "/metrics",
}

func DefaultSettings() *Settings {
	return &defaultSettings
}

func NewMetrics(s *Settings) *Metrics {
	if s == nil {
		s = DefaultSettings()
	}

	mux := http.NewServeMux()
	mux.Handle(s.MetricsPath, promhttp.Handler())

	return &Metrics{
		s: s,
		srv: &http.Server{
			Addr:    s.MetricsAddr,
			Handler: mux,
		},
	}
}

func (m *Metrics) Start() {
	m.t.Go(func() error {
		log.Info("metrics: starting")
		if err := m.srv.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Errorf("failed to serve metrics: %v", err)
				return errors.WithStack(err)
			}
		}
		return tomb.ErrDying
	})
	m.t.Go(func() error {
		<-m.t.Dying()
		return m.srv.Close()
	})
}

func (m *Metrics) Stop() {
	log.Info("metrics: stopping")
	m.t.Kill(nil)
	if err := m.t.Wait(); err != nil {
		log.Errorf("%+v", err)
	}
	log.Info("metrics: stopped")
}
