package server

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"hockeypuck/hkp/storage"
)

var buckets = append(prometheus.DefBuckets, 30, 60, 300, 600, 1800, 3600)

var serverMetrics = struct {
	httpRequestDuration *prometheus.HistogramVec
	keysAdded           prometheus.Counter
	keysIgnored         prometheus.Counter
	keysUpdated         prometheus.Counter
}{
	httpRequestDuration: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "hockeypuck",
			Name:      "http_request_duration_seconds",
			Help:      "Time spent generating HTTP responses",
			Buckets:   buckets,
		},
		[]string{"method", "status_code"},
	),
	keysAdded: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_added",
			Help:      "New keys added since startup",
		},
	),
	keysIgnored: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_ignored",
			Help:      "Keys with no-op updates since startup",
		},
	),
	keysUpdated: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_updated",
			Help:      "Keys updated since startup",
		},
	),
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(serverMetrics.httpRequestDuration)
		prometheus.MustRegister(serverMetrics.keysAdded)
		prometheus.MustRegister(serverMetrics.keysIgnored)
		prometheus.MustRegister(serverMetrics.keysUpdated)
	})
}

func metricsStorageNotifier(kc storage.KeyChange) error {
	switch kc.(type) {
	case storage.KeyAdded:
		serverMetrics.keysAdded.Inc()
	case storage.KeyNotChanged:
		serverMetrics.keysIgnored.Inc()
	case storage.KeyReplaced:
		serverMetrics.keysUpdated.Inc()
	}
	return nil
}

func recordHTTPRequestDuration(method string, statusCode int, duration time.Duration) {
	serverMetrics.httpRequestDuration.WithLabelValues(method, strconv.Itoa(statusCode)).Observe(duration.Seconds())
}
