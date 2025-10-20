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
	keysRemoved         prometheus.Counter
	keysAddedJitter     prometheus.Counter
	keysRemovedJitter   prometheus.Counter
	rateLimitViolations *prometheus.CounterVec
	rateLimitBanned     *prometheus.GaugeVec
	rateLimitTracked    prometheus.Gauge
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
	keysRemoved: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_removed",
			Help:      "Keys removed since startup",
		},
	),
	keysAddedJitter: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_added_jitter",
			Help:      "Lost PTree entries recreated since startup",
		},
	),
	keysRemovedJitter: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_removed_jitter",
			Help:      "Stale PTree entries cleaned up since startup",
		},
	),
	rateLimitViolations: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "rate_limit_violations_total",
			Help:      "Total number of rate limit violations",
		},
		[]string{"reason", "is_tor"},
	),
	rateLimitBanned: prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "hockeypuck",
			Name:      "rate_limit_banned_ips",
			Help:      "Number of currently banned IPs",
		},
		[]string{"is_tor"},
	),
	rateLimitTracked: prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "hockeypuck",
			Name:      "rate_limit_tracked_ips",
			Help:      "Number of IPs currently being tracked for rate limiting",
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
		prometheus.MustRegister(serverMetrics.keysRemoved)
		prometheus.MustRegister(serverMetrics.keysAddedJitter)
		prometheus.MustRegister(serverMetrics.keysRemovedJitter)
		prometheus.MustRegister(serverMetrics.rateLimitViolations)
		prometheus.MustRegister(serverMetrics.rateLimitBanned)
		prometheus.MustRegister(serverMetrics.rateLimitTracked)
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
	case storage.KeyRemoved:
		serverMetrics.keysRemoved.Inc()
	case storage.KeyAddedJitter:
		serverMetrics.keysAddedJitter.Inc()
	case storage.KeyRemovedJitter:
		serverMetrics.keysRemovedJitter.Inc()
	}
	return nil
}

func recordHTTPRequestDuration(method string, statusCode int, duration time.Duration) {
	serverMetrics.httpRequestDuration.WithLabelValues(method, strconv.Itoa(statusCode)).Observe(duration.Seconds())
}

// recordRateLimitViolation records a rate limiting violation in Prometheus metrics
func recordRateLimitViolation(reason string, isTor bool) {
	torLabel := "false"
	if isTor {
		torLabel = "true"
	}
	serverMetrics.rateLimitViolations.WithLabelValues(reason, torLabel).Inc()
}

// updateRateLimitStats updates the current rate limiting gauges
func updateRateLimitStats(totalTracked int, bannedRegular int, bannedTor int) {
	serverMetrics.rateLimitTracked.Set(float64(totalTracked))
	serverMetrics.rateLimitBanned.WithLabelValues("false").Set(float64(bannedRegular))
	serverMetrics.rateLimitBanned.WithLabelValues("true").Set(float64(bannedTor))
}
