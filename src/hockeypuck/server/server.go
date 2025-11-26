package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/carbocation/interpose"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	"hockeypuck/conflux/recon"
	"hockeypuck/hkp"
	"hockeypuck/hkp/pks"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/metrics"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp"
	"hockeypuck/ratelimit"
	"hockeypuck/ratelimit/backend/memory"
	"hockeypuck/ratelimit/backend/redis"

	log "github.com/sirupsen/logrus"
)

type Server struct {
	settings        *Settings
	st              storage.Storage
	middle          *interpose.Middleware
	r               *httprouter.Router
	sksPeer         *sks.Peer
	pksSender       *pks.Sender
	logWriter       io.WriteCloser
	metricsListener *metrics.Metrics
	rateLimiter     *ratelimit.RateLimiter

	t                 tomb.Tomb
	hkpAddr, hkpsAddr string
}

type statusCodeResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewStatusCodeResponseWriter(w http.ResponseWriter) *statusCodeResponseWriter {
	// WriteHeader is not called if our response implicitly
	// returns 200 OK, so we default to that status code.
	return &statusCodeResponseWriter{w, http.StatusOK}
}

func (scrw *statusCodeResponseWriter) WriteHeader(code int) {
	scrw.statusCode = code
	scrw.ResponseWriter.WriteHeader(code)
}

func KeyWriterOptions(settings *Settings) []openpgp.KeyWriterOption {
	var opts []openpgp.KeyWriterOption
	if settings.OpenPGP.Headers.Comment != "" {
		opts = append(opts, openpgp.ArmorHeaderComment(settings.OpenPGP.Headers.Comment))
	} else {
		opts = append(opts, openpgp.ArmorHeaderComment(fmt.Sprintf("Hostname: %s", settings.Hostname)))
	}
	if settings.OpenPGP.Headers.Version != "" {
		opts = append(opts, openpgp.ArmorHeaderVersion(settings.OpenPGP.Headers.Version))
	} else {
		opts = append(opts, openpgp.ArmorHeaderVersion(fmt.Sprintf("%s %s", settings.Software, settings.Version)))
	}
	return opts
}

func KeyReaderOptions(settings *Settings) []openpgp.KeyReaderOption {
	var opts []openpgp.KeyReaderOption
	if settings.OpenPGP.MaxKeyLength > 0 {
		opts = append(opts, openpgp.MaxKeyLen(settings.OpenPGP.MaxKeyLength))
	}
	if settings.OpenPGP.MaxPacketLength > 0 {
		opts = append(opts, openpgp.MaxPacketLen(settings.OpenPGP.MaxPacketLength))
	}
	if len(settings.OpenPGP.Blacklist) > 0 {
		opts = append(opts, openpgp.Blacklist(settings.OpenPGP.Blacklist))
	}
	return opts
}

func NewServer(settings *Settings) (*Server, error) {
	if settings == nil {
		defaults := DefaultSettings()
		settings = &defaults
	}
	s := &Server{
		settings: settings,
		r:        httprouter.New(),
	}

	var err error
	s.st, err = DialStorage(settings)
	if err != nil {
		return nil, err
	}

	keyReaderOptions := KeyReaderOptions(settings)
	userAgent := fmt.Sprintf("%s/%s", settings.Software, settings.Version)
	s.pksSender, err = pks.NewSender(s.st, s.st, settings.PKS)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s.sksPeer, err = sks.NewPeer(s.st, settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings, keyReaderOptions, userAgent, pks.PKSFailoverHandler{Sender: s.pksSender})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	s.middle = interpose.New()

	// Register rate limiting backends
	ratelimit.RegisterMemoryBackend(memory.MemoryBackendConstructor)
	ratelimit.RegisterRedisBackend(redis.RedisBackendConstructor)

	// Set proper UserAgent for Tor exit list fetching
	settings.RateLimit.Tor.UserAgent = userAgent

	// Initialize rate limiter with partner provider for keyserver sync exemptions
	s.rateLimiter, err = ratelimit.NewWithPartners(&settings.RateLimit, s.sksPeer)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Add rate limiting middleware first (before logging)
	s.middle.Use(s.rateLimiter.Middleware())

	s.middle.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			start := time.Now()
			rw.Header().Set("Server", fmt.Sprintf("%s/%s", s.settings.Software, s.settings.Version))
			scrw := NewStatusCodeResponseWriter(rw)
			next.ServeHTTP(scrw, req)
			duration := time.Since(start)

			fields := log.Fields{
				req.Method:    req.URL.String(),
				"duration":    duration.String(),
				"host":        req.Host,
				"status-code": scrw.statusCode,
			}

			if s.settings.HKP.LogRequestDetails {
				fields["from"] = req.RemoteAddr
				fields["user-agent"] = req.UserAgent()

				proxyHeaders := []string{
					"x-forwarded-for",
					"x-forwarded-host",
					"x-forwarded-server",
				}
				for _, ph := range proxyHeaders {
					if v := req.Header.Get(ph); v != "" {
						fields[ph] = v
					}
				}
			}

			log.WithFields(fields).Info()
			recordHTTPRequestDuration(req.Method, scrw.statusCode, duration)
		})
	})
	s.middle.UseHandler(s.r)

	s.metricsListener = metrics.NewMetrics(settings.Metrics)

	keyWriterOptions := KeyWriterOptions(settings)
	options := []hkp.HandlerOption{
		hkp.StatsFunc(s.stats),
		hkp.SelfSignedOnly(settings.HKP.Queries.SelfSignedOnly),
		hkp.FingerprintOnly(settings.HKP.Queries.FingerprintOnly),
		hkp.KeyReaderOptions(keyReaderOptions),
		hkp.KeyWriterOptions(keyWriterOptions),
		hkp.AdminKeys(settings.AdminKeys),
	}
	if settings.IndexTemplate != "" {
		options = append(options, hkp.IndexTemplate(settings.IndexTemplate))
	}
	if settings.VIndexTemplate != "" {
		options = append(options, hkp.VIndexTemplate(settings.VIndexTemplate))
	}
	if settings.StatsTemplate != "" {
		options = append(options, hkp.StatsTemplate(settings.StatsTemplate))
	}
	if settings.MaxResponseLen != 0 {
		options = append(options, hkp.MaxResponseLen(settings.MaxResponseLen))
	}
	h, err := hkp.NewHandler(s.st, options...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	h.Register(s.r)

	if settings.Webroot != "" {
		err := s.registerWebroot(settings.Webroot)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	registerMetrics()
	s.st.Subscribe(metricsStorageNotifier)

	return s, nil
}

func DialStorage(settings *Settings) (storage.Storage, error) {
	switch settings.OpenPGP.DB.Driver {
	case "postgres-jsonb":
		return pghkp.Dial(settings.OpenPGP.DB.DSN, KeyReaderOptions(settings))
	}
	return nil, errors.Errorf("storage driver %q not supported", settings.OpenPGP.DB.Driver)
}

type stats struct {
	Now           string           `json:"now"`
	Version       string           `json:"version"`
	Hostname      string           `json:"hostname"`
	Nodename      string           `json:"nodename"`
	Contact       string           `json:"contact"`
	HTTPAddr      string           `json:"httpAddr"`
	QueryConfig   statsQueryConfig `json:"queryConfig"`
	ReconAddr     string           `json:"reconAddr"`
	Software      string           `json:"software"`
	Peers         []statsPeer      `json:"peers"`
	NumKeys       int              `json:"numkeys,omitempty"`
	ServerContact string           `json:"server_contact,omitempty"`
	RateLimit     interface{}      `json:"rateLimit,omitempty"`

	Total  int
	Hourly []loadStat
	Daily  []loadStat
}

type statsQueryConfig struct {
	SelfSignedOnly  bool `json:"selfSignedOnly"`
	FingerprintOnly bool `json:"keywordSearchDisabled"`
}

type loadStat struct {
	*sks.LoadStat
	Time time.Time
}

// maskString replace input string with * to hide sensitive information
func maskString(orig string) string {
	if orig == "" {
		return orig
	}
	if len(orig) < 4 {
		return "******"
	}
	return string([]byte{orig[0]}) + "****" + string([]byte{orig[len(orig)-1]})
}

type loadStats []loadStat

func (s loadStats) Len() int           { return len(s) }
func (s loadStats) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s loadStats) Less(i, j int) bool { return s[i].Time.Before(s[j].Time) }

// default value of stats endpoint path
const defaultStatsPath = "/pks/lookup?op=stats"

type statsPeer struct {
	Name              string
	HTTPAddr          string `json:"httpAddr"`
	ReconAddr         string `json:"reconAddr"`
	StatsPath         string `json:"statsPath"`
	Masked            bool   `json:"masked,omitempty"`
	LastIncomingRecon time.Time
	LastIncomingError string
	LastOutgoingRecon time.Time
	LastOutgoingError string
	ReconStatus       string
	LastRecovery      time.Time
	LastRecoveryError string
	RecoveryStatus    string
}

type statsPeers []statsPeer

func (s statsPeers) Len() int           { return len(s) }
func (s statsPeers) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s statsPeers) Less(i, j int) bool { return s[i].Name < s[j].Name }

func (s *Server) stats(req *http.Request) (interface{}, error) {
	sksStats := s.sksPeer.Stats()

	result := &stats{
		Now:      time.Now().UTC().Format(time.RFC3339),
		Version:  s.settings.Version,
		Contact:  s.settings.Contact,
		HTTPAddr: s.settings.HKP.Bind,
		QueryConfig: statsQueryConfig{
			SelfSignedOnly:  s.settings.HKP.Queries.SelfSignedOnly,
			FingerprintOnly: s.settings.HKP.Queries.FingerprintOnly,
		},
		ReconAddr: s.settings.Conflux.Recon.Settings.ReconAddr,
		Software:  s.settings.Software,

		Total: sksStats.Total,
	}
	if s.settings.HKP.AdvBind != "" {
		result.HTTPAddr = s.settings.HKP.AdvBind
	}

	nodename, err := os.Hostname()
	if err != nil {
		log.Warningf("cannot determine local hostname: %v", err)
	}

	if s.settings.Hostname != "" {
		result.Hostname = s.settings.Hostname
	} else if nodename != "" {
		result.Hostname = nodename
	}

	if s.settings.Nodename != "" {
		result.Nodename = s.settings.Nodename
	} else {
		result.Nodename = nodename
	}

	if s.settings.EnableVHosts {
		result.Hostname = req.Host
	}

	for k, v := range sksStats.Hourly {
		result.Hourly = append(result.Hourly, loadStat{LoadStat: v, Time: k})
	}
	sort.Sort(loadStats(result.Hourly))
	for k, v := range sksStats.Daily {
		result.Daily = append(result.Daily, loadStat{LoadStat: v, Time: k})
	}
	sort.Sort(loadStats(result.Daily))
	for _, v := range s.sksPeer.CurrentPartners() {
		reconStatus := "OK"
		recoveryStatus := "OK"
		now := time.Now()
		reconStaleLimit := time.Duration(s.settings.ReconStaleSecs) * time.Second
		if v.LastIncomingRecon.Add(reconStaleLimit).Before(now) && v.LastOutgoingRecon.Add(reconStaleLimit).Before(now) {
			if v.ReconStarted.Add(reconStaleLimit).Before(now) {
				reconStatus = "Stale"
			} else {
				reconStatus = "Starting"
			}
		}
		if v.LastRecoveryError != nil {
			recoveryStatus = "Error"
		} else if v.LastRecovery.IsZero() {
			// If no recovery yet, then throw consistent error instead of implying that recovery is working.
			recoveryStatus = reconStatus
		}
		peerInfo := statsPeer{
			Name:              v.Name,
			HTTPAddr:          v.HTTPAddr,
			ReconAddr:         v.ReconAddr,
			StatsPath:         defaultStatsPath,
			LastIncomingRecon: v.LastIncomingRecon,
			LastIncomingError: fmt.Sprintf("%q", v.LastIncomingError),
			LastOutgoingRecon: v.LastOutgoingRecon,
			LastOutgoingError: fmt.Sprintf("%q", v.LastOutgoingError),
			ReconStatus:       reconStatus,
			LastRecovery:      v.LastRecovery,
			LastRecoveryError: fmt.Sprintf("%q", v.LastRecoveryError),
			RecoveryStatus:    recoveryStatus,
		}
		if v.StatsPath != "" {
			if !strings.HasPrefix(v.StatsPath, "/") {
				peerInfo.StatsPath = "/" + v.StatsPath
			} else {
				peerInfo.StatsPath = v.StatsPath
			}
		}
		if v.WebAddr != "" {
			peerInfo.HTTPAddr = v.WebAddr
		}
		if v.Mask {
			peerInfo.HTTPAddr = maskString(peerInfo.HTTPAddr)
			peerInfo.ReconAddr = maskString(v.ReconAddr)
			peerInfo.Masked = true
		}
		result.Peers = append(result.Peers, peerInfo)
	}
	sort.Sort(statsPeers(result.Peers))

	// Add rate limiting statistics
	if s.rateLimiter != nil {
		rateLimitStats := s.rateLimiter.GetRateLimitStats()
		result.RateLimit = rateLimitStats
	}

	return result, nil
}

func (s *Server) registerWebroot(webroot string) error {
	fileServer := http.FileServer(http.Dir(webroot))
	d, err := os.Open(webroot)
	if os.IsNotExist(err) {
		log.Errorf("webroot %q not found", webroot)
		// non-fatal error
		return nil
	} else if err != nil {
		return errors.WithStack(err)
	}
	defer d.Close()
	files, err := d.Readdir(0)
	if err != nil {
		return errors.WithStack(err)
	}

	s.r.GET("/", func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		fileServer.ServeHTTP(w, req)
	})
	s.r.HEAD("/", func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		fileServer.ServeHTTP(w, req)
	})
	// httprouter needs explicit paths, so we need to set up a route for each
	// path. This will panic if there are any paths that conflict with
	// previously registered routes.
	for _, fi := range files {
		name := fi.Name()
		if !fi.IsDir() {
			s.r.GET("/"+name, func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
				req.URL.Path = "/" + name
				fileServer.ServeHTTP(w, req)
			})
			s.r.HEAD("/"+name, func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
				req.URL.Path = "/" + name
				fileServer.ServeHTTP(w, req)
			})
		} else {
			s.r.GET("/"+name+"/*filepath", func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
				req.URL.Path = "/" + name + ps.ByName("filepath")
				fileServer.ServeHTTP(w, req)
			})
			s.r.HEAD("/"+name+"/*filepath", func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
				req.URL.Path = "/" + name + ps.ByName("filepath")
				fileServer.ServeHTTP(w, req)
			})
		}
	}
	return nil
}

func (s *Server) Start() error {
	s.openLog()

	s.t.Go(s.listenAndServeHKP)
	if s.settings.HKPS != nil {
		s.t.Go(s.listenAndServeHKPS)
	}

	if s.sksPeer != nil {
		if s.settings.Conflux.Recon.ReconAddr == "none" {
			s.sksPeer.StartMode(recon.PeerModeGossipOnly)
		} else {
			s.sksPeer.Start()
		}
	}

	if s.pksSender != nil {
		s.pksSender.Start()
	}

	if s.metricsListener != nil {
		s.metricsListener.Start()
	}

	if s.settings.OpenPGP.DB.ReindexOnStartup {
		s.st.StartReindex(s.settings.OpenPGP.DB.ReindexDelaySecs, s.settings.OpenPGP.DB.ReindexIntervalSecs)
	}

	// Start the rate limiter if configured
	if s.rateLimiter != nil {
		s.rateLimiter.Start()
	}

	return nil
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

func (s *Server) openLog() {
	defer func() {
		level, err := log.ParseLevel(strings.ToLower(s.settings.LogLevel))
		if err != nil {
			log.Warningf("invalid LogLevel=%q: %v", s.settings.LogLevel, err)
			return
		}
		log.SetLevel(level)
	}()

	s.logWriter = nopCloser{os.Stderr}
	if s.settings.LogFile != "" {
		f, err := os.OpenFile(s.settings.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Errorf("failed to open LogFile=%q: %v", s.settings.LogFile, err)
		}
		s.logWriter = f
	}
	log.SetOutput(s.logWriter)
	log.Debug("log opened")
}

func (s *Server) closeLog() {
	log.SetOutput(os.Stderr)
	s.logWriter.Close()
}

func (s *Server) LogRotate() {
	w := s.logWriter
	s.openLog()
	w.Close()
}

func (s *Server) Wait() error {
	return s.t.Wait()
}

// ErrStopping is the error indicates that server is stopping normally
var ErrStopping = fmt.Errorf("stopping server")

func (s *Server) Stop() {
	defer s.closeLog()

	if s.sksPeer != nil {
		s.sksPeer.Stop()
	}
	if s.metricsListener != nil {
		s.metricsListener.Stop()
	}
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	s.t.Kill(ErrStopping)
	s.t.Wait()
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by listenAndServe and listenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// Accept implements net.Listener.
func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

var newListener = (*Server).newListener

func (s *Server) newListener(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	s.t.Go(func() error {
		<-s.t.Dying()
		return ln.Close()
	})
	return tcpKeepAliveListener{ln.(*net.TCPListener)}, nil
}

func (s *Server) listenAndServeHKP() error {
	ln, err := newListener(s, s.settings.HKP.Bind)
	if err != nil {
		return errors.WithStack(err)
	}
	s.hkpAddr = ln.Addr().String()
	return http.Serve(ln, s.middle)
}

func (s *Server) listenAndServeHKPS() error {
	config := &tls.Config{
		NextProtos: []string{"http/1.1"},
	}
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(s.settings.HKPS.Cert, s.settings.HKPS.Key)
	if err != nil {
		return errors.Wrapf(err, "failed to load HKPS certificate=%q key=%q", s.settings.HKPS.Cert, s.settings.HKPS.Key)
	}

	ln, err := newListener(s, s.settings.HKPS.Bind)
	if err != nil {
		return errors.WithStack(err)
	}
	s.hkpsAddr = ln.Addr().String()
	ln = tls.NewListener(ln, config)
	return http.Serve(ln, s.middle)
}
