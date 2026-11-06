// Package metrics exposes the proxy's Prometheus metrics on the internal listener (ADR-0021 §8,
// ADR-0018 §10). Labels take only fixed values: never a user, client, tool or raw path, so the
// series count stays bounded whatever callers send. Metric names are public interface (ADR-0023).
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Buckets are fixed (seconds), from 50 ms to 10 s (ADR-0021 §8).
var Buckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Metrics holds the proxy's collectors in its own registry. A nil *Metrics records nothing.
type Metrics struct {
	reg         *prometheus.Registry
	requests    *prometheus.HistogramVec
	idp         *prometheus.HistogramVec
	inFlight    *prometheus.GaugeVec
	busy        *prometheus.CounterVec
	auditEvents *prometheus.CounterVec
}

// New registers every metric; version and goVersion label the build-info gauge.
func New(version, goVersion string) *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "mcp_authproxy_http_request_duration_seconds",
			Help: "HTTP request duration by route and status class.", Buckets: Buckets}, []string{"route", "status_class"}),
		idp: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "mcp_authproxy_idp_request_duration_seconds",
			Help: "IdP call duration by IdP, operation and outcome (success, rejected, unavailable).", Buckets: Buckets},
			[]string{"idp", "operation", "outcome"}),
		inFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "mcp_authproxy_upstream_in_flight",
			Help: "Requests to the upstream in flight, by kind (request or stream)."}, []string{"kind"}),
		busy: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "mcp_authproxy_upstream_busy_total",
			Help: "Requests refused with 503 because an upstream admission cap was full, by kind."}, []string{"kind"}),
		auditEvents: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "mcp_authproxy_audit_events_total",
			Help: "Audit events by event name and outcome, including rate-limited ones that were not logged."},
			[]string{"event", "outcome"}),
	}
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "mcp_authproxy_build_info",
		Help: "Always 1; labelled with the proxy and Go versions."}, []string{"version", "go_version"})
	build.WithLabelValues(version, goVersion).Set(1)
	m.reg.MustRegister(m.requests, m.idp, m.inFlight, m.busy, m.auditEvents, build,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Middleware times each request under route(r), which must return one of a fixed set of names.
func (m *Metrics) Middleware(route func(*http.Request) string, next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.requests.WithLabelValues(route(r), strconv.Itoa(rec.status/100)+"xx").Observe(time.Since(start).Seconds())
	})
}

// IdP records one IdP call.
func (m *Metrics) IdP(idp, operation, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.idp.WithLabelValues(idp, operation, outcome).Observe(d.Seconds())
}

// InFlight adjusts the upstream in-flight gauge for kind ("request" or "stream") by delta.
func (m *Metrics) InFlight(kind string, delta float64) {
	if m == nil {
		return
	}
	m.inFlight.WithLabelValues(kind).Add(delta)
}

// Busy counts a 503 from an admission cap of kind.
func (m *Metrics) Busy(kind string) {
	if m == nil {
		return
	}
	m.busy.WithLabelValues(kind).Inc()
}

// AuditEvent counts an audit event; it has audit.Observer's signature.
func (m *Metrics) AuditEvent(event, outcome string) {
	if m == nil {
		return
	}
	m.auditEvents.WithLabelValues(event, outcome).Inc()
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader && (code < 100 || code > 199 || code == http.StatusSwitchingProtocols) {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush for streams).
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
