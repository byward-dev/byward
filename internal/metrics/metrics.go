// Package metrics exposes the proxy's Prometheus metrics on the internal listener (ADR-0021 §8,
// ADR-0018 §10). Labels take only fixed values: never a user, client, tool or raw path, so the
// series count stays bounded whatever callers send. Metric names are public interface (ADR-0023).
package metrics

import (
	"github.com/byward-dev/byward/internal/logging"

	"net/http"
	"runtime/debug"
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
	rateLimited *prometheus.CounterVec
	cimdFetches *prometheus.CounterVec
	dcr         *prometheus.CounterVec
	consent     *prometheus.CounterVec
	appTokens   *prometheus.CounterVec
	downstream  *prometheus.CounterVec
	idpAlerts   *prometheus.CounterVec
}

// New registers every metric; the build-info gauge is labelled from the binary's build info.
func New() *Metrics {
	version, goVersion := "unknown", "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		version, goVersion = bi.Main.Version, bi.GoVersion
	}
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "byward_http_request_duration_seconds",
			Help: "HTTP request duration by route and status class.", Buckets: Buckets}, []string{"route", "status_class"}),
		idp: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "byward_idp_request_duration_seconds",
			Help: "IdP call duration by IdP, operation and outcome (success, rejected, unavailable).", Buckets: Buckets},
			[]string{"idp", "operation", "outcome"}),
		inFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "byward_upstream_in_flight",
			Help: "Requests to the upstream in flight, by kind (request or stream)."}, []string{"kind"}),
		busy: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_upstream_busy_total",
			Help: "Requests refused with 503 because an upstream admission cap was full, by kind."}, []string{"kind"}),
		auditEvents: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_audit_events_total",
			Help: "Audit events by event name and outcome, including rate-limited ones that were not logged."},
			[]string{"event", "outcome"}),
		rateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_rate_limited_total",
			Help: "OAuth endpoint requests refused with 429 because the client address was over its budget, by endpoint."},
			[]string{"endpoint"}),
		cimdFetches: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_cimd_fetches_total",
			Help: "Client ID Metadata Document fetches by outcome (ok, invalid, refused, unavailable, rate_limited, busy)."},
			[]string{"outcome"}),
		dcr: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_dcr_registrations_total",
			Help: "Dynamic client registrations at /register by outcome (registered, invalid_redirect_uri, invalid_client_metadata, full, unavailable, rate_limited)."},
			[]string{"outcome"}),
		consent: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_consent_total",
			Help: "Consent decisions by client trust level (verified, domain, not-verified; empty for a prompt=none refusal after the IdP) and outcome (shown, granted, denied, remembered, silent_refused)."},
			[]string{"trust", "outcome"}),
		appTokens: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_app_tokens_total",
			Help: "App-only tokens at the MCP endpoint by outcome (accepted, expired, invalid, delegated, keys_unavailable, revoked, deny_list_stale, denied_role, denied_client, denied_tenant)."},
			[]string{"outcome"}),
		downstream: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_downstream_tokens_total",
			Help: "On-Behalf-Of downstream tokens for upstream requests and stdio processes' asks by outcome (cached, issued, consent_required, interaction_required, unavailable, failed; for a stdio process also no_user, sign_in_expired)."},
			[]string{"outcome"}),
		idpAlerts: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "byward_idp_alerts_total",
			Help: "IdP errors that need the operator, by IdP, operation (authorize, callback, refresh, on_behalf_of) and reason (credential_unusable, credential_rejected, protocol)."},
			[]string{"idp", "operation", "reason"}),
	}
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "byward_build_info",
		Help: "Always 1; labelled with the proxy and Go versions."}, []string{"version", "go_version"})
	build.WithLabelValues(version, goVersion).Set(1)
	m.reg.MustRegister(m.requests, m.idp, m.inFlight, m.busy, m.auditEvents, m.rateLimited, m.cimdFetches, m.dcr, m.consent, m.appTokens, m.downstream, m.idpAlerts, build,
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
		rec := logging.NewStatusRecorder(w)
		next.ServeHTTP(rec, r)
		m.requests.WithLabelValues(route(r), strconv.Itoa(rec.Status()/100)+"xx").Observe(time.Since(start).Seconds())
	})
}

// IdP records one IdP call.
func (m *Metrics) IdP(idp, operation, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.idp.WithLabelValues(idp, operation, outcome).Observe(d.Seconds())
}

// SeedIdPAlerts exports the IdP alert series of idp for each operation and reason at 0, so an alert
// rule on increase() sees the first alert after a start (a series that appears at 1 has no earlier
// sample to increase from).
func (m *Metrics) SeedIdPAlerts(idp string, operations, reasons []string) {
	if m == nil {
		return
	}
	for _, op := range operations {
		for _, reason := range reasons {
			m.idpAlerts.WithLabelValues(idp, op, reason)
		}
	}
}

// IdPAlert counts one IdP error that needs the operator (#204).
func (m *Metrics) IdPAlert(idp, operation, reason string) {
	if m == nil {
		return
	}
	m.idpAlerts.WithLabelValues(idp, operation, reason).Inc()
}

// InFlight adjusts the upstream in-flight gauge for kind ("request" or "stream") by delta.
func (m *Metrics) InFlight(kind string, delta float64) {
	if m == nil {
		return
	}
	m.inFlight.WithLabelValues(kind).Add(delta)
}

// StdioProcesses exports n, the number of live stdio upstream processes, as a gauge read at scrape
// time. Call it once, when a stdio upstream is configured.
func (m *Metrics) StdioProcesses(n func() int) {
	if m == nil {
		return
	}
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "byward_stdio_processes",
		Help: "Live stdio upstream processes, including starting and stopping ones."}, func() float64 { return float64(n()) }))
}

// Busy counts a 503 from an admission cap of kind.
func (m *Metrics) Busy(kind string) {
	if m == nil {
		return
	}
	m.busy.WithLabelValues(kind).Inc()
}

// RateLimited counts a request an OAuth endpoint refused over its budget.
func (m *Metrics) RateLimited(endpoint string) {
	if m == nil {
		return
	}
	m.rateLimited.WithLabelValues(endpoint).Inc()
}

// AuditEvent counts an audit event; it has audit.Observer's signature.
func (m *Metrics) AuditEvent(event, outcome string) {
	if m == nil {
		return
	}
	m.auditEvents.WithLabelValues(event, outcome).Inc()
}

// CIMDFetch counts a Client ID Metadata Document fetch by outcome; it has the signature of
// registration.CIMDConfig.Observe.
func (m *Metrics) CIMDFetch(outcome string) {
	if m == nil {
		return
	}
	m.cimdFetches.WithLabelValues(outcome).Inc()
}

// Downstream counts a downstream token for an upstream request by outcome (ADR-0017).
func (m *Metrics) Downstream(outcome string) {
	if m == nil {
		return
	}
	m.downstream.WithLabelValues(outcome).Inc()
}

// Consent counts a consent decision for a client of a trust level (ADR-0010 §12); it has the
// signature of broker.Config.ObserveConsent.
func (m *Metrics) Consent(trust, outcome string) {
	if m == nil {
		return
	}
	m.consent.WithLabelValues(trust, outcome).Inc()
}

// DCRRegistration counts a /register outcome; it has the signature of broker.Config.ObserveRegistration.
func (m *Metrics) DCRRegistration(outcome string) {
	if m == nil {
		return
	}
	m.dcr.WithLabelValues(outcome).Inc()
}

// AppToken counts an app-only token's outcome at the MCP endpoint (ADR-0022 §7), every request.
func (m *Metrics) AppToken(outcome string) {
	if m == nil {
		return
	}
	m.appTokens.WithLabelValues(outcome).Inc()
}
