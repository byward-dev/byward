// Package server wires the proxy together: the only place that knows concrete adapters
// (AGENTS.md layout rule 3). It builds the routes and the hardened `http.Server` (ADR-0018).
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/metrics"
	"github.com/byward-dev/byward/internal/origin"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/tracing"
)

// Observability is what the routes report to: the audit stream and metrics (ADR-0021). The zero
// value records nothing.
type Observability struct {
	Audit   *audit.Log
	Metrics *metrics.Metrics
}

// routeOf names a request for metrics and spans by the mux pattern it matches, so the mux stays the
// only route table; the values are the registered patterns (bounded, never the raw path), and
// requests matching none are "other".
func routeOf(mux *http.ServeMux) func(*http.Request) string {
	return func(r *http.Request) string {
		if _, p := mux.Handler(r); p != "" {
			return p
		}
		return "other"
	}
}

// Limits from ADR-0018 §4–5 and §9.
const (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 64 << 10
	MaxMCPBody        = 8 << 20
	ShutdownTimeout   = 25 * time.Second
	// MaxInFlight and MaxStreams cap concurrent requests to the upstream (ADR-0018 §7). Long-lived
	// GET streams have their own cap so idle legacy-era streams can never use up tool-call slots.
	MaxInFlight = 64
	MaxStreams  = 256
)

// Handler builds every route behind the Host check, request logging, metrics, the server span and
// panic recovery; up is the upstream adapter. register, when not nil, adds the broker's routes, and
// sessions binds MCP sessions to the user (authenticated mode; both nil without authentication).
func Handler(cfg *config.Config, log *slog.Logger, up http.Handler, v resource.Validator, register func(*http.ServeMux), sessions func(http.Handler) http.Handler, o Observability) http.Handler {
	meta := resource.Metadata{Resource: cfg.PublicURL, Issuer: cfg.Issuer(), Scope: cfg.Scope,
		Name: cfg.ResourceName, Documentation: cfg.ResourceDocumentation}
	mux := http.NewServeMux()
	// Without authentication there is no protected-resource metadata and no challenge: clients
	// that find either start an OAuth flow that cannot succeed (ADR-0027).
	guard := func(next http.Handler) http.Handler { return resource.Guard(meta, v, o.Audit, next) }
	if cfg.NoAuth {
		guard = func(next http.Handler) http.Handler { return next }
	} else {
		md := resource.MetadataHandler(meta)
		for _, p := range meta.Paths() {
			mux.Handle(p, md)
		}
	}
	if register != nil {
		register(mux)
	}
	if sessions != nil {
		up = sessions(up)
	}
	// The proxy's own origin is same-origin and cannot be forged by another site (a DNS-rebinding
	// page sends its own origin), so it is always allowed; the MCP conformance rebinding scenario
	// expects it to be accepted.
	origins := append([]string{cfg.Origin()}, cfg.AllowedOrigins...)
	mux.Handle(cfg.PublicURL.Path, origin.Origins(o.Audit, origins,
		mcpMethods(guard(limitBody(MaxMCPBody, admit(MaxInFlight, MaxStreams, o.Metrics, up))))))

	hosts := append([]string{cfg.PublicURL.Host}, cfg.AllowedHosts...)
	rt := routeOf(mux)
	// recoverer is innermost so a panic still gets its request log line, its 5xx metric and an error
	// span: the wrappers above see the 500 it writes.
	// ClientAddress is outermost: every layer below logs and limits by the same resolved address.
	return logging.ClientAddress(cfg.TrustedProxies, logging.Middleware(log, tracing.Middleware(rt, o.Metrics.Middleware(rt, recoverer(log, origin.Hosts(o.Audit, hosts, mux))))))
}

// New wires the proxy and returns the hardened servers. WriteTimeout stays 0 so streams can run;
// per-request deadlines are set where needed through http.ResponseController. Errors are
// configuration problems (a key directory, a clients file, IdP settings).
func New(cfg *config.Config, log *slog.Logger) (*Servers, error) {
	m := metrics.New()
	o := Observability{Audit: audit.New(log, m.AuditEvent, time.Now), Metrics: m}
	var h http.Handler
	var checks []health.Check
	var background func(context.Context)
	var closeStore func() error
	var a *auth
	if !cfg.NoAuth {
		var err error
		if a, err = buildAuth(cfg, log, o); err != nil {
			return nil, err
		}
	}
	var minter *assertion.Minter
	if a != nil {
		minter = a.minter
	}
	up, err := newUpstream(cfg, log, o, minter)
	if err != nil {
		if a != nil {
			_ = a.closeStore()
		}
		return nil, err
	}
	if a == nil {
		h = Handler(cfg, log, up.handler, resource.NoTokens{}, nil, nil, o)
	} else {
		h = Handler(cfg, log, up.handler, a.validator, a.register, a.sessions, o)
		checks = a.checks
		background, closeStore = a.background, a.closeStore
	}
	s := &Servers{Public: hardened(cfg.Listen, h, log), Health: health.New(log, checks...), background: background,
		closeStore: closeStore, closeUpstream: up.shutdown}
	if cfg.InternalListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", m.Handler())
		if a != nil && a.jwks != nil {
			mux.Handle("GET "+jwksPath, a.jwks) // for an upstream that reaches only the internal listener
		}
		s.Health.Register(mux)
		s.Internal = hardened(cfg.InternalListen, origin.InternalHosts(o.Audit, cfg.AllowedHosts, mux), log)
	}
	return s, nil
}

func limitBody(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > n {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r)
	})
}

// mcpMethods admits the methods Streamable HTTP uses; anything else (TRACE, PUT, PATCH, a
// non-preflight OPTIONS) gets 405 before authentication and never reaches the upstream.
func mcpMethods(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodDelete:
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// admit caps concurrent requests: GET streams against maxStreams, everything else against
// maxRequests; over a cap the answer is 503 with Retry-After.
func admit(maxRequests, maxStreams int, m *metrics.Metrics, next http.Handler) http.Handler {
	requests, streams := make(chan struct{}, maxRequests), make(chan struct{}, maxStreams)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sem, kind := requests, "request"
		if r.Method == http.MethodGet {
			sem, kind = streams, "stream"
		}
		select {
		case sem <- struct{}{}:
			m.InFlight(kind, 1)
			defer func() { <-sem; m.InFlight(kind, -1) }()
		default:
			m.Busy(kind)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "upstream busy", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recoverer turns a panic into a 500 and logs only the panic value, never the request.
func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler { //nolint:errorlint // sentinel compared as net/http does
					panic(p)
				}
				log.ErrorContext(r.Context(), "panic", "request_id", logging.RequestID(r.Context()), "panic", fmt.Sprint(p))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
