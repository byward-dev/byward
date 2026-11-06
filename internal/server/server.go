// Package server wires the proxy together: the only place that knows concrete adapters
// (AGENTS.md layout rule 3). It builds the routes and the hardened `http.Server` (ADR-0018).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/health"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/metrics"
	"github.com/corker/mcp-authproxy/internal/origin"
	"github.com/corker/mcp-authproxy/internal/resource"
	"github.com/corker/mcp-authproxy/internal/tracing"
	"github.com/corker/mcp-authproxy/internal/upstream/relay"
)

// Observability is what the routes report to: the audit stream and metrics (ADR-0021). The zero
// value records nothing.
type Observability struct {
	Audit   *audit.Log
	Metrics *metrics.Metrics
}

// route names a request for metrics and spans from a fixed set, never from the raw path.
func route(cfg *config.Config) func(*http.Request) string {
	return func(r *http.Request) string {
		p := r.URL.Path
		switch {
		case p == cfg.PublicURL.Path:
			return "mcp"
		case strings.HasPrefix(p, "/.well-known/"):
			return "metadata"
		case p == "/authorize":
			return "authorize"
		case strings.HasPrefix(p, "/callback/"):
			return "callback"
		case p == "/token":
			return "token"
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
// panic recovery. register, when not nil, adds the broker's routes (authenticated mode).
func Handler(cfg *config.Config, log *slog.Logger, v resource.Validator, register func(*http.ServeMux), o Observability) http.Handler {
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
	up := relay.New(log, cfg.UpstreamURL)
	// The proxy's own origin is same-origin and cannot be forged by another site (a DNS-rebinding
	// page sends its own origin), so it is always allowed; the MCP conformance rebinding scenario
	// expects it to be accepted.
	origins := append([]string{cfg.Origin()}, cfg.AllowedOrigins...)
	mux.Handle(cfg.PublicURL.Path, origin.Origins(o.Audit, origins,
		mcpMethods(guard(limitBody(MaxMCPBody, admit(MaxInFlight, MaxStreams, o.Metrics, up))))))

	hosts := append([]string{cfg.PublicURL.Host}, cfg.AllowedHosts...)
	rt := route(cfg)
	return recoverer(log, logging.Middleware(log, tracing.Middleware(rt, o.Metrics.Middleware(rt, origin.Hosts(o.Audit, hosts, mux)))))
}

// Servers are the public listener and, unless turned off, the internal one for /metrics, /livez
// and /readyz (ADR-0018 §10).
type Servers struct {
	Public   *http.Server
	Internal *http.Server // nil when MCP_AUTHPROXY_INTERNAL_LISTEN is empty
	Health   *health.Health
}

func hardened(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// New wires the proxy and returns the hardened servers. WriteTimeout stays 0 so streams can run;
// per-request deadlines are set where needed through http.ResponseController. Errors are
// configuration problems (a key directory, a clients file, IdP settings).
func New(cfg *config.Config, log *slog.Logger) (*Servers, error) {
	m := metrics.New()
	o := Observability{Audit: audit.New(log, m.AuditEvent, time.Now), Metrics: m}
	var h http.Handler
	var checks []health.Check
	if cfg.NoAuth {
		h = Handler(cfg, log, resource.NoTokens{}, nil, o)
	} else {
		a, err := buildAuth(cfg, log, o)
		if err != nil {
			return nil, err
		}
		h = Handler(cfg, log, a.validator, a.register, o)
		checks = a.checks
	}
	s := &Servers{Public: hardened(cfg.Listen, h, log), Health: health.New(log, checks...)}
	if cfg.InternalListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", m.Handler())
		s.Health.Register(mux)
		s.Internal = hardened(cfg.InternalListen, mux, log)
	}
	return s, nil
}

// Run serves until ctx is done, then shuts down within ShutdownTimeout: readiness fails first, the
// public listener closes (open streams are cancelled through their request contexts), and the
// internal listener goes last so probes and scrapes see the drain.
func Run(ctx context.Context, s *Servers, log *slog.Logger) error {
	if s.Internal == nil {
		return serve(ctx, s.Public, log, s.Health.Drain)
	}
	ln, err := net.Listen("tcp", s.Internal.Addr)
	if err != nil {
		return fmt.Errorf("internal listen: %w", err)
	}
	log.Info("internal listener", "listen", ln.Addr().String())
	internalErr := make(chan error, 1)
	go func() { internalErr <- s.Internal.Serve(ln) }()
	err = serve(ctx, s.Public, log, s.Health.Drain)
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownTimeout)
	defer cancel()
	if serr := s.Internal.Shutdown(shutdownCtx); serr != nil && err == nil {
		err = fmt.Errorf("internal shutdown: %w", serr)
	}
	if ierr := <-internalErr; !errors.Is(ierr, http.ErrServerClosed) && err == nil {
		err = ierr
	}
	return err
}

// serve runs srv until ctx is done; drain is called before shutdown starts.
func serve(ctx context.Context, srv *http.Server, log *slog.Logger, drain func()) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	baseCtx, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	srv.BaseContext = func(net.Listener) context.Context { return baseCtx }
	log.Info("listening", "listen", ln.Addr().String())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	drain()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownTimeout)
	defer cancel()
	cancelRequests() // ends long-lived streams so Shutdown does not wait for them
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
