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
	"time"

	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/origin"
	"github.com/corker/mcp-authproxy/internal/resource"
	"github.com/corker/mcp-authproxy/internal/upstream/relay"
)

// Limits from ADR-0018 §4–5 and §9.
const (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 64 << 10
	MaxMCPBody        = 8 << 20
	ShutdownTimeout   = 25 * time.Second
)

// Handler builds every route behind the Host check, request logging and panic recovery.
func Handler(cfg *config.Config, log *slog.Logger, v resource.Validator) http.Handler {
	meta := resource.Metadata{Resource: cfg.PublicURL, Issuer: cfg.Issuer(), Scope: cfg.Scope,
		Name: cfg.ResourceName, Documentation: cfg.ResourceDocumentation}
	mux := http.NewServeMux()
	md := resource.MetadataHandler(meta)
	for _, p := range meta.Paths() {
		mux.Handle(p, md)
	}
	up := relay.New(log, cfg.UpstreamURL)
	mux.Handle(cfg.PublicURL.Path, origin.Origins(log, cfg.AllowedOrigins,
		resource.Guard(meta, v, limitBody(MaxMCPBody, up))))

	hosts := append([]string{cfg.PublicURL.Host}, cfg.AllowedHosts...)
	return recoverer(log, logging.Middleware(log, origin.Hosts(log, hosts, mux)))
}

// New returns the hardened server. WriteTimeout stays 0 so streams can run; per-request
// deadlines are set where needed through http.ResponseController.
func New(cfg *config.Config, log *slog.Logger, v resource.Validator) *http.Server {
	return &http.Server{
		Addr:              cfg.Listen,
		Handler:           Handler(cfg, log, v),
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Run serves until ctx is done, then shuts down within ShutdownTimeout; open streams are
// cancelled through their request contexts.
func Run(ctx context.Context, srv *http.Server, log *slog.Logger) error {
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
