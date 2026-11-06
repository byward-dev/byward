package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/corker/mcp-authproxy/internal/health"
)

// Servers are the public listener and, unless turned off, the internal one for /metrics, /livez
// and /readyz (ADR-0018 §10).
type Servers struct {
	Public   *http.Server
	Internal *http.Server // nil when MCP_AUTHPROXY_INTERNAL_LISTEN is empty
	Health   *health.Health

	background func(ctx context.Context) // nil without authentication; runs while the public listener serves
	closeStore func() error              // nil without authentication; releases the store once Run is done
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

// Run serves until ctx is done, then shuts down within ShutdownTimeout: readiness fails first, the
// public listener closes (open streams are cancelled through their request contexts), and the
// internal listener goes last so probes and scrapes see the drain.
func Run(ctx context.Context, s *Servers, log *slog.Logger) error {
	if s.closeStore != nil { // deferred first, so it runs after the background work has stopped
		defer func() {
			if err := s.closeStore(); err != nil {
				log.Warn("closing the store failed", "error", err)
			}
		}()
	}
	listening := func() {}
	if s.background != nil {
		bgCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		started := false
		listening = func() { started = true; go func() { defer close(done); s.background(bgCtx) }() }
		defer func() { // stops with Run, whatever ends it
			stop()
			if started {
				<-done
			}
		}()
	}
	if s.Internal == nil {
		return serve(ctx, s.Public, log, s.Health.Drain, listening)
	}
	ln, err := net.Listen("tcp", s.Internal.Addr)
	if err != nil {
		return fmt.Errorf("internal listen: %w", err)
	}
	log.Info("internal listener", "listen", ln.Addr().String())
	internalErr := make(chan error, 1)
	go func() { internalErr <- s.Internal.Serve(ln) }()
	err = serve(ctx, s.Public, log, s.Health.Drain, listening)
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

// serve runs srv until ctx is done; listening is called once it listens, drain before shutdown
// starts.
func serve(ctx context.Context, srv *http.Server, log *slog.Logger, drain, listening func()) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	listening()
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
