package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/secretfile"
	"github.com/byward-dev/byward/internal/tracing"
	"github.com/byward-dev/byward/internal/upstream/relay"
	"github.com/byward-dev/byward/internal/upstream/stdio"
)

// noAuthIdentity is the one user every stdio process acts for without authentication (ADR-0027).
var noAuthIdentity = stdio.Identity{Subject: "anonymous", Issuer: "urn:byward:no-auth"}

// upstream is the configured upstream adapter (ADR-0003).
type upstream struct {
	handler http.Handler
	// shutdown stops what the adapter runs; nil for an HTTP upstream.
	shutdown func(context.Context) error
}

// newUpstream builds the HTTP relay, or the stdio bridge when a command is configured. A stdio
// command that does not exist fails here, at startup.
func newUpstream(cfg *config.Config, log *slog.Logger, o Observability) (*upstream, error) {
	if cfg.UpstreamCommand == nil {
		return &upstream{handler: httpUpstream(cfg, log)}, nil
	}
	if cfg.NoAuth && !cfg.Dev {
		// With authentication, buildAuth checks every secret file; without it, this is the only one.
		for _, f := range cfg.Values.SecretFiles() {
			if err := secretfile.Check(f.Path); err != nil {
				return nil, fmt.Errorf("%s: %w", f.From, err)
			}
		}
	}
	name := stdioName(cfg)
	m, err := stdio.New(stdio.Config{Name: name, Command: cfg.UpstreamCommand, Env: cfg.UpstreamEnv,
		MaxProcesses: cfg.StdioMaxProcesses, MaxPerUser: cfg.StdioMaxPerUser, Log: log,
		Evicted: func(id stdio.Identity, reason string) {
			o.Audit.Record(nil, audit.Event{Name: audit.ProcessEvicted, Outcome: audit.Success, Reason: reason, UserKey: id.Subject})
		}})
	if err != nil {
		return nil, fmt.Errorf("stdio upstream (BYWARD_UPSTREAM_COMMAND, BYWARD_UPSTREAM_ENV_FILE): %w", err)
	}
	o.Metrics.StdioProcesses(m.Len)
	b := stdio.NewBridge(stdio.BridgeConfig{Manager: m, Identity: stdioIdentity(cfg), Log: log.With("upstream", name)})
	return &upstream{handler: b, shutdown: m.Shutdown}, nil
}

// upstreamID names the upstream in sealed session IDs, so one cannot be replayed against another.
func upstreamID(cfg *config.Config) string {
	if cfg.UpstreamCommand != nil {
		return "stdio:" + stdioName(cfg)
	}
	return cfg.UpstreamURL.String()
}

// stdioName names a stdio upstream in logs: its program's file name.
func stdioName(cfg *config.Config) string { return filepath.Base(cfg.UpstreamCommand[0]) }

// httpUpstream is the relay to the HTTP upstream.
func httpUpstream(cfg *config.Config, log *slog.Logger) http.Handler {
	return relay.New(log, cfg.UpstreamURL, relay.WithTraceContext(tracing.Inject), relay.WithResponseHeaderTimeout(cfg.UpstreamHeaderTimeout))
}

// stdioIdentity is who a stdio process acts for: the access token's subject under the proxy's
// issuer (ADR-0016 §1, §6), or the anonymous user without authentication.
func stdioIdentity(cfg *config.Config) func(*http.Request) (stdio.Identity, bool) {
	if cfg.NoAuth {
		return func(*http.Request) (stdio.Identity, bool) { return noAuthIdentity, true }
	}
	issuer := cfg.Issuer()
	return func(r *http.Request) (stdio.Identity, bool) {
		id, ok := resource.IdentityFrom(r.Context())
		return stdio.Identity{Subject: id.Subject, Issuer: issuer}, ok && id.Subject != ""
	}
}
