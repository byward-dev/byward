package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/resource"
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
	if cfg.NoAuth {
		// With authentication, buildAuth checks every secret file; without it, this is the only one.
		if err := errors.Join(looseSecretFiles(cfg)...); err != nil {
			return nil, err
		}
	}
	name := stdioName(cfg)
	m, err := newStdioManager(cfg, stdio.Config{Name: name, Command: cfg.UpstreamCommand, Env: cfg.UpstreamEnv,
		MaxProcesses: cfg.StdioMaxProcesses, MaxPerUser: cfg.StdioMaxPerUser, Log: log,
		Evicted: func(id stdio.Identity, reason string) {
			o.Audit.Record(nil, audit.Event{Name: audit.ProcessEvicted, Outcome: audit.Success, Reason: reason, UserKey: id.Subject})
		}})
	if err != nil {
		return nil, err
	}
	o.Metrics.StdioProcesses(m.Len)
	b := stdio.NewBridge(stdio.BridgeConfig{Manager: m, Identity: stdioIdentity(cfg), Log: log.With("upstream", name)})
	return &upstream{handler: b, shutdown: m.Shutdown}, nil
}

// newStdioManager is stdio.New with the settings named in its error. It finds the command and
// starts nothing; processes start per user (ADR-0003).
func newStdioManager(cfg *config.Config, sc stdio.Config) (*stdio.Manager, error) {
	m, err := stdio.New(sc)
	if err != nil {
		return nil, fmt.Errorf("stdio upstream (BYWARD_UPSTREAM_COMMAND, BYWARD_UPSTREAM_ENV_FILE): %w", err)
	}
	return m, nil
}

// checkUpstream is what check --offline and doctor ask of the upstream without reaching it: a stdio
// command that can be found, with the same check startup makes. An HTTP upstream has nothing to
// check offline.
func checkUpstream(cfg *config.Config) error {
	if cfg.UpstreamCommand == nil {
		return nil
	}
	_, err := newStdioManager(cfg, stdio.Config{Name: stdioName(cfg), Command: cfg.UpstreamCommand, Env: cfg.UpstreamEnv})
	return err
}

// upstreamResult tells doctor's reader which upstream is configured; doctor checks the proxy in front
// of it and never reaches the upstream itself.
func upstreamResult(cfg *config.Config) doctor.Result {
	r := doctor.Result{Class: doctor.ClassProxy, Name: "upstream", Status: doctor.Pass}
	if cfg.UpstreamCommand == nil {
		r.Message = "HTTP upstream " + cfg.UpstreamURL.String() + "; doctor checks the proxy in front of it, not the upstream itself"
		return r
	}
	r.Message = "stdio upstream " + stdioName(cfg) + ": the command was found; doctor does not start it (a process starts per user at their first MCP request)"
	return r
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
