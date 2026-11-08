package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/logging"
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
// command that does not exist fails here, at startup. With minter (authentication on), every
// request to an HTTP upstream carries the identity assertion (ADR-0016); with down, a downstream
// API token too (ADR-0017).
func newUpstream(cfg *config.Config, log *slog.Logger, o Observability, minter *assertion.Minter, down *downstreamTokens) (*upstream, error) {
	if cfg.UpstreamCommand == nil {
		if minter != nil {
			return &upstream{handler: assertingUpstream(cfg, log, minter, down)}, nil
		}
		return &upstream{handler: httpUpstream(cfg, log)}, nil
	}
	name := stdioName(cfg)
	m, err := newStdioManager(cfg, stdioConfig(cfg, name, log, o))
	if err != nil {
		return nil, err
	}
	o.Metrics.StdioProcesses(m.Len)
	b := stdio.NewBridge(stdio.BridgeConfig{Manager: m, Identity: stdioIdentity(cfg), Log: log.With("upstream", name)})
	return &upstream{handler: b, shutdown: m.Shutdown}, nil
}

// stdioConfig is the stdio upstream's settings from cfg, with each eviction audited.
func stdioConfig(cfg *config.Config, name string, log *slog.Logger, o Observability) stdio.Config {
	return stdio.Config{Name: name, Command: cfg.UpstreamCommand, Env: cfg.UpstreamEnv,
		MaxProcesses: cfg.StdioMaxProcesses, MaxPerUser: cfg.StdioMaxPerUser, StreamIdleTimeout: cfg.StdioStreamIdleTimeout, Log: log,
		Evicted: func(ev stdio.Eviction) {
			o.Audit.Record(nil, audit.Event{Name: audit.ProcessEvicted, Outcome: audit.Success, Reason: ev.Reason, UserKey: ev.ID.Subject,
				OpenStreams: ev.OpenStreams})
		}}
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
// of it and never reaches the upstream itself. proxy is the relay's: an HTTP proxy from the
// environment that the upstream's requests go through is named, with its userinfo redacted.
func upstreamResult(cfg *config.Config, proxy func(*http.Request) (*url.URL, error)) doctor.Result {
	r := doctor.Result{Class: doctor.ClassProxy, Name: "upstream", Status: doctor.Pass}
	if cfg.UpstreamCommand == nil {
		r.Message = "HTTP upstream " + cfg.UpstreamURL.String() + "; doctor checks the proxy in front of it, not the upstream itself"
		switch via, err := proxy(&http.Request{URL: cfg.UpstreamURL}); {
		case err != nil: // the error quotes the setting, which may hold a password
			r.Status = doctor.Warn
			r.Message += "; the environment's HTTP proxy setting is not a valid URL, so every request to the upstream fails"
			r.Fix = "fix HTTP_PROXY or HTTPS_PROXY, or list the upstream's host in NO_PROXY"
		case via != nil:
			r.Message += "; requests to it go through the HTTP proxy " + via.Redacted() + " from the environment (list the upstream's host in NO_PROXY to reach it directly)"
		}
		if !cfg.NoAuth {
			r.Message += "; requests carry the identity assertion in " + cfg.AssertionHeader + ", with aud " + cfg.UpstreamURL.String()
		}
		if cfg.UpstreamCredential != "" {
			r.Message += "; the operator's upstream credential is set and sent in " + cfg.UpstreamCredentialHeader
		}
		if len(cfg.OBOScopes) > 0 {
			r.Message += "; and an On-Behalf-Of token for " + strings.Join(cfg.OBOScopes, " ") + " in " + cfg.OBOHeader +
				" (grant admin consent for these permissions; docs/how-to/downstream-apis.md)"
		}
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

// httpUpstream is the relay to the HTTP upstream. The assertion's header and the plain identity
// headers are stripped from every inbound request even when nothing is asserted, so a client can
// never supply them; so is the operator credential's, which the relay then sets (ADR-0016 §5, §7),
// and the On-Behalf-Of header's (ADR-0017 §3).
func httpUpstream(cfg *config.Config, log *slog.Logger, opts ...relay.Option) http.Handler {
	base := []relay.Option{relay.WithInject(tracing.Inject), relay.WithResponseHeaderTimeout(cfg.UpstreamHeaderTimeout), relay.WithStripped(cfg.AssertionHeader),
		relay.WithStripped(config.IdentityHeaderNames...)}
	if cfg.OBOHeader != "" { // set with authentication, whether or not On-Behalf-Of is on
		base = append(base, relay.WithStripped(cfg.OBOHeader))
	}
	if cred := cfg.UpstreamCredential; cred != "" {
		header := cfg.UpstreamCredentialHeader
		base = append(base, relay.WithStripped(header), relay.WithInject(func(_ context.Context, h http.Header) { h.Set(header, cred) }))
	}
	return relay.New(log, cfg.UpstreamURL, append(base, opts...)...)
}

// assertionKey carries a request's minted assertion from withAssertion to the relay.
type assertionKey struct{}

// assertingUpstream is the relay that sends every request with the identity assertion in
// BYWARD_ASSERTION_HEADER, after the inbound copies are gone (ADR-0016 §2, §4).
func assertingUpstream(cfg *config.Config, log *slog.Logger, m *assertion.Minter, down *downstreamTokens) http.Handler {
	header := cfg.AssertionHeader
	opts := []relay.Option{relay.WithInject(func(ctx context.Context, h http.Header) {
		if tok, ok := ctx.Value(assertionKey{}).(string); ok {
			h.Set(header, "Bearer "+tok)
		}
	})}
	if cfg.IdentityHeaders {
		opts = append(opts, relay.WithInject(setIdentityHeaders))
	}
	if down == nil {
		return withAssertion(m, log, httpUpstream(cfg, log, opts...))
	}
	// The downstream token is fetched first: a request refused for want of one gets no assertion.
	return down.middleware(withAssertion(m, log, httpUpstream(cfg, log, append(opts, relay.WithInject(down.inject))...)))
}

// withAssertion mints the assertion for the user Guard admitted. A request it cannot mint one for
// fails here and never reaches the upstream without it.
func withAssertion(m *assertion.Minter, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := resource.IdentityFrom(r.Context())
		var tok string
		var err error
		if ok {
			tok, err = m.Mint(id)
		}
		if !ok || err != nil {
			log.ErrorContext(r.Context(), "the identity assertion could not be minted; request refused", "request_id", logging.RequestID(r.Context()), "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), assertionKey{}, tok)))
	})
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
		return stdio.Identity{Subject: id.Subject, Issuer: issuer, PrincipalType: id.PrincipalType}, ok && id.Subject != ""
	}
}
