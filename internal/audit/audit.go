// Package audit writes the audit stream (ADR-0021 §3): one JSON record per security event, marked
// `log.type=audit` with a `schema_version`, through the proxy's redacting logger. Event names and
// fields are public interface (ADR-0023); docs/reference/observability.md maps them to OCSF.
package audit

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// SchemaVersion is bumped on any incompatible change to an event's fields.
const SchemaVersion = 1

// Event names. Add new ones here, to the golden file and to the docs; never rename one.
const (
	Login               = "login"                 // sign-in through the IdP finished (success) or failed
	AccessDenied        = "access_denied"         // the access gate refused a signed-in user, at sign-in or refresh (ADR-0015)
	TokenIssued         = "token_issued"          // /token issued an access token
	TokenRejected       = "token_rejected"        // /token or /revoke refused a request
	AccessTokenRejected = "access_token_rejected" // an MCP request carried an invalid or expired token
	GrantRevoked        = "grant_revoked"         // a grant was revoked (code or refresh-token reuse, misuse, the client, or the IdP)
	ClientRegistered    = "client_registered"     // a client was registered (static clients at startup)
	KeyLoaded           = "key_loaded"            // a sealing key was loaded at startup
	HostRejected        = "host_rejected"         // a request named a Host outside the allowlist
	OriginRejected      = "origin_rejected"       // a request sent an Origin outside the allowlist
	ConsentShown        = "consent_shown"         // the consent page was shown (ADR-0010 §12)
	ConsentGranted      = "consent_granted"       // the user allowed the client on the consent page
	ConsentDenied       = "consent_denied"        // the user denied the client on the consent page
	RateLimited         = "rate_limited"          // an OAuth endpoint refused a request over its per-address budget
	StoreRestored       = "store_restored"        // startup found the store restored from an older copy; a new epoch began (ADR-0007 §9)
	SessionRejected     = "session_rejected"      // a signed-in user presented an MCP session ID not bound to them (invariant 13)
	ProcessEvicted      = "process_evicted"       // an idle stdio upstream process was stopped to make room under a process cap (ADR-0003 §5)
)

// Outcomes.
const (
	Success = "success"
	Failure = "failure"
)

// Event is one audit record. Only the fields that apply are set; none may hold a credential.
type Event struct {
	Name     string
	Outcome  string
	Reason   string // a fixed, human-readable reason; never request data
	ClientID string // the MCP client's ID
	// ClientTrust is the client's trust level (ADR-0008 §8): verified, domain or not-verified.
	ClientTrust string
	UserKey     string // the IdP user key (`tid:oid` for Entra)
	GrantID     string
	KeyID       string
	IdP         string // the IdP adapter name, e.g. "entra"
	Host        string
	Origin      string
	Epoch       int64 // the store epoch (store_restored); 0 means not set
}

// Observer is told about every event, including suppressed ones (metrics count them all).
type Observer func(name, outcome string)

// Log emits audit events. A nil *Log discards them, so packages can be used without one.
type Log struct {
	log     *slog.Logger
	limiter *logging.Limiter
	observe Observer
}

// Unauthenticated events are limited to this many per source address per minute.
const (
	unauthBurst   = 10
	unauthWindow  = time.Minute
	unauthSources = 10000
)

// New returns an audit log writing through log; observe may be nil.
func New(log *slog.Logger, observe Observer, now func() time.Time) *Log {
	return &Log{log: log, observe: observe, limiter: logging.NewLimiter(unauthBurst, unauthWindow, unauthSources, now)}
}

// Record writes e for request r, with its request ID and source address. r is nil for events
// with no request (startup).
func (l *Log) Record(r *http.Request, e Event) {
	if l == nil {
		return
	}
	if r == nil {
		l.write(context.Background(), e, "", 0)
		return
	}
	l.write(r.Context(), e, logging.RemoteIP(r), 0)
}

// RecordUnauthenticated writes e for a request whose sender is not authenticated, limited per
// source address and event, so frequent events (page views) never crowd out rarer ones (decisions);
// when events were dropped the next record of that event carries `suppressed=N` (ADR-0021 §5).
func (l *Log) RecordUnauthenticated(r *http.Request, e Event) {
	if l == nil {
		return
	}
	ip := logging.RemoteIP(r)
	ok, suppressed := l.limiter.Allow(ip + "\x00" + e.Name)
	if !ok {
		if l.observe != nil {
			l.observe(e.Name, e.Outcome)
		}
		return
	}
	l.write(r.Context(), e, ip, suppressed)
}

func (l *Log) write(ctx context.Context, e Event, ip string, suppressed int) {
	if l.observe != nil {
		l.observe(e.Name, e.Outcome)
	}
	attrs := []slog.Attr{slog.String("log.type", "audit"), slog.Int("schema_version", SchemaVersion),
		slog.String("event", e.Name), slog.String("outcome", e.Outcome)}
	if id := logging.RequestID(ctx); id != "" {
		attrs = append(attrs, slog.String("request_id", id))
	}
	for _, f := range []struct{ k, v string }{{"reason", e.Reason}, {"client_id", e.ClientID}, {"client_trust", e.ClientTrust}, {"user_key", e.UserKey},
		{"grant_id", e.GrantID}, {"key_id", e.KeyID}, {"idp", e.IdP}, {"host", e.Host}, {"origin", e.Origin}, {"remote_ip", ip}} {
		if f.v != "" {
			attrs = append(attrs, slog.String(f.k, f.v))
		}
	}
	if e.Epoch > 0 {
		attrs = append(attrs, slog.Int64("epoch", e.Epoch))
	}
	if suppressed > 0 {
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}
	level := slog.LevelInfo
	if e.Outcome == Failure {
		level = slog.LevelWarn
	}
	l.log.LogAttrs(ctx, level, "audit "+e.Name, attrs...)
}
