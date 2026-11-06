// Package broker is the proxy's authorization-server role toward MCP clients (CONTEXT.md
// "Broker"): it serves authorization-server metadata, runs /authorize, receives the IdP's callback,
// and issues proxy tokens at /token, acting itself as an OAuth client of the IdP (ADR-0005).
//
// Slice 1.4 scope: static clients, a consent page before every IdP login, the access gate as a
// Gate (slice 1.5), no refresh tokens yet (slice 1.6).
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/token"
)

// Lifetimes (ADR-0006 §5).
const (
	CodeLifetime   = 60 * time.Second
	AccessLifetime = time.Hour
	GrantLifetime  = 30 * 24 * time.Hour
	LoginLifetime  = 10 * time.Minute
)

// Gate is the access gate (ADR-0015), checked before a grant is created. A refusal is an error
// implementing Denial; any other error is a failure to decide (500), never shown as a denial.
type Gate interface {
	Allow(ctx context.Context, id idp.Identity) error
}

// Denial is a Gate refusal; DeniedRule names the rule, for the audit log.
type Denial interface {
	error
	DeniedRule() string
}

// AllowAll lets every signed-in user through; New uses it when Config.Gate is nil. The proxy wires
// the access gate built by gate.New.
type AllowAll struct{}

// Allow implements Gate.
func (AllowAll) Allow(context.Context, idp.Identity) error { return nil }

// Config wires a Broker.
type Config struct {
	Issuer      string   // derived once from the public URL (ADR-0013 §2)
	Origin      string   // the public URL's origin; consent answers must carry exactly this Origin
	Resource    *url.URL // the public MCP URL
	Scope       string
	IdPName     string // "entra": the callback path is /callback/{IdPName}
	IdPLabel    string // "Microsoft Entra", for pages
	IdPScopes   string // the scopes asked of the IdP, listed on the consent page
	IdP         idp.Authenticator
	Clients     registration.Registry
	Store       store.Store
	Sealer      *token.Sealer // proxy tokens: access and code
	LoginBox    *token.Box    // the login-in-progress cookie
	ConsentBox  *token.Box    // the consent flow in the consent page's form
	IdPTokenBox *token.Box    // IdP tokens at rest
	Gate        Gate
	// Consent page wording (ADR-0010 §4): the upstream's name (default: the public host), what the
	// scope lets an app do in plain words, and who runs the proxy. All optional.
	UpstreamName string
	ScopeText    string
	OperatorName string
	// SecureCookies is false only in development mode on loopback http (ADR-0010 §10).
	SecureCookies bool
	Log           *slog.Logger
	// Audit receives the security events (ADR-0021 §3); nil discards them.
	Audit *audit.Log
	// ObserveIdP, when set, is told each IdP call's operation, outcome (success, rejected,
	// unavailable) and duration, for metrics.
	ObserveIdP func(operation, outcome string, d time.Duration)
	Now        func() time.Time
}

// Broker is the authorization server.
type Broker struct {
	cfg     Config
	deny    *DenyList
	answers *answers
}

// New checks cfg.
func New(cfg Config) (*Broker, error) {
	if cfg.Issuer == "" || cfg.Resource == nil || cfg.Scope == "" || cfg.IdPName == "" || cfg.IdP == nil ||
		cfg.Clients == nil || cfg.Store == nil || cfg.Sealer == nil || cfg.LoginBox == nil || cfg.IdPTokenBox == nil || cfg.ConsentBox == nil || cfg.Origin == "" || cfg.Log == nil {
		return nil, errors.New("broker: incomplete configuration")
	}
	if cfg.Gate == nil {
		cfg.Gate = AllowAll{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ObserveIdP == nil {
		cfg.ObserveIdP = func(string, string, time.Duration) {}
	}
	return &Broker{cfg: cfg, deny: newDenyList(), answers: newAnswers()}, nil
}

// Paths the broker serves.
func (b *Broker) callbackPath() string  { return "/callback/" + b.cfg.IdPName }
func (b *Broker) tokenEndpoint() string { return b.cfg.Issuer + "/token" }

// Register adds the broker's routes to mux.
func (b *Broker) Register(mux *http.ServeMux) {
	md := b.metadataHandler()
	mux.Handle("/.well-known/oauth-authorization-server", md)
	mux.Handle("/.well-known/openid-configuration", md)
	mux.HandleFunc("/authorize", b.authorize)
	mux.Handle("/consent", limitBody(16<<10, http.HandlerFunc(b.consent)))
	mux.HandleFunc(StylesheetPath, stylesheet)
	mux.HandleFunc(b.callbackPath(), b.callback)
	mux.Handle("/token", limitBody(64<<10, http.HandlerFunc(b.token)))
}

// DenyList is the in-memory revocation list the access-token validator reads (ADR-0006 §3). In
// slice 1.2 only this replica's own revocations fill it; syncing from the store is slice 1.6.
type DenyList struct {
	mu     sync.RWMutex
	grants map[string]bool
}

func newDenyList() *DenyList { return &DenyList{grants: map[string]bool{}} }

// Denied implements token.DenyList.
func (d *DenyList) Denied(grantID, _ string, _ time.Time) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.grants[grantID], nil
}

func (d *DenyList) add(grantID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.grants[grantID] = true
}

// Deny is the deny list for the access-token validator.
func (b *Broker) Deny() *DenyList { return b.deny }

func randomID() string {
	r := make([]byte, 16)
	_, _ = rand.Read(r)
	return hex.EncodeToString(r)
}

func limitBody(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r)
	})
}
