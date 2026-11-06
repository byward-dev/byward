// Package broker is the proxy's authorization-server role toward MCP clients (CONTEXT.md
// "Broker"): it serves authorization-server metadata, runs /authorize, receives the IdP's callback,
// and issues proxy tokens at /token, acting itself as an OAuth client of the IdP (ADR-0005).
//
// Scope so far: static clients, a consent page before every IdP login (slice 1.4), the access
// gate as a Gate (slice 1.5); refresh, rotation and /revoke since slice 1.6.
package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/denylist"
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
	// RefreshIdleLifetime: a refresh token unused for this long expires (ADR-0006 §5).
	RefreshIdleLifetime = 14 * 24 * time.Hour
	// DefaultRefreshGrace and MaxRefreshGrace bound the reuse grace window (ADR-0006 §4).
	DefaultRefreshGrace = 30 * time.Second
	MaxRefreshGrace     = 60 * time.Second
)

// IdP is what the broker needs from the IdP adapter: sign-in, and refresh on every token refresh
// so a grant never outlives the IdP session (ADR-0006 §5). Every adapter implements both.
type IdP interface {
	idp.Authenticator
	idp.Refresher
}

// Gate is the access gate (ADR-0015), checked before a grant is created and again on every
// refresh. A refusal is an error implementing Denial; any other error is a failure to decide
// (500), never shown as a denial.
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
	IdP         IdP
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
	// RefreshGrace is how long the previous refresh token may be presented again after a rotation
	// (a lost response); 0 disables it. At most MaxRefreshGrace.
	RefreshGrace time.Duration
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
	deny    *denylist.List
	answers *answers
	// refreshing serializes refreshes per grant on this replica, so two concurrent refreshes do not
	// both spend the IdP's refresh token. Sharded: memory stays fixed.
	refreshing [64]sync.Mutex
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
	if cfg.RefreshGrace < 0 || cfg.RefreshGrace > MaxRefreshGrace {
		return nil, errors.New("broker: the refresh grace window must be between 0 and 60 s")
	}
	return &Broker{cfg: cfg, deny: denylist.New(cfg.Store, cfg.Now), answers: newAnswers()}, nil
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
	mux.Handle("/revoke", limitBody(64<<10, http.HandlerFunc(b.revokeEndpoint)))
}

// Deny is the deny list for the access-token validator. The caller syncs it before serving and
// keeps it fresh with Run (ADR-0006 §3).
func (b *Broker) Deny() *denylist.List { return b.deny }

// lockGrant serializes refreshes of one grant on this replica.
func (b *Broker) lockGrant(id string) func() {
	sum := sha256.Sum256([]byte(id))
	m := &b.refreshing[int(sum[0])%len(b.refreshing)]
	m.Lock()
	return m.Unlock
}

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
