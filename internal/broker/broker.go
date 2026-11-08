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
	"strconv"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/denylist"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/token"
)

// Lifetimes (ADR-0006 §5).
const (
	CodeLifetime   = 60 * time.Second
	AccessLifetime = time.Hour
	// IdPTokenMargin: with CapAccessToIdPToken, an access token expires this long before the IdP
	// access token it rides on (the downstream cache's margin, ADR-0017 §4).
	IdPTokenMargin = 60 * time.Second
	// MinCappedLifetime: a cap that would leave an access token less than this is not applied; a
	// client given expires_in 0 would refresh in a loop.
	MinCappedLifetime = 30 * time.Second
	GrantLifetime     = 30 * 24 * time.Hour
	LoginLifetime     = 10 * time.Minute
	// ConsentLifetime is how long a remembered consent counts, from its Allow (ADR-0010 §3); it does
	// not slide with use.
	ConsentLifetime = 30 * 24 * time.Hour
	// RefreshIdleLifetime: a refresh token unused for this long expires (ADR-0006 §5).
	RefreshIdleLifetime = 14 * 24 * time.Hour
	// MaxRefreshGrace bounds the reuse grace window (ADR-0006 §4); its default is the
	// refresh-grace setting's.
	MaxRefreshGrace = 60 * time.Second
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
	Issuer    string   // derived once from the public URL (ADR-0013 §2)
	Origin    string   // the public URL's origin; consent answers must carry exactly this Origin
	Resource  *url.URL // the public MCP URL
	Scope     string
	IdPName   string // "entra": the callback path is /callback/{IdPName}
	IdPLabel  string // "Microsoft Entra", for pages
	IdPScopes string // the scopes asked of the IdP, listed on the consent page
	// CIMD advertises client_id_metadata_document_supported; Clients then resolves CIMD URLs.
	CIMD bool
	// Registrar, when set, serves POST /register and advertises registration_endpoint (DCR,
	// ADR-0008 §2-3); Clients then resolves the clients it registers.
	Registrar Registrar
	// JWKSURI is the identity assertion's JWKS (ADR-0016 §3), advertised as jwks_uri so a verifier
	// that only uses OIDC discovery finds the keys (ADR-0016 amendment, #207); "" without assertion
	// keys (a stdio upstream).
	JWKSURI string
	// ObserveRegistration, when set, is told every /register outcome (one of the Registration*).
	ObserveRegistration func(outcome string)
	IdP                 IdP
	Clients             registration.Registry
	Store               store.Store
	Sealer              *token.Sealer // proxy tokens: access and code
	LoginBox            *token.Box    // the login-in-progress cookie
	ConsentBox          *token.Box    // the consent flow in the consent page's form
	IdPTokenBox         *token.Box    // IdP tokens at rest
	// ConsentHintBox seals the remembered-consent hint cookie (ADR-0010 §3); nil asks every client
	// every time.
	ConsentHintBox *token.Box
	// ObserveConsent, when set, is told each consent outcome (shown, granted, denied, remembered)
	// with the client's trust level, for metrics (ADR-0010 §12).
	ObserveConsent func(trust, outcome string)
	Gate           Gate
	// Assert selects the optional identity claims access tokens carry for the upstream's
	// assertion (ADR-0016 §1).
	Assert Asserted
	// Consent page wording (ADR-0010 §4): the upstream's name (default: the public host), what the
	// scope lets an app do in plain words, and who runs the proxy. All optional.
	UpstreamName string
	ScopeText    string
	OperatorName string
	// RefreshGrace is how long the previous refresh token may be presented again after a rotation
	// (a lost response); 0 disables it. At most MaxRefreshGrace.
	RefreshGrace time.Duration
	// CapAccessToIdPToken caps every access token at the grant's IdP access token expiry minus
	// IdPTokenMargin, so the token On-Behalf-Of presents is valid while the access token is
	// (ADR-0017 amendment 2026-11-07). The server sets it when On-Behalf-Of is on.
	CapAccessToIdPToken bool
	// SecureCookies is false only in development mode on loopback http (ADR-0010 §10).
	SecureCookies bool
	Log           *slog.Logger
	// Audit receives the security events (ADR-0021 §3); nil discards them.
	Audit *audit.Log
	// Limiter rate-limits the OAuth endpoints per client address (ADR-0018 §8); nil limits nothing.
	Limiter Limiter
	// ObserveIdP, when set, is told each IdP call's operation, outcome (success, rejected,
	// unavailable) and duration, for metrics.
	ObserveIdP func(operation, outcome string, d time.Duration)
	Now        func() time.Time
}

// Limiter decides whether a request to an OAuth endpoint (authorize, consent, callback, token,
// revoke, register) from a client address may proceed, and if not, when it may retry.
type Limiter interface {
	Allow(endpoint, ip string) (ok bool, retryAfter time.Duration)
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
	if b.cfg.Registrar != nil {
		mux.Handle("/register", limitBody(64<<10, http.HandlerFunc(b.register)))
	}
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

// throttled reports whether r is over endpoint's budget; if so it records the audit event (rate-
// limited itself, the sender is not authenticated), sets Retry-After and returns its seconds. The
// caller writes the response its endpoint calls for.
func (b *Broker) throttled(w http.ResponseWriter, r *http.Request, endpoint string) (retry int, limited bool) {
	if b.cfg.Limiter == nil {
		return 0, false
	}
	ok, wait := b.cfg.Limiter.Allow(endpoint, logging.RemoteIP(r))
	if ok {
		return 0, false
	}
	b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.RateLimited, Outcome: audit.Failure, Reason: endpoint})
	retry = retrySeconds(wait)
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	return retry, true
}

// retrySeconds rounds wait up to whole seconds, at least 1 (RFC 9110 §10.2.3 delay-seconds).
func retrySeconds(wait time.Duration) int {
	s := int((wait + time.Second - 1) / time.Second)
	if s < 1 {
		return 1
	}
	return s
}

const tooManyTitle = "Too many sign-in attempts from your network."

func tooManyHint(retry int) string {
	return "Wait " + strconv.Itoa(retry) + " seconds and start again from your app."
}
