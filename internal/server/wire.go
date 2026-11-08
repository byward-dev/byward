package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/token"
)

// maxRateLimitKeys bounds the client addresses each OAuth endpoint tracks (ADR-0018 §8).
const maxRateLimitKeys = 100000

// auth is what authenticated mode adds: the broker's routes, the access-token validator and the
// readiness checks for its keys and store.
type auth struct {
	register  func(*http.ServeMux)
	validator resource.Validator
	checks    []health.Check
	// background runs until ctx ends: it keeps the revocation list fresh (ADR-0006 §3) and removes
	// expired store rows (ADR-0007 §1).
	background func(ctx context.Context)
	// closeStore releases the store; Run calls it after the background work has stopped.
	closeStore func() error
	// sessions binds legacy-era MCP sessions to the user (ADR-0004 §2, invariant 13).
	sessions func(http.Handler) http.Handler
	// minter signs the identity assertion and jwks serves its keys; both nil for a stdio upstream.
	minter *assertion.Minter
	// downstream is On-Behalf-Of (ADR-0017); nil when it is off.
	downstream *downstreamTokens
	jwks       http.Handler
}

// buildAuth wires the broker: sealing keys, Entra, static clients, the access gate and the SQLite
// store. Errors name the file or setting at fault.
func buildAuth(cfg *config.Config, log *slog.Logger, o Observability) (_ *auth, err error) {
	logPaths(cfg, log)
	parts, err := loadAuthParts(cfg, idpHTTPClient)
	if err != nil {
		return nil, err
	}
	if err := parts.idp.refusal(time.Now()); err != nil {
		return nil, err
	}
	ring, sealer, ip, static, g := parts.ring, parts.sealer, parts.idp, parts.static, parts.gate
	auditStartup(o.Audit, ring, static.IDs())
	log.Info("client sources", "static_clients", len(static.IDs()), "cimd", cfg.CIMD, "dcr", cfg.DCR)
	for _, w := range parts.warnings {
		w.log(log)
	}
	log.Info("IdP", "idp", ip.name, "reason", "register this redirect URI with the IdP app: "+ip.redirect)
	for _, w := range ip.timedWarnings(time.Now()) {
		w.log(log)
	}
	st, err := wireStore(cfg, log, o.Audit)
	if err != nil {
		return nil, err
	}
	defer func() { // every later failure closes the store it opened
		if err != nil {
			_ = st.Close()
		}
	}()
	w := &wiring{cfg: cfg, log: log, o: o, parts: parts, store: st,
		guard: ssrfguard.New(ssrfguard.Config{})} // every client-supplied URL (CIMD documents, jwks_uri) goes through it
	clients := registration.Chain{static}
	var registrar broker.Registrar
	for _, source := range clientSources {
		c, r, err := source(w)
		if err != nil {
			return nil, err
		}
		if c != nil {
			clients = append(clients, c)
		}
		if r != nil {
			registrar = r
		}
	}
	b, err := newBroker(broker.Config{Issuer: cfg.Issuer(), Origin: cfg.Origin(), Resource: cfg.PublicURL, Scope: cfg.Scope,
		IdPName: ip.name, IdPLabel: ip.label, IdPScopes: ip.scope, IdP: ip.adapter, Clients: clients, CIMD: cfg.CIMD, Registrar: registrar, ObserveRegistration: o.Metrics.DCRRegistration,
		Store: st, Sealer: sealer, LoginBox: parts.loginBox, IdPTokenBox: parts.idpBox, ConsentBox: parts.consentBox, ConsentHintBox: parts.hintBox, ObserveConsent: o.Metrics.Consent, Gate: g,
		UpstreamName: cfg.ResourceName, ScopeText: cfg.ScopeDescription, OperatorName: cfg.OperatorName, CapAccessToIdPToken: len(cfg.OBOScopes) > 0,
		SecureCookies: cfg.PublicURL.Scheme == "https", Log: log,
		Audit: o.Audit, Limiter: ratelimit.New(cfg.OAuthRateLimits, maxRateLimitKeys, time.Now, o.Metrics.RateLimited),
		ObserveIdP:   func(op, outcome string, d time.Duration) { o.Metrics.IdP(ip.name, op, outcome, d) },
		RefreshGrace: cfg.RefreshGrace, Assert: assertedClaims(cfg), JWKSURI: assertionJWKSURI(cfg, parts)})
	if err != nil {
		return nil, err
	}
	deny := b.Deny()
	// The list refuses every token until its first sync, so sync before serving.
	syncCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := deny.Sync(syncCtx); err != nil {
		return nil, fmt.Errorf("loading the revocation list: %w", err)
	}
	sealed, err := token.NewValidator(sealer, deny, nil)
	if err != nil {
		return nil, err
	}
	app, err := wireAppTokens(w, deny)
	if err != nil {
		return nil, err
	}
	v := resource.Dispatch(token.Prefix, sealed, app)
	log.Info("broker ready", "reason", "keys "+fmt.Sprint(len(ring.KeyIDs()))+", signing with "+ring.SigningKeyID()+"")
	a := &auth{register: b.Register, validator: v, checks: readiness(ring, st), background: func(ctx context.Context) { runBackground(ctx, st, deny, log) }, closeStore: st.Close,
		sessions: func(next http.Handler) http.Handler {
			return mcpsession.Bind(mcpsession.Config{Box: parts.sessionBox, Upstream: upstreamID(cfg), User: signedInUser,
				Lifetime: broker.GrantLifetime, Audit: o.Audit, Log: log}, next)
		}}
	w.broker = b
	for _, feature := range authFeatures {
		if err := feature(w, a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// wiring is what buildAuth has built so far, for the feature files' wiring steps.
type wiring struct {
	cfg    *config.Config
	log    *slog.Logger
	o      Observability
	parts  *authParts
	store  *sqlite.Store
	guard  *ssrfguard.Fetcher
	broker *broker.Broker // set once the broker is built, before authFeatures run
}

// clientSources add client registries after the static clients, in this order; each returns nil
// when its feature is off, and the registry that also registers clients (DCR) as the Registrar.
var clientSources = []func(*wiring) (registration.Registry, broker.Registrar, error){wireCIMD, wireDCR}

// authFeatures complete auth once the broker is built, in this order (the plain identity headers
// need the assertion's minter).
var authFeatures = []func(*wiring, *auth) error{wireAssertion, wireIdentityHeaders, wireOBO}

// auditStartup records the keys and static clients the proxy starts with (ADR-0021 §3).
func auditStartup(rec *audit.Log, ring *token.KeyRing, staticClients []string) {
	for _, id := range ring.KeyIDs() {
		use := "verification"
		if id == ring.SigningKeyID() {
			use = "signing"
		}
		rec.Record(nil, audit.Event{Name: audit.KeyLoaded, Outcome: audit.Success, Reason: use, KeyID: id})
	}
	for _, id := range staticClients {
		rec.Record(nil, audit.Event{Name: audit.ClientRegistered, Outcome: audit.Success, Reason: "static", ClientID: id})
	}
}

// signedInUser is the subject Guard attached to the request, which MCP sessions are bound to. Any
// principal other than a user is marked with its type, so a user's session is never an app's
// (invariant 13); users' keys stay as they were.
func signedInUser(r *http.Request) (string, bool) {
	id, ok := resource.IdentityFrom(r.Context())
	ok = ok && id.Subject != ""
	if id.PrincipalType != resource.PrincipalUser && id.PrincipalType != "" {
		return id.PrincipalType + ":" + id.Subject, ok
	}
	return id.Subject, ok
}

// idpHTTPClient reaches the IdP for the serving proxy; nil is the default client. Tests point it at
// a fake IdP.
var idpHTTPClient *http.Client

// newBroker is broker.New; tests replace it to see the wired configuration.
var newBroker = broker.New

// logPaths logs the absolute paths the proxy uses, defaults resolved (ADR-0007 §6).
func logPaths(cfg *config.Config, log *slog.Logger) {
	for _, p := range []struct{ setting, value string }{
		{"BYWARD_DATA_DIR", cfg.DataDir}, {"BYWARD_KEYS_DIR", cfg.KeysDir},
		{"BYWARD_STATIC_CLIENTS_FILE", cfg.StaticClientsFile}, {"BYWARD_STORE_DIR", cfg.StoreDir},
		{"BYWARD_STORE_COUNTER_FILE", cfg.StoreCounterFile},
	} {
		log.Info("path", "setting", p.setting, "value", p.value)
	}
}
