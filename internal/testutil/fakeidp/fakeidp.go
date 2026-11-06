// Package fakeidp is an in-process OIDC identity provider for tests.
//
// The entra profile reproduces the Microsoft Entra ID v2 behaviour the proxy depends on
// (ADR-0012, ADR-0017, ADR-0022, ADR-0024 §5): the v2 issuer per tenant, `aud` = the client ID,
// a pairwise `sub`, `tid`/`oid`, roles, groups overage, AADSTS-shaped errors, app-only tokens and
// On-Behalf-Of. The generic profile is a plain OIDC provider with RFC 9207 `iss` support.
//
// Login is automatic: the authorization endpoint signs in the configured user and redirects
// straight back to the redirect URI, so tests need no browser. Quirks and failures are options,
// applied at construction with New or later with Set.
package fakeidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Profile selects which IdP the fake behaves like.
type Profile string

// Profiles.
const (
	Entra   Profile = "entra"
	Generic Profile = "generic"
)

// Grant types accepted at the token endpoint.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: a grant-type URN, not a credential
)

// DefaultAuthority is the host of the Entra v2 issuer.
const DefaultAuthority = "https://login.microsoftonline.com"

// User is the person the fake signs in.
type User struct {
	// TenantID is the user's home tenant (Entra); empty means the IdP's tenant.
	TenantID string
	// OID is the Entra object ID; empty means a generated GUID.
	OID string
	// Subject is the generic profile's `sub`; empty means a generated GUID. Entra derives a
	// pairwise `sub` per app instead.
	Subject           string
	Name              string
	PreferredUsername string
	Email             string
	// EmailVerified is used by the generic profile only.
	EmailVerified bool
	// HostedDomain is the generic profile's `hd` claim (Google Workspace).
	HostedDomain string
	// Roles are the user's app roles (Entra only).
	Roles  []string
	Groups []string
	// GroupsOverage replaces `groups` with the overage claims, as Entra does above 200 groups
	// (Entra only).
	GroupsOverage bool
}

// Client is an app registration at the fake IdP: the proxy's IdP app, a headless caller, or a
// resource (API) that tokens are issued for.
type Client struct {
	ID string
	// Secrets lists accepted client secrets; more than one models a rollover.
	Secrets []string
	// Certificates lists accepted private_key_jwt keys; more than one models a rollover.
	Certificates []*Certificate
	RedirectURIs []string
	// ServicePrincipalID is the `oid` of app-only tokens (Entra only); empty means a generated GUID.
	ServicePrincipalID string
	// AppRoles maps a resource client ID to the app roles assigned to this client on it (Entra
	// only).
	AppRoles map[string][]string
	// AssignmentRequired, on a resource, refuses client-credential tokens to callers without a
	// role (AADSTS501051; Entra only).
	AssignmentRequired bool
}

func (c Client) confidential() bool { return len(c.Secrets) > 0 || len(c.Certificates) > 0 }

// IdP is a running fake identity provider.
type IdP struct {
	srv     *httptest.Server
	profile Profile

	mu      sync.Mutex
	cfg     settings
	keys    []*signingKey // the last one signs
	codes   map[string]*authCode
	refresh map[string]*refreshGrant
}

type settings struct {
	clock           func() time.Time
	tenantID        string
	authority       string
	issuer          string
	user            User
	userTenantSet   bool
	clients         map[string]Client
	tokenLifetime   time.Duration
	refreshLifetime time.Duration
	codeLifetime    time.Duration
	issParam        bool
	requirePKCE     bool
	rotateRefresh   bool
	idtyp           bool
	emailAsString   bool
	authorizeFail   *Failure
	jwksDown        bool
	tokenFail       map[string]Failure
}

// Option configures the fake. Options apply at New and at Set.
type Option func(*settings)

// New starts a fake IdP with the given profile and stops it when the test ends.
func New(t testing.TB, profile Profile, opts ...Option) *IdP {
	t.Helper()
	if profile != Entra && profile != Generic {
		t.Fatalf("fakeidp: unknown profile %q", profile)
	}
	p := &IdP{
		profile: profile,
		cfg: settings{
			clock:           time.Now,
			tenantID:        NewGUID(),
			authority:       DefaultAuthority,
			clients:         map[string]Client{},
			tokenLifetime:   time.Hour,
			refreshLifetime: 90 * 24 * time.Hour,
			codeLifetime:    10 * time.Minute,
			issParam:        profile == Generic,
			rotateRefresh:   true,
			idtyp:           true,
			tokenFail:       map[string]Failure{},
		},
		codes:   map[string]*authCode{},
		refresh: map[string]*refreshGrant{},
	}
	for _, o := range opts {
		o(&p.cfg)
	}
	p.cfg.user = p.completeUser(p.cfg.user)
	key, err := newSigningKey(p.cfg.clock())
	if err != nil {
		t.Fatalf("fakeidp: signing key: %v", err)
	}
	p.keys = []*signingKey{key}
	p.srv = httptest.NewServer(p.routes())
	t.Cleanup(p.srv.Close)
	return p
}

// Set applies options to a running fake, e.g. to make the next refresh fail.
func (p *IdP) Set(opts ...Option) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, o := range opts {
		o(&p.cfg)
	}
	// A user without an explicit tenant follows a WithTenantID change.
	if !p.cfg.userTenantSet {
		p.cfg.user.TenantID = p.cfg.tenantID
	}
	p.cfg.user = p.completeUser(p.cfg.user)
}

func (p *IdP) completeUser(u User) User {
	if u.TenantID == "" {
		u.TenantID = p.cfg.tenantID
	}
	if u.OID == "" {
		u.OID = NewGUID()
	}
	if u.Subject == "" {
		u.Subject = NewGUID()
	}
	if u.Name == "" {
		u.Name = "Test User"
	}
	if u.PreferredUsername == "" {
		u.PreferredUsername = "test.user@contoso.example"
	}
	return u
}

// WithClock sets the time source for every issued and checked timestamp.
func WithClock(now func() time.Time) Option { return func(s *settings) { s.clock = now } }

// WithTenantID sets the IdP's (home) tenant; the default is a generated GUID.
func WithTenantID(tid string) Option { return func(s *settings) { s.tenantID = tid } }

// WithAuthority sets the host of the Entra issuer; the default is DefaultAuthority. Endpoints are
// always served by the fake itself.
func WithAuthority(url string) Option {
	return func(s *settings) { s.authority = strings.TrimSuffix(url, "/") }
}

// WithIssuer sets the generic profile's issuer; the default is the fake's URL.
func WithIssuer(iss string) Option { return func(s *settings) { s.issuer = iss } }

// WithUser sets the user the authorization endpoint signs in.
func WithUser(u User) Option {
	return func(s *settings) { s.user, s.userTenantSet = u, u.TenantID != "" }
}

// WithClient registers or replaces an app registration.
func WithClient(c Client) Option {
	return func(s *settings) {
		if c.ServicePrincipalID == "" {
			if old, ok := s.clients[c.ID]; ok {
				c.ServicePrincipalID = old.ServicePrincipalID
			} else {
				c.ServicePrincipalID = NewGUID()
			}
		}
		s.clients[c.ID] = c
	}
}

// WithTokenLifetime sets the lifetime of ID and access tokens (default 1 h).
func WithTokenLifetime(d time.Duration) Option { return func(s *settings) { s.tokenLifetime = d } }

// WithRefreshTokenLifetime sets the lifetime of refresh tokens (default 90 days).
func WithRefreshTokenLifetime(d time.Duration) Option {
	return func(s *settings) { s.refreshLifetime = d }
}

// WithCodeLifetime sets the lifetime of authorization codes (default 10 min).
func WithCodeLifetime(d time.Duration) Option { return func(s *settings) { s.codeLifetime = d } }

// WithIssParameter switches the RFC 9207 `iss` authorization-response parameter and its metadata
// flag. Default: on for generic, off for Entra (Entra never sends it).
func WithIssParameter(on bool) Option { return func(s *settings) { s.issParam = on } }

// WithRequirePKCE refuses authorization requests without a code challenge.
func WithRequirePKCE(on bool) Option { return func(s *settings) { s.requirePKCE = on } }

// WithRefreshTokenRotation switches returning a new refresh token on refresh (default on).
func WithRefreshTokenRotation(on bool) Option { return func(s *settings) { s.rotateRefresh = on } }

// WithIDTypClaim switches `idtyp: app` on app-only tokens, i.e. whether the resource app has the
// optional claim configured (default on).
func WithIDTypClaim(on bool) Option { return func(s *settings) { s.idtyp = on } }

// WithEmailVerifiedAsString makes the generic profile send `email_verified` as "true"/"false"
// (a Google quirk).
func WithEmailVerifiedAsString(on bool) Option { return func(s *settings) { s.emailAsString = on } }

// WithJWKSUnavailable makes the JWKS endpoint answer 503, as during an IdP outage.
func WithJWKSUnavailable(on bool) Option { return func(s *settings) { s.jwksDown = on } }

// FailAuthorize makes every authorization request redirect back with f; nil clears it.
func FailAuthorize(f *Failure) Option {
	return func(s *settings) {
		if f == nil {
			s.authorizeFail = nil
			return
		}
		c := *f
		s.authorizeFail = &c
	}
}

// FailToken makes every token request of the grant type fail with f, after client
// authentication; nil clears it.
func FailToken(grantType string, f *Failure) Option {
	return func(s *settings) {
		if f == nil {
			delete(s.tokenFail, grantType)
			return
		}
		s.tokenFail[grantType] = *f
	}
}

// URL is the base URL the fake listens on.
func (p *IdP) URL() string { return p.srv.URL }

// TenantID is the IdP's home tenant.
func (p *IdP) TenantID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.tenantID
}

// User returns the user the fake signs in, with generated fields filled.
func (p *IdP) User() User {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.user
}

// Client returns a registered client, with generated fields filled.
func (p *IdP) Client(id string) (Client, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.cfg.clients[id]
	return c, ok
}

// Issuer is the issuer of tokens for the home tenant.
func (p *IdP) Issuer() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.issuerFor(p.cfg.tenantID)
}

func (p *IdP) issuerFor(tid string) string {
	if p.profile == Generic {
		if p.cfg.issuer != "" {
			return p.cfg.issuer
		}
		return p.srv.URL
	}
	return p.cfg.authority + "/" + tid + "/v2.0"
}

// endpointBase is where a tenant's endpoints live on the fake ("" for generic).
func (p *IdP) endpointBase(tenant string) string {
	if p.profile == Generic {
		return p.srv.URL
	}
	return p.srv.URL + "/" + tenant
}

// DiscoveryURL is the OpenID configuration URL for a tenant path segment (Entra: a tenant GUID,
// "organizations" or "common"; ignored for generic).
func (p *IdP) DiscoveryURL(tenant string) string {
	if p.profile == Generic {
		return p.srv.URL + "/.well-known/openid-configuration"
	}
	return p.endpointBase(tenant) + "/v2.0/.well-known/openid-configuration"
}

// AuthorizeURL is the authorization endpoint for a tenant path segment.
func (p *IdP) AuthorizeURL(tenant string) string {
	if p.profile == Generic {
		return p.srv.URL + "/authorize"
	}
	return p.endpointBase(tenant) + "/oauth2/v2.0/authorize"
}

// TokenURL is the token endpoint for a tenant path segment.
func (p *IdP) TokenURL(tenant string) string {
	if p.profile == Generic {
		return p.srv.URL + "/token"
	}
	return p.endpointBase(tenant) + "/oauth2/v2.0/token"
}

// JWKSURL is the key set URL for a tenant path segment.
func (p *IdP) JWKSURL(tenant string) string {
	if p.profile == Generic {
		return p.srv.URL + "/keys"
	}
	return p.endpointBase(tenant) + "/discovery/v2.0/keys"
}

// RotateKeys adds a new signing key; earlier keys stay in the JWKS until RetireOldKeys.
func (p *IdP) RotateKeys(t testing.TB) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	key, err := newSigningKey(p.cfg.clock())
	if err != nil {
		t.Fatalf("fakeidp: signing key: %v", err)
	}
	p.keys = append(p.keys, key)
}

// RetireOldKeys removes every key but the current one from the JWKS.
func (p *IdP) RetireOldKeys() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = p.keys[len(p.keys)-1:]
}

// RevokeRefreshTokens makes every refresh token issued so far fail (AADSTS50173 for Entra).
func (p *IdP) RevokeRefreshTokens() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, g := range p.refresh {
		g.revoked = true
	}
}

// Mint signs arbitrary claims with the current key, for tests that need a crafted token.
func (p *IdP) Mint(claims map[string]any) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sign(claims)
}

func (p *IdP) sign(claims map[string]any) string {
	return p.keys[len(p.keys)-1].sign(claims)
}

func (p *IdP) routes() http.Handler {
	mux := http.NewServeMux()
	if p.profile == Generic {
		mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
		mux.HandleFunc("GET /keys", p.jwks)
		mux.HandleFunc("GET /authorize", p.authorize)
		mux.HandleFunc("POST /token", p.token)
		return mux
	}
	mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /{tenant}/discovery/v2.0/keys", p.jwks)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/authorize", p.authorize)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", p.token)
	return mux
}

func (p *IdP) keyByID(kid string) *signingKey {
	for _, k := range p.keys {
		if k.kid == kid {
			return k
		}
	}
	return nil
}
