// Package entra is the Microsoft Entra ID adapter (ADR-0012): v2 endpoints derived from the tenant,
// the `tid:oid` user key, our own access_as_user scope at login, and AADSTS error mapping.
package entra

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/idp"
)

// Authority is the only Entra host the adapter talks to; endpoints are derived from it and the
// tenant and cannot be configured (AGENTS.md security rules).
const Authority = "https://login.microsoftonline.com"

// Organizations is the multi-tenant Tenant value; it needs AllowedTenants.
const Organizations = "organizations"

// Config is the Entra adapter's input, as plain values.
type Config struct {
	// Tenant is a tenant GUID (default, single tenant) or Organizations.
	Tenant string
	// AllowedTenants is required with Organizations: the `tid` allowlist.
	AllowedTenants []string
	ClientID       string
	ClientAuth     idp.ClientAuth
	// RedirectURL is our https://<proxy>/callback/entra.
	RedirectURL string
	// HTTPClient defaults to idp.NewHTTPClient. Tests reach a fake by giving it a transport;
	// there is no endpoint setting.
	HTTPClient *http.Client
	Now        func() time.Time
}

// Provider is the Entra adapter.
type Provider struct {
	cfg     Config
	fetch   *idp.Fetcher
	keys    *idp.KeySet
	allowed map[string]bool

	mu    sync.Mutex
	ready bool
}

var _ interface {
	idp.Authenticator
	idp.Refresher
	idp.Readiness
} = (*Provider)(nil)

// New validates cfg (ADR-0012 §2): a tenant GUID, or organizations with a GUID allowlist; common
// and consumers are refused.
func New(cfg Config) (*Provider, error) {
	cfg.Tenant = strings.ToLower(cfg.Tenant)
	p := &Provider{allowed: map[string]bool{}}
	switch {
	case cfg.Tenant == Organizations:
		if len(cfg.AllowedTenants) == 0 {
			return nil, errors.New("entra: organizations needs a non-empty tenant allowlist")
		}
		for _, t := range cfg.AllowedTenants {
			if !isGUID(t) {
				return nil, fmt.Errorf("entra: allowed tenant %q is not a GUID", t)
			}
			p.allowed[strings.ToLower(t)] = true
		}
	case isGUID(cfg.Tenant):
		if len(cfg.AllowedTenants) > 0 {
			return nil, errors.New("entra: a tenant allowlist only applies to organizations")
		}
	default:
		return nil, fmt.Errorf("entra: tenant must be a tenant GUID or %q (common and consumers are not supported)", Organizations)
	}
	if !isGUID(cfg.ClientID) {
		return nil, errors.New("entra: client ID must be the app registration's GUID")
	}
	if cfg.ClientAuth == nil {
		return nil, errors.New("entra: a client credential is required")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("entra: redirect URL is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p.cfg = cfg
	p.fetch = idp.NewFetcher(cfg.HTTPClient)
	p.keys = idp.NewKeySet(p.fetch, p.endpoint("/discovery/v2.0/keys"), cfg.Now)
	return p, nil
}

func (p *Provider) endpoint(path string) string { return Authority + "/" + p.cfg.Tenant + path }

// Scope is the login scope set: OIDC plus our own API scope, whose access token is kept for
// On-Behalf-Of (ADR-0012 §4).
func (p *Provider) Scope() string {
	return "openid profile email offline_access api://" + p.cfg.ClientID + "/access_as_user"
}

// issuerFor is the v2 issuer of a tenant.
func issuerFor(tid string) string { return Authority + "/" + tid + "/v2.0" }

// Ready fetches the discovery document once and checks its issuer: exact for a tenant, the
// {tenantid} template for organizations. Logins and refreshes wait for it; errors are not cached.
func (p *Provider) Ready(ctx context.Context) error {
	p.mu.Lock()
	ready := p.ready
	p.mu.Unlock()
	if ready {
		return nil
	}
	var m struct {
		Issuer string `json:"issuer"`
	}
	if err := p.fetch.GetJSON(ctx, p.endpoint("/v2.0/.well-known/openid-configuration"), &m); err != nil {
		return &idp.Error{Class: idp.Unavailable, Err: fmt.Errorf("entra discovery: %w", err)}
	}
	want := issuerFor(p.cfg.Tenant)
	if p.cfg.Tenant == Organizations {
		want = issuerFor("{tenantid}")
	}
	if m.Issuer != want {
		return &idp.Error{Class: idp.Fatal, Err: fmt.Errorf("entra discovery: issuer %q, want %q", m.Issuer, want)}
	}
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
	return nil
}

// AuthCodeURL builds the login URL (ADR-0012 §4, §11): PKCE S256, nonce, response_mode=query,
// never `resource`.
func (p *Provider) AuthCodeURL(ctx context.Context, l idp.Login) (string, error) {
	if err := p.Ready(ctx); err != nil {
		return "", err
	}
	if l.State == "" || l.Nonce == "" || l.CodeVerifier == "" {
		return "", errors.New("entra: state, nonce and code verifier are required")
	}
	q := url.Values{
		"client_id":             {p.cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {p.cfg.RedirectURL},
		"response_mode":         {"query"},
		"scope":                 {p.Scope()},
		"state":                 {l.State},
		"nonce":                 {l.Nonce},
		"code_challenge":        {idp.CodeChallenge(l.CodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	if l.LoginHint != "" {
		q.Set("login_hint", l.LoginHint)
	}
	if l.DomainHint != "" {
		q.Set("domain_hint", l.DomainHint)
	}
	switch {
	case l.Silent:
		q.Set("prompt", "none")
	case l.SelectAccount:
		q.Set("prompt", "select_account")
	}
	return p.endpoint("/oauth2/v2.0/authorize") + "?" + q.Encode(), nil
}

// Callback handles /callback/entra. Entra sends no RFC 9207 `iss`; the per-IdP callback path and
// the issuer bound in the broker's state defend against mix-up (ADR-0011 §6).
func (p *Provider) Callback(ctx context.Context, query url.Values, l idp.Login) (idp.Identity, idp.Tokens, error) {
	if err := p.Ready(ctx); err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	cb, err := idp.ReadCallback(query, l, "")
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, &idp.Error{Class: idp.Fatal, Err: err}
	}
	if cb.Error != "" {
		return idp.Identity{}, idp.Tokens{}, newError(0, cb.Error, cb.ErrorDescription, nil, "", "")
	}
	tr, err := p.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.Code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {l.CodeVerifier},
		"scope":         {p.Scope()},
	})
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	if tr.IDToken == "" {
		return idp.Identity{}, idp.Tokens{}, &idp.Error{Class: idp.Fatal, Err: errors.New("entra: token response has no ID token")}
	}
	id, err := p.identity(ctx, tr.IDToken, l.Nonce)
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	if err := p.checkAccessToken(ctx, tr.AccessToken); err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	return id, tr.Tokens(p.cfg.Now()), nil
}

// Refresh renews the tokens with the login scopes. Tokens.RefreshToken is empty when Entra returned
// none, in which case the old one stays (ADR-0012 §6).
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (*idp.Identity, idp.Tokens, error) {
	if refreshToken == "" {
		return nil, idp.Tokens{}, &idp.Error{Class: idp.SignInAgain, Err: errors.New("entra: no refresh token")}
	}
	if err := p.Ready(ctx); err != nil {
		return nil, idp.Tokens{}, err
	}
	tr, err := p.token(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"scope":         {p.Scope()},
	})
	if err != nil {
		return nil, idp.Tokens{}, err
	}
	var id *idp.Identity
	if tr.IDToken != "" {
		i, err := p.identity(ctx, tr.IDToken, "")
		if err != nil {
			return nil, idp.Tokens{}, err
		}
		id = &i
	}
	if err := p.checkAccessToken(ctx, tr.AccessToken); err != nil {
		return nil, idp.Tokens{}, err
	}
	return id, tr.Tokens(p.cfg.Now()), nil
}

func (p *Provider) token(ctx context.Context, form url.Values) (*idp.TokenResponse, error) {
	return p.tokenAt(ctx, p.cfg.Tenant, form)
}

// tokenAt posts form to the token endpoint of tenant (the configured one, or a user's own for
// On-Behalf-Of).
func (p *Provider) tokenAt(ctx context.Context, tenant string, form url.Values) (*idp.TokenResponse, error) {
	tokenURL := Authority + "/" + tenant + "/oauth2/v2.0/token"
	if err := p.cfg.ClientAuth.Apply(form, p.cfg.ClientID, tokenURL, p.cfg.Now()); err != nil {
		return nil, &idp.Error{Class: idp.Unavailable, Alert: true, Err: err}
	}
	header := http.Header{}
	if id := idp.RequestID(ctx); isGUID(id) {
		header.Set("client-request-id", id)
	}
	tr, err := p.fetch.PostToken(ctx, tokenURL, form, header)
	if err != nil {
		return nil, &idp.Error{Class: idp.Unavailable, Err: err}
	}
	if !tr.OK() {
		return nil, newError(tr.Status, tr.Error, tr.ErrorDescription, tr.ErrorCodes, tr.TraceID, tr.CorrelationID)
	}
	return tr, nil
}

func (p *Provider) rules(nonce string) idp.TokenRules {
	return idp.TokenRules{
		Issuer:   p.checkIssuer,
		ClientID: p.cfg.ClientID,
		Nonce:    nonce,
		Algs:     []jose.SignatureAlgorithm{jose.RS256},
		Now:      p.cfg.Now,
	}
}

// checkIssuer is ADR-0012 §2: `tid` must be the configured tenant (or allowlisted under
// organizations) and `iss` exactly that tenant's v2 issuer.
func (p *Provider) checkIssuer(iss string, claims map[string]any) error {
	tid := strings.ToLower(idp.StringClaim(claims, "tid"))
	if !isGUID(tid) {
		return errors.New("entra: token tid is not a GUID")
	}
	if p.cfg.Tenant == Organizations {
		if !p.allowed[tid] {
			return fmt.Errorf("entra: tenant %s is not allowed", tid)
		}
	} else if tid != p.cfg.Tenant {
		return fmt.Errorf("entra: token tenant %s is not the configured tenant", tid)
	}
	if iss != issuerFor(tid) {
		return fmt.Errorf("entra: issuer %q is not the v2 issuer of tenant %s", iss, tid)
	}
	if idp.StringClaim(claims, "ver") != "2.0" {
		return errors.New("entra: token is not a v2 token")
	}
	return nil
}

func (p *Provider) identity(ctx context.Context, raw, nonce string) (idp.Identity, error) {
	claims, err := idp.VerifyJWT(ctx, raw, p.keys, p.rules(nonce))
	if err != nil {
		return idp.Identity{}, idp.TokenCheckError(err, "")
	}
	tid := strings.ToLower(idp.StringClaim(claims, "tid"))
	oid := strings.ToLower(idp.StringClaim(claims, "oid"))
	if !isGUID(oid) {
		return idp.Identity{}, &idp.Error{Class: idp.Fatal, Err: errors.New("entra: ID token oid is not a GUID")}
	}
	_, overage := claims["_claim_names"].(map[string]any)
	if b, _ := claims["hasgroups"].(bool); b {
		overage = true
	}
	return idp.Identity{
		Subject:           tid + ":" + oid,
		Issuer:            issuerFor(tid),
		Name:              idp.StringClaim(claims, "name"),
		Email:             idp.StringClaim(claims, "email"),
		PreferredUsername: idp.StringClaim(claims, "preferred_username"),
		Roles:             idp.StringsClaim(claims, "roles"),
		Groups:            idp.StringsClaim(claims, "groups"),
		GroupsUnavailable: overage,
		Claims:            claims,
	}, nil
}

// checkAccessToken makes sure the login returned our own v2 access_as_user token, the OBO
// assertion (ADR-0012 §4); otherwise the app registration is misconfigured.
func (p *Provider) checkAccessToken(ctx context.Context, raw string) error {
	hint := "expose the access_as_user scope on the app registration with requestedAccessTokenVersion 2"
	if raw == "" {
		return &idp.Error{Class: idp.Fatal, OperatorHint: hint, Err: errors.New("entra: no access token for access_as_user")}
	}
	claims, err := idp.VerifyJWT(ctx, raw, p.keys, p.rules(""))
	if err != nil {
		return idp.TokenCheckError(fmt.Errorf("entra: access token: %w", err), hint)
	}
	if !slices.Contains(strings.Fields(idp.StringClaim(claims, "scp")), "access_as_user") {
		return &idp.Error{Class: idp.Fatal, OperatorHint: hint, Err: errors.New("entra: access token lacks scp access_as_user")}
	}
	return nil
}

// UserKey returns the canonical user key ("tid:oid", both GUIDs in lower case, as sign-in stores
// it) for an operator-typed key, and whether s is one: the portal shows GUIDs in either case.
func UserKey(s string) (string, bool) {
	tid, oid, ok := strings.Cut(strings.ToLower(strings.TrimSpace(s)), ":")
	if !ok || !isGUID(tid) || !isGUID(oid) {
		return "", false
	}
	return tid + ":" + oid, true
}

func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", r):
			return false
		}
	}
	return true
}
