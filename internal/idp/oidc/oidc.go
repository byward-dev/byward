// Package oidc is the generic OIDC IdP adapter with presets (ADR-0011 §2): endpoints come from
// the configured issuer's discovery document, whose `issuer` must match exactly.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/idp"
)

// Config is the generic adapter's input, as plain values.
type Config struct {
	// Preset is a key of Presets ("" for plain OIDC).
	Preset   string
	Issuer   string
	ClientID string
	// ClientAuth authenticates the IdP app; nil means a public client (PKCE only).
	ClientAuth idp.ClientAuth
	// RedirectURL is our /callback/{idp} URL.
	RedirectURL string
	// Scopes are requested in addition to openid and the preset's scopes.
	Scopes []string
	// SubjectClaim is the user key claim; default `sub`.
	SubjectClaim string
	// HostedDomain, if set, is sent as the hd hint and requires the `hd` claim to equal it (Google
	// Workspace).
	HostedDomain string
	// AllowLoopbackHTTP accepts an http issuer on a loopback host, and http endpoints on loopback
	// for it: development mode only. Otherwise the issuer and every discovered endpoint are https.
	// Private addresses are fine either way: the IdP is the operator's, not client-supplied.
	AllowLoopbackHTTP bool
	// HTTPClient defaults to idp.NewHTTPClient.
	HTTPClient *http.Client
	Now        func() time.Time
}

// mutableClaims are claims a user can change; using one as the subject earns a warning.
var mutableClaims = []string{"email", "preferred_username", "upn", "name"}

// Provider is a generic OIDC adapter.
type Provider struct {
	cfg      Config
	preset   Preset
	fetch    *idp.Fetcher
	warnings []string

	mu   sync.Mutex
	meta *metadata
	keys *idp.KeySet
}

type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IssParameterSupported bool   `json:"authorization_response_iss_parameter_supported"`
}

var _ interface {
	idp.Authenticator
	idp.Refresher
	idp.Readiness
} = (*Provider)(nil)

// New validates cfg. Discovery is lazy: the first call that needs it (or Ready) fetches it.
func New(cfg Config) (*Provider, error) {
	preset, ok := Presets[cfg.Preset]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown preset %q", cfg.Preset)
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: issuer, client ID and redirect URL are required")
	}
	if err := checkURL(cfg.Issuer, cfg.Issuer, cfg.AllowLoopbackHTTP); err != nil {
		return nil, fmt.Errorf("oidc: issuer: %w", err)
	}
	if preset.CheckIssuer != nil {
		if err := preset.CheckIssuer(cfg.Issuer); err != nil {
			return nil, err
		}
	}
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = "sub"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p := &Provider{cfg: cfg, preset: preset, fetch: idp.NewFetcher(cfg.HTTPClient)}
	if slices.Contains(mutableClaims, cfg.SubjectClaim) {
		p.warnings = append(p.warnings, fmt.Sprintf("oidc: subject claim %q can be changed by users; prefer sub", cfg.SubjectClaim))
	}
	return p, nil
}

// Warnings are startup warnings for the operator log.
func (p *Provider) Warnings() []string { return p.warnings }

// Ready fetches discovery if needed and reports whether it succeeded.
func (p *Provider) Ready(ctx context.Context) error {
	_, err := p.discover(ctx)
	return err
}

func (p *Provider) discover(ctx context.Context) (*metadata, error) {
	p.mu.Lock()
	cached := p.meta
	p.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	// Fetched without the lock, so a slow IdP never queues logins behind one another's retries;
	// concurrent first calls may fetch twice, and the first stored result wins.
	var m metadata
	wellKnown := strings.TrimSuffix(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	if err := p.fetch.GetJSON(ctx, wellKnown, &m); err != nil {
		return nil, &idp.Error{Class: idp.Unavailable, Err: fmt.Errorf("oidc discovery: %w", err)}
	}
	if m.Issuer != p.cfg.Issuer {
		return nil, &idp.Error{Class: idp.Fatal, OperatorHint: "set the issuer exactly as the IdP's discovery document states it",
			Err: fmt.Errorf("oidc discovery: issuer %q does not match configured %q", m.Issuer, p.cfg.Issuer)}
	}
	for _, e := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if err := checkURL(e, p.cfg.Issuer, p.cfg.AllowLoopbackHTTP); err != nil {
			return nil, &idp.Error{Class: idp.Fatal, Err: fmt.Errorf("oidc discovery: endpoint: %w", err)}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meta == nil {
		p.meta = &m
		p.keys = idp.NewKeySet(p.fetch, m.JWKSURI, p.cfg.Now)
	}
	return p.meta, nil
}

// checkURL requires https, except, when allowed (development mode), http on a loopback host when
// the issuer itself is loopback http.
func checkURL(raw, issuer string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	iu, _ := url.Parse(issuer)
	if allowLoopbackHTTP && u.Scheme == "http" && iu != nil && iu.Scheme == "http" && loopback(u.Hostname()) && loopback(iu.Hostname()) {
		return nil
	}
	return fmt.Errorf("%q must use https", raw)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Scope is the scope parameter sent to the IdP, for the consent page's technical details.
func (p *Provider) Scope() string { return strings.Join(p.scopes(), " ") }

func (p *Provider) scopes() []string {
	s := append([]string{"openid"}, p.preset.Scopes...)
	for _, extra := range p.cfg.Scopes {
		if !slices.Contains(s, extra) {
			s = append(s, extra)
		}
	}
	return s
}

// AuthCodeURL builds the IdP login URL with PKCE S256, state and nonce.
func (p *Provider) AuthCodeURL(ctx context.Context, l idp.Login) (string, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	if l.State == "" || l.Nonce == "" || l.CodeVerifier == "" {
		return "", errors.New("oidc: state, nonce and code verifier are required")
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {strings.Join(p.scopes(), " ")},
		"state":                 {l.State},
		"nonce":                 {l.Nonce},
		"code_challenge":        {idp.CodeChallenge(l.CodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	for k, v := range p.preset.AuthParams {
		q[k] = v
	}
	if l.LoginHint != "" {
		q.Set("login_hint", l.LoginHint)
	}
	if p.cfg.HostedDomain != "" {
		// Google shows only that Workspace's accounts; the hd claim is still checked at the callback.
		q.Set("hd", p.cfg.HostedDomain)
	}
	switch {
	case l.Silent:
		// none must stand alone (OIDC Core §3.1.2.1), so it replaces the preset's prompt too: a
		// silent Google sign-in may then get no new refresh token, and its grant cannot refresh.
		q.Set("prompt", "none")
	case l.SelectAccount:
		// prompt is a space-separated list (OIDC Core §3.1.2.1): keep the preset's values.
		q.Set("prompt", strings.TrimSpace(q.Get("prompt")+" select_account"))
	}
	u, err := url.Parse(m.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	existing := u.Query()
	for k, v := range q {
		existing[k] = v
	}
	u.RawQuery = existing.Encode()
	return u.String(), nil
}

// Callback handles the IdP redirect: an error response, or a code to exchange.
func (p *Provider) Callback(ctx context.Context, query url.Values, l idp.Login) (idp.Identity, idp.Tokens, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	wantIss := ""
	if m.IssParameterSupported {
		wantIss = m.Issuer
	}
	cb, err := idp.ReadCallback(query, l, wantIss)
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, &idp.Error{Class: idp.Fatal, Err: err}
	}
	if cb.Error != "" {
		return idp.Identity{}, idp.Tokens{}, &idp.Error{Class: idp.GenericClass(0, cb.Error), OAuth: cb.Error, Alert: cb.Error == "invalid_client",
			Description: cb.ErrorDescription, UserMessage: "Sign-in at the identity provider did not complete."}
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.Code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {l.CodeVerifier},
	}
	tr, err := p.token(ctx, m, form)
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	if tr.IDToken == "" {
		return idp.Identity{}, idp.Tokens{}, &idp.Error{Class: idp.Fatal, Err: errors.New("oidc: token response has no ID token")}
	}
	id, err := p.identity(ctx, tr.IDToken, l.Nonce)
	if err != nil {
		return idp.Identity{}, idp.Tokens{}, err
	}
	return id, tr.Tokens(p.cfg.Now()), nil
}

// Refresh renews tokens. Tokens.RefreshToken is empty when the IdP kept the old one.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (*idp.Identity, idp.Tokens, error) {
	if refreshToken == "" {
		return nil, idp.Tokens{}, &idp.Error{Class: idp.SignInAgain, Err: errors.New("oidc: no refresh token")}
	}
	m, err := p.discover(ctx)
	if err != nil {
		return nil, idp.Tokens{}, err
	}
	tr, err := p.token(ctx, m, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
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
	return id, tr.Tokens(p.cfg.Now()), nil
}

func (p *Provider) token(ctx context.Context, m *metadata, form url.Values) (*idp.TokenResponse, error) {
	if p.cfg.ClientAuth != nil {
		if err := p.cfg.ClientAuth.Apply(form, p.cfg.ClientID, m.TokenEndpoint, p.cfg.Now()); err != nil {
			return nil, &idp.Error{Class: idp.Unavailable, Alert: true, Err: fmt.Errorf("%w: %w", idp.ErrCredential, err)}
		}
	} else {
		form.Set("client_id", p.cfg.ClientID)
	}
	tr, err := p.fetch.PostToken(ctx, m.TokenEndpoint, form, nil)
	if ie := (*idp.Error)(nil); errors.As(err, &ie) {
		return nil, err // the fetcher classed it (a success without tokens)
	} else if err != nil {
		return nil, &idp.Error{Class: idp.Unavailable, Err: err} // transport: try later
	}
	if !tr.OK() {
		class := idp.GenericClass(tr.Status, tr.Error)
		return nil, &idp.Error{Class: class, OAuth: tr.Error, Status: tr.Status, Description: tr.ErrorDescription,
			Alert: tr.Error == "invalid_client"}
	}
	return tr, nil
}

func (p *Provider) identity(ctx context.Context, raw, nonce string) (idp.Identity, error) {
	accepted := []string{p.cfg.Issuer}
	if p.preset.AlsoAcceptIssuer != nil {
		if alt := p.preset.AlsoAcceptIssuer(p.cfg.Issuer); alt != "" {
			accepted = append(accepted, alt)
		}
	}
	claims, err := idp.VerifyJWT(ctx, raw, p.keys, idp.TokenRules{
		Issuer: func(iss string, _ map[string]any) error {
			if !slices.Contains(accepted, iss) {
				return fmt.Errorf("oidc: ID token issuer %q is not %q", iss, p.cfg.Issuer)
			}
			return nil
		},
		ClientID: p.cfg.ClientID,
		Nonce:    nonce,
		Algs:     []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256},
		Now:      p.cfg.Now,
	})
	if err != nil {
		return idp.Identity{}, idp.TokenCheckError(err, "")
	}
	subject := idp.StringClaim(claims, p.cfg.SubjectClaim)
	if subject == "" {
		return idp.Identity{}, &idp.Error{Class: idp.Fatal, Err: fmt.Errorf("oidc: ID token has no %s claim", p.cfg.SubjectClaim)}
	}
	if p.cfg.HostedDomain != "" && idp.StringClaim(claims, "hd") != p.cfg.HostedDomain {
		return idp.Identity{}, &idp.Error{Class: idp.Fatal, UserMessage: "This account is not in the organisation this service is for.",
			Err: errors.New("oidc: hd claim does not match the configured hosted domain")}
	}
	return idp.Identity{
		Subject:           subject,
		Issuer:            p.cfg.Issuer,
		Name:              idp.StringClaim(claims, "name"),
		Email:             idp.StringClaim(claims, "email"),
		EmailVerified:     p.emailVerified(claims["email_verified"]),
		PreferredUsername: idp.StringClaim(claims, "preferred_username"),
		Roles:             idp.StringsClaim(claims, "roles"),
		Groups:            idp.StringsClaim(claims, "groups"),
		Claims:            claims,
	}, nil
}

func (p *Provider) emailVerified(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return p.preset.EmailVerifiedAsString && b == "true"
	}
	return false
}
