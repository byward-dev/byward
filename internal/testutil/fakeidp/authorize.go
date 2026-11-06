package fakeidp

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type authCode struct {
	clientID    string
	redirectURI string
	scopes      []string
	nonce       string
	challenge   string
	user        User
	tenant      string // tenant the user signed into (Entra: always the user's tid)
	authTime    time.Time
	expires     time.Time
	used        bool
}

func (p *IdP) discovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.profile == Generic {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                         p.issuerFor(""),
			"authorization_endpoint":                         p.AuthorizeURL(""),
			"token_endpoint":                                 p.TokenURL(""),
			"jwks_uri":                                       p.JWKSURL(""),
			"response_types_supported":                       []string{"code"},
			"subject_types_supported":                        []string{"public"},
			"id_token_signing_alg_values_supported":          []string{"RS256"},
			"scopes_supported":                               []string{"openid", "profile", "email", "offline_access"},
			"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
			"grant_types_supported":                          []string{GrantAuthorizationCode, GrantRefreshToken},
			"code_challenge_methods_supported":               []string{"S256"},
			"claims_supported":                               []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "email", "email_verified", "groups", "hd"},
			"authorization_response_iss_parameter_supported": p.cfg.issParam,
		})
		return
	}
	tenant, ok := p.tenantSegment(w, r)
	if !ok {
		return
	}
	// Entra's discovery advertises no code_challenge_methods_supported, no RFC 9207 flag, no PAR
	// and no DPoP (ADR-0012), so neither does the fake.
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.discoveryIssuer(tenant),
		"authorization_endpoint":                p.AuthorizeURL(tenant),
		"token_endpoint":                        p.TokenURL(tenant),
		"jwks_uri":                              p.JWKSURL(tenant),
		"end_session_endpoint":                  p.endpointBase(tenant) + "/oauth2/v2.0/logout",
		"userinfo_endpoint":                     "https://graph.microsoft.com/oidc/userinfo",
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt", "client_secret_basic"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"response_types_supported":              []string{"code", "id_token", "code id_token", "id_token token"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nbf", "nonce", "oid", "tid", "ver", "name", "preferred_username", "email", "roles", "groups"},
		"request_uri_parameter_supported":       false,
		"http_logout_supported":                 true,
		"frontchannel_logout_supported":         true,
		"cloud_instance_name":                   "microsoftonline.com",
	})
}

func (p *IdP) jwks(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	issuer := ""
	if p.profile == Entra {
		tenant, ok := p.tenantSegment(w, r)
		if !ok {
			return
		}
		issuer = p.discoveryIssuer(tenant)
	}
	keys := make([]map[string]any, 0, len(p.keys))
	for _, k := range p.keys {
		keys = append(keys, k.jwk(issuer))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// tenantSegment validates the Entra tenant path segment. Caller holds p.mu.
func (p *IdP) tenantSegment(w http.ResponseWriter, r *http.Request) (string, bool) {
	t := r.PathValue("tenant")
	if isGUID(t) || t == "organizations" || t == "common" {
		return strings.ToLower(t), true
	}
	p.tokenError(w, r, Failure{Error: "invalid_tenant", Code: 90002, Description: "Tenant not found."})
	return "", false
}

func multiTenant(tenant string) bool { return tenant == "organizations" || tenant == "common" }

func (p *IdP) discoveryIssuer(tenant string) string {
	if multiTenant(tenant) {
		return p.issuerFor("{tenantid}")
	}
	return p.issuerFor(tenant)
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tenant := ""
	if p.profile == Entra {
		var ok bool
		if tenant, ok = p.tenantSegment(w, r); !ok {
			return
		}
	}
	q := r.URL.Query()
	c, ok := p.cfg.clients[q.Get("client_id")]
	if !ok {
		p.errorPage(w, r, UnknownClient)
		return
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(c.RedirectURIs, redirect) {
		p.errorPage(w, r, RedirectMismatch)
		return
	}
	// From here on the redirect URI is trusted, so errors go back to the client.
	state := q.Get("state")
	fail := func(f Failure, desc string) {
		if desc != "" {
			f.Description = desc
		}
		p.authorizeError(w, r, redirect, state, f)
	}
	if q.Get("response_type") != "code" {
		fail(Failure{Error: "unsupported_response_type"}, "The fake supports response_type=code only.")
		return
	}
	if m := q.Get("response_mode"); m != "" && m != "query" {
		fail(InvalidRequest, "The fake supports response_mode=query only.")
		return
	}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	switch {
	case challenge == "" && p.cfg.requirePKCE:
		fail(InvalidRequest, "Proof Key for Code Exchange is required.")
		return
	case challenge != "" && method != "S256":
		fail(InvalidRequest, "The fake supports code_challenge_method=S256 only.")
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	if _, f := p.resolveResource(scopes); f != nil {
		fail(*f, "")
		return
	}
	if p.cfg.authorizeFail != nil {
		fail(*p.cfg.authorizeFail, "")
		return
	}
	u := p.cfg.user
	if p.profile == Entra && !multiTenant(tenant) && !strings.EqualFold(tenant, u.TenantID) {
		fail(UserFromOtherTenant, "")
		return
	}
	now := p.cfg.clock()
	code := randomToken()
	p.codes[code] = &authCode{
		clientID:    c.ID,
		redirectURI: redirect,
		scopes:      scopes,
		nonce:       q.Get("nonce"),
		challenge:   challenge,
		user:        u,
		tenant:      u.TenantID,
		authTime:    now,
		expires:     now.Add(p.cfg.codeLifetime),
	}
	resp := url.Values{"code": {code}}
	if state != "" {
		resp.Set("state", state)
	}
	if p.profile == Entra {
		resp.Set("session_state", NewGUID())
	}
	if p.cfg.issParam {
		resp.Set("iss", p.issuerFor(u.TenantID))
	}
	http.Redirect(w, r, withQuery(redirect, resp), http.StatusFound) //nolint:gosec // G710: redirect is an exact-match registered URI
}
