package fakeidp

import (
	"net/http"
	"strings"
)

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
			"scopes_supported":                               oidcScopes,
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
		"scopes_supported":                      oidcScopes,
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
	if p.cfg.jwksDown {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
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
		if p.cfg.jwksEmpty {
			break
		}
		keys = append(keys, k.jwk(issuer))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// tenantSegment validates the Entra tenant path segment. Caller holds p.mu.
func (p *IdP) tenantSegment(w http.ResponseWriter, r *http.Request) (string, bool) {
	t := r.PathValue("tenant")
	known := !p.cfg.strictTenants || strings.EqualFold(t, p.cfg.tenantID)
	if (isGUID(t) && known) || t == "organizations" || t == "common" {
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
