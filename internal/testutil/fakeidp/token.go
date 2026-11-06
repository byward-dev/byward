package fakeidp

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type refreshGrant struct {
	clientID string
	scopes   []string
	user     User
	authTime time.Time
	expires  time.Time
	revoked  bool
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tenant := ""
	if p.profile == Entra {
		var ok bool
		if tenant, ok = p.tenantSegment(w, r); !ok {
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		p.tokenError(w, r, InvalidRequest)
		return
	}
	p.correlation(w, r) // Entra echoes the correlation headers on success too.
	c, method, f := p.authenticateClient(r, tenant)
	if f != nil {
		p.tokenError(w, r, *f)
		return
	}
	grant := r.PostForm.Get("grant_type")
	if !p.supportsGrant(grant) {
		p.tokenError(w, r, UnsupportedGrantType)
		return
	}
	if f, ok := p.cfg.tokenFail[grant]; ok {
		p.tokenError(w, r, f)
		return
	}
	var resp map[string]any
	switch grant {
	case GrantAuthorizationCode:
		resp, f = p.redeemCode(r.PostForm, c, method)
	case GrantRefreshToken:
		resp, f = p.redeemRefresh(r.PostForm, c, method)
	case GrantClientCredentials:
		resp, f = p.clientCredentials(r.PostForm, c, method)
	case GrantJWTBearer:
		resp, f = p.onBehalfOf(r.PostForm, c, method)
	}
	if f != nil {
		p.tokenError(w, r, *f)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// supportsGrant reports whether the profile implements a grant type; injected failures never
// make an unsupported grant look supported.
func (p *IdP) supportsGrant(grant string) bool {
	switch grant {
	case GrantAuthorizationCode, GrantRefreshToken:
		return true
	case GrantClientCredentials, GrantJWTBearer:
		return p.profile == Entra
	}
	return false
}

func (p *IdP) redeemCode(form url.Values, c Client, method string) (map[string]any, *Failure) {
	ac, ok := p.codes[form.Get("code")]
	now := p.cfg.clock()
	switch {
	case !ok || ac.clientID != c.ID:
		return nil, failure(InvalidCode)
	case ac.used:
		return nil, failure(CodeRedeemed)
	case !now.Before(ac.expires):
		return nil, failure(CodeExpired)
	case form.Get("redirect_uri") != ac.redirectURI:
		f := RedirectMismatch
		f.Error = "invalid_grant"
		return nil, &f
	}
	verifier := form.Get("code_verifier")
	if ac.challenge != "" || verifier != "" {
		if verifier == "" || subtle.ConstantTimeCompare([]byte(s256(verifier)), []byte(ac.challenge)) != 1 {
			return nil, failure(PKCEMismatch)
		}
	}
	ac.used = true
	return p.issue(c, method, ac.user, ac.scopes, ac.nonce, ac.authTime, true)
}

func (p *IdP) redeemRefresh(form url.Values, c Client, method string) (map[string]any, *Failure) {
	rt := form.Get("refresh_token")
	g, ok := p.refresh[rt]
	now := p.cfg.clock()
	switch {
	case !ok || g.clientID != c.ID:
		return nil, failure(InvalidRefreshToken)
	case g.revoked:
		return nil, failure(RefreshTokenRevoked)
	case !now.Before(g.expires):
		return nil, failure(RefreshTokenExpired)
	}
	scopes := g.scopes
	if s := form.Get("scope"); s != "" {
		scopes = strings.Fields(s)
	}
	return p.issue(c, method, g.user, scopes, "", g.authTime, p.cfg.rotateRefresh)
}

// issue builds the token response for a user login or refresh. Caller holds p.mu.
func (p *IdP) issue(c Client, method string, u User, scopes []string, nonce string, authTime time.Time, newRefresh bool) (map[string]any, *Failure) {
	res, f := p.resolveResource(scopes)
	if f != nil {
		return nil, f
	}
	now := p.cfg.clock()
	resp := map[string]any{
		"token_type": "Bearer",
		"expires_in": int(p.cfg.tokenLifetime.Seconds()),
	}
	if p.profile == Entra {
		resp["ext_expires_in"] = int(p.cfg.tokenLifetime.Seconds())
	}
	// Requesting the app's own .default returns only an ID token (ADR-0012).
	ownDefault := res != nil && res.aud == c.ID && slices.Equal(res.perms, []string{".default"})
	switch {
	case p.profile == Generic:
		resp["access_token"] = p.genericAccessToken(c.ID, u, scopes, now)
		resp["scope"] = strings.Join(scopes, " ")
	case res != nil && !ownDefault:
		resp["access_token"] = p.userAccessToken(res, c.ID, method, u, now)
		resp["scope"] = res.scopeString()
	case res == nil:
		// Only OIDC scopes: Entra issues a Graph token for the sign-in itself.
		g := &resource{aud: GraphAppID, perms: []string{"User.Read"}}
		resp["access_token"] = p.userAccessToken(g, c.ID, method, u, now)
		resp["scope"] = g.scopeString()
	}
	if slices.Contains(scopes, "openid") {
		resp["id_token"] = p.idToken(c.ID, u, scopes, nonce, authTime, now)
	}
	if newRefresh && slices.Contains(scopes, "offline_access") {
		rt := randomToken()
		p.refresh[rt] = &refreshGrant{clientID: c.ID, scopes: scopes, user: u, authTime: authTime, expires: now.Add(p.cfg.refreshLifetime)}
		resp["refresh_token"] = rt
	}
	return resp, nil
}

func (p *IdP) clientCredentials(form url.Values, c Client, method string) (map[string]any, *Failure) {
	if method == "none" {
		return nil, failure(MissingClientCredential)
	}
	scopes := strings.Fields(form.Get("scope"))
	res, f := p.resolveResource(scopes)
	if f != nil {
		return nil, f
	}
	if res == nil || !slices.Equal(res.perms, []string{".default"}) || len(scopes) != 1 {
		f := InvalidScope
		f.Description = "The client credentials grant needs exactly one scope of the form <resource>/.default."
		return nil, &f
	}
	if res.app != nil && res.app.AssignmentRequired && len(c.AppRoles[res.aud]) == 0 {
		return nil, failure(AppNotAssigned)
	}
	return map[string]any{
		"token_type":     "Bearer",
		"expires_in":     int(p.cfg.tokenLifetime.Seconds()),
		"ext_expires_in": int(p.cfg.tokenLifetime.Seconds()),
		"access_token":   p.appToken(res, c, method, p.cfg.clock()),
	}, nil
}

// onBehalfOf exchanges a user's access token for c (the assertion) for a token to another
// resource (ADR-0017). Caller holds p.mu.
func (p *IdP) onBehalfOf(form url.Values, c Client, method string) (map[string]any, *Failure) {
	if method == "none" {
		return nil, failure(MissingClientCredential)
	}
	if form.Get("requested_token_use") != "on_behalf_of" {
		f := InvalidRequest
		f.Description = "requested_token_use must be on_behalf_of."
		return nil, &f
	}
	u, f := p.oboUser(form.Get("assertion"), c.ID)
	if f != nil {
		return nil, f
	}
	scopes := strings.Fields(form.Get("scope"))
	res, f := p.resolveResource(scopes)
	if f != nil {
		return nil, f
	}
	if res == nil {
		return nil, failure(InvalidScope)
	}
	now := p.cfg.clock()
	resp := map[string]any{
		"token_type":     "Bearer",
		"scope":          res.scopeString(),
		"expires_in":     int(p.cfg.tokenLifetime.Seconds()),
		"ext_expires_in": int(p.cfg.tokenLifetime.Seconds()),
		"access_token":   p.userAccessToken(res, c.ID, method, u, now),
	}
	if slices.Contains(scopes, "offline_access") {
		rt := randomToken()
		p.refresh[rt] = &refreshGrant{clientID: c.ID, scopes: scopes, user: u, authTime: now, expires: now.Add(p.cfg.refreshLifetime)}
		resp["refresh_token"] = rt
	}
	return resp, nil
}

// oboUser validates an On-Behalf-Of assertion: a delegated user token from this IdP for clientID.
// Caller holds p.mu.
func (p *IdP) oboUser(assertion, clientID string) (User, *Failure) {
	invalid := func(desc string) *Failure {
		f := InvalidAssertion
		if desc != "" {
			f.Description = desc
		}
		return &f
	}
	j, err := parseJWS(assertion)
	if err != nil {
		return User{}, invalid("Assertion is not a valid JWT.")
	}
	key := p.keyByID(j.str("kid"))
	if key == nil || j.verify(&key.cert.Key.PublicKey, "RS256") != nil {
		return User{}, invalid("")
	}
	aud, _ := j.claims["aud"].(string)
	if aud != clientID {
		return User{}, invalid("Assertion audience does not match the client app presenting the assertion.")
	}
	tid, _ := j.claims["tid"].(string)
	if iss, _ := j.claims["iss"].(string); iss != p.issuerFor(tid) {
		return User{}, invalid("Assertion issuer is not valid.")
	}
	exp, ok := numericDate(j.claims["exp"])
	if !ok || !p.cfg.clock().Before(exp) {
		return User{}, invalid("Assertion is not within its valid time range.")
	}
	if _, ok := j.claims["scp"].(string); !ok {
		return User{}, invalid("The On-Behalf-Of flow only works for user principals.")
	}
	u := User{TenantID: tid}
	u.OID, _ = j.claims["oid"].(string)
	u.Name, _ = j.claims["name"].(string)
	u.PreferredUsername, _ = j.claims["preferred_username"].(string)
	return u, nil
}
