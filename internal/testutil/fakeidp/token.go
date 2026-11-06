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

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

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
	// Echo the correlation headers on success too.
	if p.profile == Entra {
		correlation(w, r)
	}
	c, method, f := p.authenticateClient(r, tenant)
	if f != nil {
		p.tokenError(w, r, *f)
		return
	}
	grant := r.PostForm.Get("grant_type")
	if f, ok := p.cfg.tokenFail[grant]; ok {
		p.tokenError(w, r, f)
		return
	}
	var resp map[string]any
	switch {
	case grant == GrantAuthorizationCode:
		resp, f = p.redeemCode(r.PostForm, c, method)
	case grant == GrantRefreshToken:
		resp, f = p.redeemRefresh(r.PostForm, c, method)
	case grant == GrantClientCredentials && p.profile == Entra:
		resp, f = p.clientCredentials(r.PostForm, c, method)
	case grant == GrantJWTBearer && p.profile == Entra:
		resp, f = p.onBehalfOf(r.PostForm, c, method)
	default:
		f = &UnsupportedGrantType
	}
	if f != nil {
		p.tokenError(w, r, *f)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// authenticateClient checks client_secret_basic, client_secret_post, private_key_jwt or a
// public client. Caller holds p.mu.
func (p *IdP) authenticateClient(r *http.Request, tenant string) (Client, string, *Failure) {
	form := r.PostForm
	id := form.Get("client_id")
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if hasBasic {
		// RFC 6749 §2.3.1: the credentials are form-urlencoded inside Basic.
		var err1, err2 error
		basicID, err1 = url.QueryUnescape(basicID)
		basicSecret, err2 = url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil || (id != "" && id != basicID) {
			return Client{}, "", &InvalidRequest
		}
		id = basicID
	}
	assertion := form.Get("client_assertion")
	methods := 0
	for _, used := range []bool{hasBasic, form.Has("client_secret"), assertion != ""} {
		if used {
			methods++
		}
	}
	if methods > 1 {
		f := InvalidRequest
		f.Description = "More than one client authentication method was used."
		return Client{}, "", &f
	}
	if id == "" && assertion != "" {
		if j, err := parseJWS(assertion); err == nil {
			id, _ = j.claims["sub"].(string)
		}
	}
	if id == "" {
		f := InvalidRequest
		f.Code, f.Description = 900144, "The request body must contain the following parameter: 'client_id'."
		return Client{}, "", &f
	}
	c, ok := p.cfg.clients[id]
	if !ok {
		return Client{}, "", &UnknownClient
	}
	switch {
	case assertion != "":
		if form.Get("client_assertion_type") != clientAssertionType {
			return Client{}, "", &InvalidRequest
		}
		if f := p.checkClientAssertion(c, assertion, tenant); f != nil {
			return Client{}, "", f
		}
		return c, "private_key_jwt", nil
	case hasBasic:
		if !secretMatches(c, basicSecret) {
			return Client{}, "", &InvalidClientSecret
		}
		return c, "client_secret_basic", nil
	case form.Has("client_secret"):
		if !secretMatches(c, form.Get("client_secret")) {
			return Client{}, "", &InvalidClientSecret
		}
		return c, "client_secret_post", nil
	case c.confidential():
		return Client{}, "", &MissingClientCredential
	}
	return c, "none", nil
}

func secretMatches(c Client, secret string) bool {
	for _, s := range c.Secrets {
		if subtle.ConstantTimeCompare([]byte(s), []byte(secret)) == 1 {
			return true
		}
	}
	return false
}

// checkClientAssertion validates a private_key_jwt assertion the way the real-tenant test saw
// Entra do it (ADR-0012): RS256 or PS256, a certificate found by x5t#S256 or x5t, `aud` = the v2
// token endpoint, `iss` = `sub` = the client ID.
func (p *IdP) checkClientAssertion(c Client, assertion, tenant string) *Failure {
	bad := func(desc string) *Failure {
		f := InvalidClientAssertion
		if desc != "" {
			f.Description = desc
		}
		return &f
	}
	j, err := parseJWS(assertion)
	if err != nil {
		return bad("Client assertion is not a valid JWT.")
	}
	var cert *Certificate
	switch s256, s1, kid := j.str("x5t#S256"), j.str("x5t"), j.str("kid"); {
	case s256 != "":
		cert = findCert(c, func(k *Certificate) string { return k.ThumbprintSHA256() }, s256)
	case s1 != "":
		cert = findCert(c, func(k *Certificate) string { return k.ThumbprintSHA1() }, s1)
	case p.profile == Generic && kid != "":
		cert = findCert(c, func(k *Certificate) string { return k.ThumbprintSHA256() }, kid)
	default:
		return &MissingThumbprint
	}
	if cert == nil {
		return bad("Client assertion contains an invalid signature. The key was not found.")
	}
	if err := j.verify(&cert.Key.PublicKey, "RS256", "PS256"); err != nil {
		return bad("")
	}
	now := p.cfg.clock()
	iss, _ := j.claims["iss"].(string)
	sub, _ := j.claims["sub"].(string)
	if iss != c.ID || sub != c.ID {
		return bad("Client assertion iss and sub must be the client ID.")
	}
	if !audContains(j.claims["aud"], p.assertionAudiences(tenant)...) {
		return bad("Client assertion audience is not the token endpoint.")
	}
	exp, ok := numericDate(j.claims["exp"])
	if !ok || !now.Before(exp) {
		return bad("Client assertion has expired.")
	}
	if nbf, ok := numericDate(j.claims["nbf"]); ok && now.Before(nbf) {
		return bad("Client assertion is not yet valid.")
	}
	return nil
}

// assertionAudiences are the token-endpoint URLs a client assertion may name: the fake's own and,
// for Entra, the one under the real authority. Caller holds p.mu.
func (p *IdP) assertionAudiences(tenant string) []string {
	if p.profile == Generic {
		return []string{p.TokenURL(""), p.issuerFor("")}
	}
	return []string{p.TokenURL(tenant), p.cfg.authority + "/" + tenant + "/oauth2/v2.0/token"}
}

func findCert(c Client, thumb func(*Certificate) string, want string) *Certificate {
	for _, k := range c.Certificates {
		if subtle.ConstantTimeCompare([]byte(thumb(k)), []byte(want)) == 1 {
			return k
		}
	}
	return nil
}

func audContains(aud any, want ...string) bool {
	switch v := aud.(type) {
	case string:
		return slices.Contains(want, v)
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && slices.Contains(want, s) {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

func (p *IdP) redeemCode(form url.Values, c Client, method string) (map[string]any, *Failure) {
	ac, ok := p.codes[form.Get("code")]
	now := p.cfg.clock()
	switch {
	case !ok || ac.clientID != c.ID:
		return nil, &InvalidCode
	case ac.used:
		return nil, &CodeRedeemed
	case !now.Before(ac.expires):
		return nil, &CodeExpired
	case form.Get("redirect_uri") != ac.redirectURI:
		f := RedirectMismatch
		f.Error = "invalid_grant"
		return nil, &f
	}
	verifier := form.Get("code_verifier")
	if ac.challenge != "" || verifier != "" {
		if verifier == "" || subtle.ConstantTimeCompare([]byte(s256(verifier)), []byte(ac.challenge)) != 1 {
			return nil, &PKCEMismatch
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
		return nil, &InvalidRefreshToken
	case g.revoked:
		return nil, &RefreshTokenRevoked
	case !now.Before(g.expires):
		return nil, &RefreshTokenExpired
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
		return nil, &MissingClientCredential
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
		return nil, &AppNotAssigned
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
		return nil, &MissingClientCredential
	}
	if form.Get("requested_token_use") != "on_behalf_of" {
		f := InvalidRequest
		f.Description = "requested_token_use must be on_behalf_of."
		return nil, &f
	}
	invalid := func(desc string) *Failure {
		f := InvalidAssertion
		if desc != "" {
			f.Description = desc
		}
		return &f
	}
	j, err := parseJWS(form.Get("assertion"))
	if err != nil {
		return nil, invalid("Assertion is not a valid JWT.")
	}
	key := p.keyByID(j.str("kid"))
	if key == nil || j.verify(&key.cert.Key.PublicKey, "RS256") != nil {
		return nil, invalid("")
	}
	aud, _ := j.claims["aud"].(string)
	if aud != c.ID {
		return nil, invalid("Assertion audience does not match the client app presenting the assertion.")
	}
	tid, _ := j.claims["tid"].(string)
	if iss, _ := j.claims["iss"].(string); iss != p.issuerFor(tid) {
		return nil, invalid("Assertion issuer is not valid.")
	}
	exp, ok := numericDate(j.claims["exp"])
	if !ok || !p.cfg.clock().Before(exp) {
		return nil, invalid("Assertion is not within its valid time range.")
	}
	if _, ok := j.claims["scp"].(string); !ok {
		return nil, invalid("The On-Behalf-Of flow only works for user principals.")
	}
	scopes := strings.Fields(form.Get("scope"))
	res, f := p.resolveResource(scopes)
	if f != nil {
		return nil, f
	}
	if res == nil {
		return nil, &InvalidScope
	}
	u := User{TenantID: tid}
	u.OID, _ = j.claims["oid"].(string)
	u.Name, _ = j.claims["name"].(string)
	u.PreferredUsername, _ = j.claims["preferred_username"].(string)
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

func (p *IdP) keyByID(kid string) *signingKey {
	for _, k := range p.keys {
		if k.kid == kid {
			return k
		}
	}
	return nil
}
