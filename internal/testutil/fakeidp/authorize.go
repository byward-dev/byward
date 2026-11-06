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
	authTime    time.Time
	expires     time.Time
	used        bool
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
	if len(scopes) == 0 {
		f := InvalidRequest
		f.Code = 900144
		fail(f, "The request body must contain the following parameter: 'scope'.")
		return
	}
	if _, f := p.resolveResource(scopes); f != nil {
		fail(*f, "")
		return
	}
	if p.cfg.authorizeFail != nil {
		fail(*p.cfg.authorizeFail, "")
		return
	}
	if slices.Contains(strings.Fields(q.Get("prompt")), "none") { // fails closed: only WithSilentSession signs in
		switch p.cfg.silent {
		case "session":
		case "":
			fail(Failure{Error: "login_required"}, "The fake holds no session for prompt=none.")
			return
		default:
			fail(Failure{Error: p.cfg.silent}, "The fake was told to refuse prompt=none.")
			return
		}
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
