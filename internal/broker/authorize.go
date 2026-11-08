package broker

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/token"
)

// metadataHandler serves RFC 8414 metadata, identical at both well-known paths (ADR-0013 §2).
func (b *Broker) metadataHandler() http.Handler {
	md := map[string]any{
		"issuer":                   b.cfg.Issuer,
		"authorization_endpoint":   b.cfg.Issuer + "/authorize",
		"token_endpoint":           b.tokenEndpoint(),
		"response_types_supported": []string{"code"},
		"response_modes_supported": []string{"query"},
		"grant_types_supported":    grantTypes,
		"revocation_endpoint":      b.cfg.Issuer + "/revoke",
		// ADR-0006 §7: like the token endpoint, secret methods are not advertised.
		"revocation_endpoint_auth_methods_supported":       []string{"none", "private_key_jwt"},
		"code_challenge_methods_supported":                 []string{"S256"},
		"token_endpoint_auth_methods_supported":            []string{"none", "private_key_jwt"}, // ADR-0008 §1: DCR clients are never offered a secret; configured static secrets still work
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "PS256", "ES256"},
		// offline_access: the TS SDK asks for refresh tokens only when it is listed (comment on #49).
		"scopes_supported": []string{b.cfg.Scope, "offline_access"},
		"authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported":          b.cfg.CIMD, // ADR-0008 §1
	}
	if b.cfg.Registrar != nil {
		md["registration_endpoint"] = b.cfg.Issuer + "/register" // ADR-0008 §1, RFC 7591
	}
	if b.cfg.JWKSURI != "" {
		// The identity assertion's keys only: proxy tokens are opaque byw_ strings, and the assertion
		// is typ at+jwt with the upstream as aud, so the keys verify nothing an MCP client holds.
		md["jwks_uri"] = b.cfg.JWKSURI
	}
	doc, err := json.Marshal(md)
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cors(w, r, "GET, HEAD, OPTIONS")
		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			_, _ = w.Write(doc)
		default:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// cors follows ADR-0013 §6 for discovery and OAuth endpoints: echo the Origin, no credentials.
func cors(w http.ResponseWriter, r *http.Request, methods string) {
	o := r.Header.Get("Origin")
	if o == "" {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", o)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", methods)
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Retry-After")
	h.Set("Access-Control-Max-Age", "3600")
}

// login is the sealed login-in-progress (ADR-0007 §3), kept in a cookie per IdP state.
type login struct {
	ClientID    string   `json:"c"`
	RedirectURI string   `json:"r"`
	State       string   `json:"s,omitempty"` // the MCP client's state
	Challenge   string   `json:"p"`
	Scopes      []string `json:"o"`
	IdPState    string   `json:"is"`
	Nonce       string   `json:"n"`
	Verifier    string   `json:"v"`
	// Hint is the user a remembered consent was assumed for, from the hint cookie; the callback
	// checks it against the user who signed in (ADR-0010 §3). Empty when the user answered the page.
	Hint *hint `json:"h,omitempty"`
	// Silent is a prompt=none sign-in: the IdP is asked with prompt=none too, and anything that
	// would need the user ends in an error at the redirect URI instead of a page (#126).
	Silent bool `json:"x,omitempty"`
}

func (b *Broker) cookieName(idpState string) string {
	name := "byw_login_" + idpState[:16]
	if b.cfg.SecureCookies {
		return "__Host-" + name
	}
	return name
}

// authorize handles the authorization request. A bad client or redirect URI gets an error page,
// never a redirect (ADR-0009 §6, ADR-0013 §4); every other error redirects with error, state and iss.
func (b *Broker) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	ctx := r.Context()
	if retry, limited := b.throttled(w, r, ratelimit.Authorize); limited {
		// RFC 6749 §4.1.2.1: with a client and redirect URI we trust, tell the MCP client at once;
		// otherwise there is nowhere safe to send it, so the user sees the page.
		if c, err := b.cfg.Clients.Client(ctx, q.Get("client_id")); err == nil && c.RedirectAllowed(q.Get("redirect_uri")) == nil {
			b.redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "temporarily_unavailable",
				"too many sign-in attempts from this network; retry after "+strconv.Itoa(retry)+" s")
			return
		}
		b.page(w, r, http.StatusTooManyRequests, tooManyTitle, tooManyHint(retry))
		return
	}
	// Never a redirect: the redirect URI is not verified yet (draft-ietf-oauth-client-id-metadata-document-03 §6.1).
	redirect := q.Get("redirect_uri")
	client, ok := b.loadClient(w, r, q.Get("client_id"), redirect)
	if !ok {
		return
	}
	fail := func(code, desc string) { b.redirectError(w, r, redirect, q.Get("state"), code, desc) }
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	case !validChallenge(q.Get("code_challenge")) || q.Get("code_challenge_method") != "S256":
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	case len(q.Get("state")) > maxState:
		fail("invalid_request", "state is longer than 512 bytes")
		return
	case !validState(q.Get("state")):
		fail("invalid_request", "state may only contain visible ASCII characters and spaces (RFC 6749 Appendix A.5)")
		return
	case len(q["prompt"]) > 1: // RFC 6749 §3.1: no parameter more than once; prompt=none&prompt=consent must not run silently
		fail("invalid_request", "prompt must be sent once")
		return
	case wantsSilent(q.Get("prompt")) && len(promptValues(q.Get("prompt"))) > 1:
		fail("invalid_request", "prompt=none cannot be combined with other prompt values (OIDC Core 1.0 §3.1.2.1)")
		return
	case q.Get("resource") != "" && q.Get("resource") != b.cfg.Resource.String():
		// A missing resource means ours (ADR-0005 §4).
		fail("invalid_target", "this server only issues tokens for "+b.cfg.Resource.String())
		return
	}
	scopes, ok := b.scopes(q.Get("scope"))
	if !ok {
		fail("invalid_scope", "supported scopes: "+b.cfg.Scope+" offline_access")
		return
	}
	l := login{ClientID: client.ID(), RedirectURI: redirect, State: q.Get("state"), Challenge: q.Get("code_challenge"),
		Scopes: scopes, IdPState: randomID() + randomID(), Nonce: randomID(), Verifier: randomID() + randomID()}
	// Refused now rather than lost later: a browser drops a cookie over 4 KB, which would surface
	// only at the callback as an expired sign-in.
	if _, err := encodeLogin(l); err != nil {
		fail("invalid_request", "the request is too large")
		return
	}
	if wantsSilent(q.Get("prompt")) {
		b.authorizeSilently(w, r, client, l)
		return
	}
	if b.skipConsent(r, client, &l) {
		b.startLogin(w, r, l, b.cfg.Now())
		return
	}
	b.showConsent(w, r, client, l)
}

// loadClient resolves a client and checks its redirect URI, answering with an error page (never a
// redirect) when either fails.
func (b *Broker) loadClient(w http.ResponseWriter, r *http.Request, clientID, redirect string) (registration.Client, bool) {
	ctx := r.Context()
	client, err := b.cfg.Clients.Client(ctx, clientID)
	if err != nil {
		b.clientLookupFailed(ctx, clientID, err)
	}
	switch {
	case errors.Is(err, registration.ErrUnknownClient):
		b.page(w, r, http.StatusBadRequest, "This app is not registered with the proxy.", "Ask your operator to register the app, or check its client ID.")
		return nil, false
	case errors.Is(err, registration.ErrUnavailable):
		b.page(w, r, http.StatusServiceUnavailable, "The proxy could not load this app's details.", "Try again in a minute.")
		return nil, false
	case err != nil:
		b.serverError(w, r, err)
		return nil, false
	}
	if err := client.RedirectAllowed(redirect); err != nil {
		b.page(w, r, http.StatusBadRequest, "This app asked to return to an address the proxy does not allow.", err.Error())
		return nil, false
	}
	return client, true
}

// startLogin sends the browser to the IdP for l, keeping l in the login cookie until the callback.
func (b *Broker) startLogin(w http.ResponseWriter, r *http.Request, l login, now time.Time) {
	ctx := r.Context()
	failed := func(err error) { // a page, or an OAuth answer for prompt=none (the redirect URI is validated)
		if !l.Silent {
			b.serverError(w, r, err)
			return
		}
		b.cfg.Log.ErrorContext(ctx, "broker error", "request_id", logging.RequestID(ctx), "error", err)
		b.refuseSilently(w, r, "", l, "server_error", "the proxy could not start the sign-in; try again")
	}
	plain, err := encodeLogin(l)
	if err != nil {
		failed(err)
		return
	}
	sealed, err := b.cfg.LoginBox.Seal(plain, now.Add(LoginLifetime))
	if err != nil {
		failed(err)
		return
	}
	start := time.Now()
	target, err := b.cfg.IdP.AuthCodeURL(idp.WithRequestID(ctx, logging.RequestID(ctx)), idp.Login{State: l.IdPState, Nonce: l.Nonce, CodeVerifier: l.Verifier, Silent: l.Silent})
	b.cfg.ObserveIdP("authorize", idpOutcome(err), time.Since(start))
	if err != nil && l.Silent { // the IdP is not ready (discovery or keys down)
		b.noteIdPFailure(r, l.ClientID, err)
		b.refuseSilently(w, r, "", l, "temporarily_unavailable", "the identity provider is not reachable; try again")
		return
	}
	if err != nil {
		b.idpFailure(w, r, l.ClientID, err)
		return
	}
	//nolint:gosec // G124: Secure is false only in development mode on loopback http (ADR-0010 §10)
	http.SetCookie(w, &http.Cookie{Name: b.cookieName(l.IdPState), Value: sealed, Path: "/", MaxAge: int(LoginLifetime.Seconds()),
		HttpOnly: true, Secure: b.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	// 303: the browser follows the consent form's answer with a GET.
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// The login cookie must stay under the browsers' 4096-byte limit for name, value and attributes.
// maxState bounds the client's state; maxLoginJSON bounds the encoded login, so the sealed, base64url
// cookie value (4/3 of it plus about 100 bytes of header and tag) stays near 3.6 KB.
const (
	maxState     = 512
	maxLoginJSON = 2600
)

// validState accepts RFC 6749's state syntax: VSCHAR, printable ASCII and space. Control
// characters would each grow to six bytes in the encoded login.
func validState(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var errLoginTooLarge = errors.New("broker: login too large for its cookie")

// encodeLogin encodes l for the login cookie, without HTML escaping (which would grow each <, >
// and & to six bytes), and refuses a login over maxLoginJSON.
func encodeLogin(l login) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		return nil, err
	}
	plain := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(plain) > maxLoginJSON {
		return nil, errLoginTooLarge
	}
	return plain, nil
}

// validChallenge accepts an S256 challenge: the base64url (no padding) of 32 bytes, 43 characters.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	return strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

// scopes returns the requested scopes, defaulting to the resource scope; unknown scopes fail.
func (b *Broker) scopes(raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return []string{b.cfg.Scope}, true
	}
	var out []string
	for _, s := range strings.Fields(raw) {
		if s != b.cfg.Scope && s != "offline_access" {
			return nil, false
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, true
}

// callback receives the IdP's redirect, creates the grant and its single-use code, and returns the
// user to the MCP client.
func (b *Broker) callback(w http.ResponseWriter, r *http.Request) {
	if retry, limited := b.throttled(w, r, ratelimit.Callback); limited {
		// A silent sign-in's sealed login names a validated redirect URI: answer there, never a page.
		// Its login is spent as at any other callback: the browser is told to drop it, so it cannot
		// finish this sign-in later.
		if l, c, badLogin := b.openLogin(r); badLogin == "" && l.Silent {
			err := b.spendLogin(r, l)
			if err != nil && !errors.Is(err, store.ErrConsumed) {
				b.cfg.Log.ErrorContext(r.Context(), "recording a used login failed", "request_id", logging.RequestID(r.Context()), "error", err)
			}
			if !errors.Is(err, store.ErrConsumed) { // a replay of a login already used gets the page
				b.expireLogin(w, c)
				b.refuseSilently(w, r, "", l, "temporarily_unavailable", "too many sign-in attempts from this network; retry after "+strconv.Itoa(retry)+" s")
				return
			}
		}
		b.page(w, r, http.StatusTooManyRequests, tooManyTitle, tooManyHint(retry))
		return
	}
	q := r.URL.Query()
	ctx := r.Context()
	if q.Has("admin_consent") && !q.Has("code") {
		b.adminConsent(w, r, q)
		return
	}
	l, c, badLogin := b.openLogin(r)
	if c != nil { // single use: spent whether or not it opens
		b.expireLogin(w, c)
	}
	spent := error(nil)
	if badLogin == "" {
		spent = b.spendLogin(r, l) // before the IdP: a login is used once, whatever the browser kept (#150)
	}
	if badLogin != "" || errors.Is(spent, store.ErrConsumed) {
		b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.Login, Outcome: audit.Failure, Reason: "sign-in state missing, invalid or expired", IdP: b.cfg.IdPName})
		b.page(w, r, http.StatusBadRequest, cmp.Or(badLogin, "This sign-in has expired."), "Start again from your app.")
		return
	}
	if spent != nil { // the store is down: no login goes on unrecorded
		if l.Silent {
			b.cfg.Log.ErrorContext(ctx, "recording a used login failed", "request_id", logging.RequestID(ctx), "error", spent)
			b.refuseSilently(w, r, "", l, "temporarily_unavailable", "the proxy could not record the sign-in; try again")
			return
		}
		b.serverError(w, r, spent)
		return
	}
	start := time.Now()
	id, toks, err := b.cfg.IdP.Callback(idp.WithRequestID(ctx, logging.RequestID(ctx)), q, idp.Login{State: l.IdPState, Nonce: l.Nonce, CodeVerifier: l.Verifier})
	b.cfg.ObserveIdP("callback", idpOutcome(err), time.Since(start))
	if err != nil {
		if l.Silent {
			b.refuseSilentIdPFailure(w, r, l, err)
			return
		}
		var ie *idp.Error
		if errors.As(err, &ie) && ie.OAuth == "access_denied" {
			b.cfg.Audit.Record(r, audit.Event{Name: audit.Login, Outcome: audit.Failure, Reason: "the user declined to sign in", ClientID: l.ClientID, IdP: b.cfg.IdPName})
			b.redirectError(w, r, l.RedirectURI, l.State, "access_denied", "the user declined to sign in")
			return
		}
		b.idpFailure(w, r, l.ClientID, err)
		return
	}
	// failed is a broker failure after the IdP: a page, or an OAuth answer for prompt=none.
	failed := func(err error) {
		if !l.Silent {
			b.serverError(w, r, err)
			return
		}
		b.cfg.Log.ErrorContext(ctx, "broker error", "request_id", logging.RequestID(ctx), "error", err)
		b.refuseSilently(w, r, "", l, "server_error", "the proxy could not finish the sign-in; try again")
	}
	if err := b.cfg.Gate.Allow(ctx, id); err != nil {
		var d Denial
		if !errors.As(err, &d) {
			failed(err)
			return
		}
		// Every denial is audited (ADR-0015 §5): the rule and pseudonymous keys only, no email or name.
		b.cfg.Audit.Record(r, audit.Event{Name: audit.AccessDenied, Outcome: audit.Failure, Reason: d.DeniedRule(),
			ClientID: l.ClientID, UserKey: id.Subject, IdP: b.cfg.IdPName})
		if l.Silent { // a silent sign-in's browser shows no page to anyone (ADR-0015 §2, clarified for #126); never name the rule
			b.redirectError(w, r, l.RedirectURI, l.State, "access_denied", "access denied by the operator's policy")
			return
		}
		// A browser page the MCP client never parses, so 403 is right here (ADR-0015 §2).
		b.page(w, r, http.StatusForbidden, "You don't have access to this server.", "Ask your operator for access.")
		return
	}
	grantScopes := b.grantScopes(ctx, l, toks)
	// A login that skipped the page holds only if the registry agrees for the user who signed in.
	var remembered registration.Client
	if l.Hint != nil {
		c, reason, lookupErr := b.confirmRemembered(ctx, l, id)
		if reason != "" {
			b.askAfterMismatch(w, r, l, id, reason, lookupErr)
			return
		}
		remembered = c
	}
	now := b.cfg.Now()
	sealedTokens, err := b.cfg.IdPTokenBox.Seal(marshalSecrets(toks, b.cfg.Assert.claimsOf(id)), now.Add(GrantLifetime))
	if err != nil {
		failed(err)
		return
	}
	g, err := b.cfg.Store.CreateGrant(ctx, store.Grant{ID: randomID(), ClientID: l.ClientID, Subject: id.Subject, Issuer: id.Issuer,
		// Short-lived until the code is redeemed (token.go extends it), so an abandoned login does
		// not leave a 30-day grant holding IdP tokens.
		Resource: b.cfg.Resource.String(), Scopes: grantScopes, IdPTokens: []byte(sealedTokens), CreatedAt: now, ExpiresAt: now.Add(LoginLifetime)})
	if err != nil {
		failed(err)
		return
	}
	if err := b.cfg.Store.PutCode(ctx, store.PendingCode{GrantID: g.ID, ClientID: l.ClientID, RedirectURI: l.RedirectURI,
		CodeChallenge: l.Challenge, Scopes: grantScopes, ExpiresAt: now.Add(CodeLifetime)}); err != nil {
		failed(err)
		return
	}
	code, err := b.cfg.Sealer.Seal(token.Code, token.Claims{GrantID: g.ID, Subject: id.Subject, IssuedAt: now, ExpiresAt: now.Add(CodeLifetime)})
	if err != nil {
		failed(err)
		return
	}
	b.cfg.Audit.Record(r, audit.Event{Name: audit.Login, Outcome: audit.Success, ClientID: l.ClientID, UserKey: id.Subject, GrantID: g.ID, IdP: b.cfg.IdPName})
	b.afterGrant(w, r, l, id, g.ID, remembered, now)
	v := url.Values{"code": {code}, "iss": {b.cfg.Issuer}}
	if l.State != "" {
		v.Set("state", l.State)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, withQuery(l.RedirectURI, v), http.StatusFound)
}

// openLogin returns the login the callback's state names, from its sealed cookie, and the cookie
// itself when present. badLogin is the page title saying why there is no login, "" when it opened. It
// is the callback's only check of a login, for the rate-limited path too.
func (b *Broker) openLogin(r *http.Request) (l login, c *http.Cookie, badLogin string) {
	st := r.URL.Query().Get("state")
	if len(st) < 16 {
		return login{}, nil, "This sign-in link is not valid."
	}
	c, err := r.Cookie(b.cookieName(st))
	if err != nil {
		return login{}, nil, "This sign-in has expired or was started in another browser."
	}
	plain, err := b.cfg.LoginBox.Open(c.Value)
	if err != nil || json.Unmarshal(plain, &l) != nil || l.IdPState != st {
		return login{}, c, "This sign-in has expired."
	}
	return l, c, ""
}

// spendLogin records l as used, so the server refuses it a second time (store.ErrConsumed) for as
// long as its sealed cookie could still open.
func (b *Broker) spendLogin(r *http.Request, l login) error {
	now := b.cfg.Now()
	return b.cfg.Store.SpendLogin(r.Context(), sha256.Sum256([]byte(l.IdPState)), now, now.Add(LoginLifetime))
}

// expireLogin deletes a login cookie, so the login it holds cannot be used again.
func (b *Broker) expireLogin(w http.ResponseWriter, c *http.Cookie) {
	//nolint:gosec // G124: Secure is false only in development mode on loopback http (ADR-0010 §10)
	http.SetCookie(w, &http.Cookie{Name: c.Name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: b.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
}

func withQuery(base string, v url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + v.Encode()
}

// redirectError sends an OAuth error to a validated redirect URI, with iss (RFC 9207).
func (b *Broker) redirectError(w http.ResponseWriter, r *http.Request, redirect, state, code, desc string) {
	v := url.Values{"error": {code}, "error_description": {desc}, "iss": {b.cfg.Issuer}}
	if state != "" {
		v.Set("state", state)
	}
	w.Header().Set("Cache-Control", "no-store")
	// redirect was checked with RedirectAllowed (ADR-0009) before any caller gets here.
	http.Redirect(w, r, withQuery(redirect, v), http.StatusFound) //nolint:gosec // G710: validated redirect URI
}

// noteIdPFailure logs and audits a failed IdP sign-in: the operator hint and the IdP's error code,
// trace ID and correlation ID go to the log, never to the user. It returns the user's message.
func (b *Broker) noteIdPFailure(r *http.Request, clientID string, err error) string {
	ctx := r.Context()
	var ie *idp.Error
	msg := "Signing in failed."
	reason := "the IdP sign-in failed"
	if errors.As(err, &ie) {
		if ie.UserMessage != "" {
			msg = ie.UserMessage
		}
		reason = "the IdP sign-in failed (" + ie.Class.String() + ")"
		attrs := []any{"request_id", logging.RequestID(ctx), "error", err, "reason", ie.OperatorHint}
		if ie.Code != 0 {
			attrs = append(attrs, "idp_error_code", ie.Code)
		}
		if ie.TraceID != "" {
			attrs = append(attrs, "trace_id", ie.TraceID)
		}
		if ie.CorrelationID != "" {
			attrs = append(attrs, "correlation_id", ie.CorrelationID)
		}
		b.cfg.Log.ErrorContext(ctx, "IdP sign-in failed", attrs...)
	} else {
		b.cfg.Log.ErrorContext(ctx, "IdP sign-in failed", "request_id", logging.RequestID(ctx), "error", err)
	}
	b.cfg.Audit.Record(r, audit.Event{Name: audit.Login, Outcome: audit.Failure, Reason: reason, ClientID: clientID, IdP: b.cfg.IdPName})
	return msg
}

// idpFailure explains an IdP error on a page; the operator hint and the IdP's error code, trace ID
// and correlation ID go to the log (ADR-0021 §7), the failure to the audit stream.
func (b *Broker) idpFailure(w http.ResponseWriter, r *http.Request, clientID string, err error) {
	msg := b.noteIdPFailure(r, clientID, err)
	b.page(w, r, http.StatusBadGateway, msg, "Try again; if it keeps failing, tell your operator the reference below.")
}

// idpOutcome classifies an IdP call for metrics: success, unavailable (try later) or rejected.
func idpOutcome(err error) string {
	var ie *idp.Error
	switch {
	case err == nil:
		return "success"
	case errors.As(err, &ie) && ie.Class == idp.Unavailable:
		return "unavailable"
	}
	return "rejected"
}

func (b *Broker) serverError(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	b.cfg.Log.ErrorContext(ctx, "broker error", "request_id", logging.RequestID(ctx), "error", err)
	b.page(w, r, http.StatusInternalServerError, "Something went wrong on the proxy.", "Try again; if it keeps failing, tell your operator the reference below.")
}

// Operator log messages for a CIMD client that was refused, and one whose metadata or keys could
// not be fetched for now.
const (
	metadataRefused     = "client metadata refused"
	metadataUnavailable = "client metadata unavailable"
)

// clientLookupFailed tells the operator why a Client ID Metadata Document client was refused; the
// client itself only sees invalid_client or the error page. Static client IDs are not logged.
func (b *Broker) clientLookupFailed(ctx context.Context, clientID string, err error) {
	if !registration.IsCIMDURL(clientID) {
		return
	}
	msg := metadataRefused
	if errors.Is(err, registration.ErrUnavailable) {
		msg = metadataUnavailable
	}
	b.cfg.Log.WarnContext(ctx, msg, "request_id", logging.RequestID(ctx), "error", err.Error())
}

// grantScopes are the scopes a new grant gets: those approved, less offline_access when the IdP
// returned no refresh token, since a proxy refresh token could then only revoke the grant at its
// first use. An IdP adapter that stops asking for refresh tokens shows up here, as a warning for a
// client that may refresh, not as hourly sign-ins. The approved scopes themselves stay as they are.
func (b *Broker) grantScopes(ctx context.Context, l login, toks idp.Tokens) []string {
	if !slices.Contains(l.Scopes, "offline_access") || toks.RefreshToken != "" {
		return l.Scopes
	}
	if c, err := b.cfg.Clients.Client(ctx, l.ClientID); err == nil && c.AllowsRefresh() {
		b.cfg.Log.WarnContext(ctx, "the IdP returned no refresh token, so this grant cannot refresh", "request_id", logging.RequestID(ctx),
			"idp", b.cfg.IdPName, "client_id", l.ClientID, "reason", "check that the IdP is asked for refresh tokens; see the IdP's how-to")
	}
	return slices.DeleteFunc(slices.Clone(l.Scopes), func(s string) bool { return s == "offline_access" })
}
