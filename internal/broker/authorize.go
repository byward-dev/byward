package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/ratelimit"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/token"
)

// metadataHandler serves RFC 8414 metadata, identical at both well-known paths (ADR-0013 §2).
func (b *Broker) metadataHandler() http.Handler {
	doc, err := json.Marshal(map[string]any{
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
		"client_id_metadata_document_supported":          false, // slice 2.1
	})
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
}

func (b *Broker) cookieName(idpState string) string {
	name := "mcpap_login_" + idpState[:16]
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
	client, err := b.cfg.Clients.Client(ctx, q.Get("client_id"))
	switch {
	case errors.Is(err, registration.ErrUnknownClient):
		b.page(w, r, http.StatusBadRequest, "This app is not registered with the proxy.", "Ask your operator to register the app, or check its client ID.")
		return
	case err != nil:
		b.serverError(w, r, err)
		return
	}
	redirect := q.Get("redirect_uri")
	if err := client.RedirectAllowed(redirect); err != nil {
		b.page(w, r, http.StatusBadRequest, "This app asked to return to an address the proxy does not allow.", err.Error())
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
	b.showConsent(w, r, client, l)
}

// startLogin sends the browser to the IdP for l, keeping l in the login cookie until the callback.
func (b *Broker) startLogin(w http.ResponseWriter, r *http.Request, l login, now time.Time) {
	ctx := r.Context()
	plain, err := json.Marshal(l)
	if err != nil {
		b.serverError(w, r, err)
		return
	}
	sealed, err := b.cfg.LoginBox.Seal(plain, now.Add(LoginLifetime))
	if err != nil {
		b.serverError(w, r, err)
		return
	}
	start := time.Now()
	target, err := b.cfg.IdP.AuthCodeURL(idp.WithRequestID(ctx, logging.RequestID(ctx)), idp.Login{State: l.IdPState, Nonce: l.Nonce, CodeVerifier: l.Verifier})
	b.cfg.ObserveIdP("authorize", idpOutcome(err), time.Since(start))
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

// maxState keeps the login cookie well under the browsers' 4 KB limit.
const maxState = 512

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
		b.page(w, r, http.StatusTooManyRequests, tooManyTitle, tooManyHint(retry))
		return
	}
	q := r.URL.Query()
	ctx := r.Context()
	st := q.Get("state")
	badState := func(title string) {
		b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.Login, Outcome: audit.Failure, Reason: "sign-in state missing, invalid or expired", IdP: b.cfg.IdPName})
		b.page(w, r, http.StatusBadRequest, title, "Start again from your app.")
	}
	if len(st) < 16 {
		badState("This sign-in link is not valid.")
		return
	}
	c, err := r.Cookie(b.cookieName(st))
	if err != nil {
		badState("This sign-in has expired or was started in another browser.")
		return
	}
	//nolint:gosec // G124: as above (ADR-0010 §10)
	http.SetCookie(w, &http.Cookie{Name: c.Name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: b.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
	plain, err := b.cfg.LoginBox.Open(c.Value)
	var l login
	if err != nil || json.Unmarshal(plain, &l) != nil || l.IdPState != st {
		badState("This sign-in has expired.")
		return
	}
	start := time.Now()
	id, toks, err := b.cfg.IdP.Callback(idp.WithRequestID(ctx, logging.RequestID(ctx)), q, idp.Login{State: l.IdPState, Nonce: l.Nonce, CodeVerifier: l.Verifier})
	b.cfg.ObserveIdP("callback", idpOutcome(err), time.Since(start))
	if err != nil {
		var ie *idp.Error
		if errors.As(err, &ie) && ie.OAuth == "access_denied" {
			b.cfg.Audit.Record(r, audit.Event{Name: audit.Login, Outcome: audit.Failure, Reason: "the user declined to sign in", ClientID: l.ClientID, IdP: b.cfg.IdPName})
			b.redirectError(w, r, l.RedirectURI, l.State, "access_denied", "the user declined to sign in")
			return
		}
		b.idpFailure(w, r, l.ClientID, err)
		return
	}
	if err := b.cfg.Gate.Allow(ctx, id); err != nil {
		var d Denial
		if !errors.As(err, &d) {
			b.serverError(w, r, err)
			return
		}
		// Every denial is audited (ADR-0015 §5): the rule and pseudonymous keys only, no email or name.
		b.cfg.Audit.Record(r, audit.Event{Name: audit.AccessDenied, Outcome: audit.Failure, Reason: d.DeniedRule(),
			ClientID: l.ClientID, UserKey: id.Subject, IdP: b.cfg.IdPName})
		// A browser page the MCP client never parses, so 403 is right here (ADR-0015 §2).
		b.page(w, r, http.StatusForbidden, "You don't have access to this server.", "Ask your operator for access.")
		return
	}
	now := b.cfg.Now()
	tokJSON, _ := json.Marshal(toks) //nolint:gosec // G117: marshalled only to be sealed in the IdP-token box below

	sealedTokens, err := b.cfg.IdPTokenBox.Seal(tokJSON, now.Add(GrantLifetime))
	if err != nil {
		b.serverError(w, r, err)
		return
	}
	g, err := b.cfg.Store.CreateGrant(ctx, store.Grant{ID: randomID(), ClientID: l.ClientID, Subject: id.Subject, Issuer: id.Issuer,
		// Short-lived until the code is redeemed (token.go extends it), so an abandoned login does
		// not leave a 30-day grant holding IdP tokens.
		Resource: b.cfg.Resource.String(), Scopes: l.Scopes, IdPTokens: []byte(sealedTokens), CreatedAt: now, ExpiresAt: now.Add(LoginLifetime)})
	if err != nil {
		b.serverError(w, r, err)
		return
	}
	if err := b.cfg.Store.PutCode(ctx, store.PendingCode{GrantID: g.ID, ClientID: l.ClientID, RedirectURI: l.RedirectURI,
		CodeChallenge: l.Challenge, Scopes: l.Scopes, ExpiresAt: now.Add(CodeLifetime)}); err != nil {
		b.serverError(w, r, err)
		return
	}
	code, err := b.cfg.Sealer.Seal(token.Code, token.Claims{GrantID: g.ID, Subject: id.Subject, IssuedAt: now, ExpiresAt: now.Add(CodeLifetime)})
	if err != nil {
		b.serverError(w, r, err)
		return
	}
	b.cfg.Audit.Record(r, audit.Event{Name: audit.Login, Outcome: audit.Success, ClientID: l.ClientID, UserKey: id.Subject, GrantID: g.ID, IdP: b.cfg.IdPName})
	v := url.Values{"code": {code}, "iss": {b.cfg.Issuer}}
	if l.State != "" {
		v.Set("state", l.State)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, withQuery(l.RedirectURI, v), http.StatusFound)
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

// idpFailure explains an IdP error on a page; the operator hint and the IdP's error code, trace ID
// and correlation ID go to the log (ADR-0021 §7), the failure to the audit stream.
func (b *Broker) idpFailure(w http.ResponseWriter, r *http.Request, clientID string, err error) {
	ctx := r.Context()
	var ie *idp.Error
	msg, hint := "Signing in failed.", "Try again; if it keeps failing, tell your operator the reference below."
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
	b.page(w, r, http.StatusBadGateway, msg, hint)
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
