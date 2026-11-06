package broker

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// silentAnswer is where a prompt=none request ended: the error the client got at its redirect URI
// (or "" for a code), with the state and iss that came with it.
type silentAnswer struct {
	error, state, iss, code string
}

func answerOf(t *testing.T, res *http.Response) silentAnswer {
	t.Helper()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), clientCB) {
		t.Fatalf("%d to %q, want a redirect to the client %s", res.StatusCode, res.Header.Get("Location"), clientCB)
	}
	q := loc.Query()
	return silentAnswer{error: q.Get("error"), state: q.Get("state"), iss: q.Get("iss"), code: q.Get("code")}
}

// refused is the answer a refused prompt=none request must get: the error, with state and iss.
func refused(e *env, code string) silentAnswer {
	return silentAnswer{error: code, state: "client-state", iss: e.b.cfg.Issuer}
}

func silent(extra url.Values) url.Values {
	q := url.Values{"prompt": {"none"}}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

// prompt=none never shows the consent page: a request that cannot finish silently gets an OAuth
// error at its validated redirect URI, with state and iss, before anything goes to the IdP.
// Without a hint the user is unknown before the IdP, so it is login_required (ADR-0010 §1). A
// client asked every time gets consent_required before the hint is even read, so it learns
// nothing about it.
func TestPromptNoneThatCannotFinishSilentlyIsAnsweredWithoutAPage(t *testing.T) {
	asked := url.Values{"client_id": {unverifiedID}} // a client asked every time
	for _, tc := range []struct {
		name, want    string
		extra         url.Values
		hint          bool
		storedConsent bool // a consent remembered for the client while it was verified
		storeDown     bool
		idpDown       bool // the IdP is not ready when the silent sign-in starts
	}{
		{name: "a client asked every time is refused with consent_required", want: "consent_required", extra: asked, hint: true},
		{name: "a client asked every time without a hint is refused with consent_required, not login_required", want: "consent_required", extra: asked},
		{name: "a client no longer verified is refused with consent_required, whatever is remembered", want: "consent_required", extra: asked, hint: true, storedConsent: true},
		{name: "no hint cookie is refused with login_required", want: "login_required"},
		{name: "a hint without a consent covering the request is refused with consent_required", want: "consent_required", extra: url.Values{"scope": {"mcp offline_access"}}, hint: true},
		{name: "a store failure is answered with temporarily_unavailable", want: "temporarily_unavailable", hint: true, storeDown: true},
		{name: "an IdP that is not ready is answered with temporarily_unavailable", want: "temporarily_unavailable", hint: true, idpDown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust := "verified"
			switch {
			case tc.extra.Get("client_id") == unverifiedID:
				trust = "not-verified"
			case tc.idpDown: // refused while starting the IdP leg, where the client is not re-read
				trust = ""
			}
			counted := &consentOutcomes{}
			e := newEnv(t, withRemember(t, counted))
			var h *http.Cookie
			if tc.hint {
				h = e.remember(t, url.Values{"scope": {"mcp"}})
			}
			if tc.storedConsent {
				g := user(e)
				if err := e.st.RememberConsent(context.Background(), store.Consent{Key: store.ConsentKey{Issuer: g.Issuer, Subject: g.Subject,
					ClientID: unverifiedID, Redirect: registration.RedirectKey(clientCB), Resource: resourceID}, Scopes: []string{"mcp"},
					ApprovedAt: e.now, ExpiresAt: e.now.Add(ConsentLifetime)}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.idpDown { // after the interactive sign-in that set the hint
				e.b.cfg.IdP = &failOnceIdP{IdP: e.b.cfg.IdP}
			}
			e.st.down.Store(tc.storeDown)
			logins, before := len(e.auditEvents(t, "login")), counted.list()
			if got := answerOf(t, e.authorizeWith(t, silent(tc.extra), h)); got != refused(e, tc.want) {
				t.Fatalf("answer %+v, want error %s with state and iss", got, tc.want)
			}
			rec := e.oneAuditEvent(t, "consent_silent", map[string]any{"outcome": "failure", "reason": tc.want, "client_id": "*"})
			if got, _ := rec["client_trust"].(string); got != trust {
				t.Fatalf("client_trust = %q, want %q", got, trust)
			}
			if got := counted.list()[len(before):]; !slices.Equal(got, []string{trust + " silent_refused"}) {
				t.Fatalf("consent outcomes %v, want only %q", got, trust+" silent_refused")
			}
			if tc.idpDown { // the IdP failure is logged and audited as for an interactive sign-in
				if got := e.auditEvents(t, "login")[logins:]; len(got) != 1 || got[0]["outcome"] != "failure" {
					t.Fatalf("login records after the IdP failure: %v, want one failure", got)
				}
			}
		})
	}
}

// prompt=none goes with no other prompt value, in any order, and prompt is sent once (OIDC Core
// 1.0 §3.1.2.1; RFC 6749 §3.1, whatever the values), so a request carrying none with consent can
// never reach the page.
func TestPromptNoneWithAnotherValueIsAnInvalidRequest(t *testing.T) {
	for _, prompt := range [][]string{{"none consent"}, {"consent none"}, {"login none"}, {"none select_account"}, {"none", "consent"}, {"consent", "none"}, {"consent", "login"}} {
		t.Run(strings.Join(prompt, "&"), func(t *testing.T) {
			e := newEnv(t, withRemember(t, nil))
			if got := answerOf(t, e.authorizeWith(t, url.Values{"prompt": prompt}, nil)); got != refused(e, "invalid_request") {
				t.Fatalf("answer %+v, want invalid_request with state and iss", got)
			}
		})
	}
}

// On a remembered consent prompt=none signs in without any page: the IdP is asked with its own
// prompt=none, and an IdP session gives the client a code.
func TestPromptNoneOnARememberedConsentSignsInSilently(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, nil)
	e.fake.Set(fakeidp.WithSilentSession())
	res := e.authorizeWith(t, silent(nil), h)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if !skipped(res) || loc.Query().Get("prompt") != "none" {
		t.Fatalf("authorize: %d to %s, want the IdP with prompt=none", res.StatusCode, loc)
	}
	if got := answerOf(t, e.finish(t, res)); got.error != "" || got.code == "" {
		t.Fatalf("callback answer %+v, want a code", got)
	}
}

// When the IdP's own prompt=none needs the user, the client gets the IdP's answer as it is; any
// other IdP failure becomes server_error, or temporarily_unavailable when the IdP is unavailable.
// Nothing is issued, and nothing is a page. The fake answers login_required unless told otherwise
// (it fails closed).
func TestPromptNoneAnswersTheIdPsFailureAtTheRedirect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		idp     fakeidp.Option
		want    string
		audited bool // logged and audited as an IdP sign-in failure
	}{
		{"no IdP session passes login_required through", nil, "login_required", false},
		{"the IdP needing interaction passes interaction_required through", fakeidp.WithSilentError("interaction_required"), "interaction_required", false},
		{"the IdP needing an account choice passes account_selection_required through", fakeidp.WithSilentError("account_selection_required"), "account_selection_required", false},
		{"the IdP needing its own consent passes consent_required through", fakeidp.WithSilentError("consent_required"), "consent_required", false},
		{"the IdP refusing the user passes access_denied through", fakeidp.WithSilentError("access_denied"), "access_denied", false},
		{"the IdP being unavailable is temporarily_unavailable", fakeidp.WithSilentError("temporarily_unavailable"), "temporarily_unavailable", true},
		{"any other IdP error is server_error", fakeidp.WithSilentError("invalid_request"), "server_error", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counted := &consentOutcomes{}
			e := newEnv(t, withRemember(t, counted))
			h := e.remember(t, nil)
			if tc.idp != nil {
				e.fake.Set(tc.idp)
			}
			grants, before, logins := len(e.st.ids), counted.list(), len(e.auditEvents(t, "login"))
			if got := answerOf(t, e.finish(t, e.authorizeWith(t, silent(nil), h))); got != refused(e, tc.want) {
				t.Fatalf("answer %+v, want %s with state and iss", got, tc.want)
			}
			if got := e.auditEvents(t, "login")[logins:]; (len(got) == 1 && got[0]["outcome"] == "failure") != tc.audited || len(got) > 1 {
				t.Fatalf("login records %v, want an IdP failure audited: %v", got, tc.audited)
			}
			if len(e.st.ids) != grants {
				t.Fatal("a grant was created")
			}
			e.oneAuditEvent(t, "consent_silent", map[string]any{"outcome": "failure", "reason": tc.want, "client_id": clientID})
			if got := counted.list()[len(before):]; !slices.Equal(got, []string{" silent_refused"}) {
				t.Fatalf("consent outcomes %v, want only a silent refusal with no trust", got)
			}
		})
	}
}

// An interactive sign-in whose IdP answers interaction_required keeps the interactive handling
// (the IdP failure page); it is not a silent refusal.
func TestAnInteractiveSignInIsNeverRefusedSilently(t *testing.T) {
	counted := &consentOutcomes{}
	e := newEnv(t, withRemember(t, counted))
	e.fake.Set(fakeidp.FailAuthorize(&fakeidp.Failure{Error: "interaction_required"}))
	c, cb := e.startLogin(t, nil)
	if res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c}); res.StatusCode != http.StatusBadGateway {
		t.Fatalf("callback: %d, want the IdP failure page", res.StatusCode)
	}
	if n := len(e.auditEvents(t, "consent_silent")); n != 0 || slices.ContainsFunc(counted.list(), func(s string) bool { return strings.HasSuffix(s, "silent_refused") }) {
		t.Fatalf("an interactive sign-in was refused silently: %d consent_silent records, outcomes %v", n, counted.list())
	}
}

// After the IdP, a silent sign-in whose remembered consent no longer holds gets consent_required
// and no code, never the page: someone else signed in behind a stale hint, or the consent went
// between /authorize and the callback. The hint is cleared and the mismatch audited as for an
// interactive sign-in. A store or registry failure while checking is temporarily_unavailable and
// keeps the hint.
func TestPromptNoneWhoseConsentDoesNotHoldAfterTheIdPGetsNoCodeAndNoPage(t *testing.T) {
	for _, tc := range []struct {
		name, want, reason string
		between            func(t *testing.T, e *env) // after /authorize, before the callback
		hintCleared        bool
	}{
		{"another user behind a stale hint gets consent_required", "consent_required", hintUserMismatch, func(t *testing.T, e *env) {
			e.fake.Set(fakeidp.WithUser(fakeidp.User{OID: fakeidp.NewGUID(), Name: "Mallory"}))
		}, true},
		{"a consent forgotten in between gets consent_required", "consent_required", hintNotRemembered, func(t *testing.T, e *env) {
			if err := e.st.RevokeGrant(context.Background(), firstGrant(e.st), e.now); err != nil { // every revocation forgets
				t.Fatal(err)
			}
		}, true},
		{"a store failure while checking gets temporarily_unavailable", "temporarily_unavailable", hintNotRemembered, func(t *testing.T, e *env) {
			e.st.down.Store(true)
		}, false},
		{"a registry failure while checking gets temporarily_unavailable", "temporarily_unavailable", hintNotRemembered, func(t *testing.T, e *env) {
			e.reg.fail()
		}, false},
		{"a client removed in between gets consent_required", "consent_required", hintNotRemembered, func(t *testing.T, e *env) {
			e.reg.remove(clientID)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counted := &consentOutcomes{}
			e := newEnv(t, withRemember(t, counted))
			h := e.remember(t, nil)
			e.fake.Set(fakeidp.WithSilentSession())
			res := e.authorizeWith(t, silent(nil), h)
			tc.between(t, e)
			grants, before := len(e.st.ids), counted.list()
			back := e.finish(t, res)
			if got := answerOf(t, back); got != refused(e, tc.want) {
				t.Fatalf("answer %+v, want %s and no code", got, tc.want)
			}
			if c := hintIn(e, back); (c != nil && c.MaxAge < 0) != tc.hintCleared {
				t.Fatalf("hint cookie %+v, want cleared %v", c, tc.hintCleared)
			}
			if len(e.st.ids) != grants {
				t.Fatal("a grant was created")
			}
			e.oneAuditEvent(t, "consent_remembered", map[string]any{"outcome": "failure", "reason": tc.reason, "client_id": clientID, "user_key": "*"})
			e.oneAuditEvent(t, "consent_silent", map[string]any{"outcome": "failure", "reason": tc.want, "client_id": clientID})
			if got := counted.list()[len(before):]; !slices.Equal(got, []string{" silent_refused"}) {
				t.Fatalf("consent outcomes %v, want only a silent refusal with no trust", got)
			}
		})
	}
}

// A broker failure after the IdP is server_error at the redirect for a silent sign-in, not a page.
func TestPromptNoneWhoseSignInFailsAfterTheIdPIsAServerError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(e *env)
	}{
		{"the access gate cannot decide", func(e *env) { e.b.cfg.Gate = brokenGate{} }},
		{"the grant cannot be stored", func(e *env) { e.st.createDown.Store(true) }},
		{"the code cannot be stored", func(e *env) { e.st.putCodeDown.Store(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, withRemember(t, nil))
			h := e.remember(t, nil)
			e.fake.Set(fakeidp.WithSilentSession())
			res := e.authorizeWith(t, silent(nil), h)
			tc.breakIt(e) // after the interactive sign-in that set the hint
			if got := answerOf(t, e.finish(t, res)); got != refused(e, "server_error") {
				t.Fatalf("answer %+v, want server_error", got)
			}
		})
	}
}

// A silent sign-in whose callback is rate limited is answered at its redirect URI, which its sealed
// login names, not with the page.
func TestPromptNoneWhoseCallbackIsRateLimitedIsTemporarilyUnavailable(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, nil)
	e.fake.Set(fakeidp.WithSilentSession())
	res := e.authorizeWith(t, silent(nil), h)
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"callback": true}}
	if got := answerOf(t, e.finish(t, res)); got != refused(e, "temporarily_unavailable") {
		t.Fatalf("answer %+v, want temporarily_unavailable", got)
	}
}

// A user the access gate refuses gets access_denied at the redirect on a silent sign-in, audited
// as every denial is, and the description never names the rule, role or group that refused them
// (ADR-0015 §2, clarified for #126).
func TestPromptNoneForAUserTheGateRefusesIsAccessDeniedNamingNoRule(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, nil)
	e.b.cfg.Gate = roleGate{role: "mcp-admins"} // only now: from the start it would refuse the sign-in that set the hint
	e.fake.Set(fakeidp.WithSilentSession())
	back := e.finish(t, e.authorizeWith(t, silent(nil), h))
	if got := answerOf(t, back); got != refused(e, "access_denied") {
		t.Fatalf("answer %+v, want access_denied", got)
	}
	loc, _ := url.Parse(back.Header.Get("Location"))
	desc := strings.ToLower(loc.Query().Get("error_description"))
	for _, secret := range []string{"role", "mcp-admins", "group", "tenant", "domain"} {
		if strings.Contains(desc, secret) {
			t.Fatalf("error_description %q names %q", desc, secret)
		}
	}
	e.oneAuditEvent(t, "access_denied", map[string]any{"outcome": "failure", "reason": "role", "client_id": clientID})
	if n := len(e.auditEvents(t, "consent_silent")); n != 0 {
		t.Fatalf("%d consent_silent records; a denial is audited as access_denied only", n)
	}
}
