package broker

import (
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/token"
)

// consentOutcomes records the consent metric's "trust outcome" pairs.
type consentOutcomes struct {
	mu   sync.Mutex
	seen []string
}

func (o *consentOutcomes) observe(trust, outcome string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, trust+" "+outcome)
}

func (o *consentOutcomes) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.seen)
}

// withRemember turns remembered consent on: a hint box, and the consent metric into counted.
func withRemember(t *testing.T, counted *consentOutcomes) func(*Config) {
	ring, _ := keyRing(t)
	return func(c *Config) {
		box, err := token.NewBox(ring, "consent-hint", c.Now)
		if err != nil {
			t.Fatal(err)
		}
		c.ConsentHintBox = box
		if counted != nil {
			c.ObserveConsent = counted.observe
		}
	}
}

// remember signs in through the consent page and returns the hint cookie the callback set (nil
// when it set none).
func (e *env) remember(t *testing.T, extra url.Values) *http.Cookie {
	t.Helper()
	c, cb := e.startLogin(t, extra)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("callback: %d %s", res.StatusCode, b)
	}
	return hintIn(e, res)
}

func hintIn(e *env, res *http.Response) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == e.b.hintCookie() {
			return c
		}
	}
	return nil
}

// authorizeWith sends an authorization request carrying the hint cookie.
func (e *env) authorizeWith(t *testing.T, extra url.Values, h *http.Cookie) *http.Response {
	t.Helper()
	var cookies []*http.Cookie
	if h != nil {
		cookies = []*http.Cookie{h}
	}
	return e.do(t, "GET", "/authorize?"+authorizeQuery(extra).Encode(), nil, cookies)
}

// skipped reports whether /authorize went straight to the IdP, without the page.
func skipped(res *http.Response) bool {
	return res.StatusCode == http.StatusSeeOther && strings.Contains(res.Header.Get("Location"), "/oauth2/v2.0/authorize")
}

// finish completes a login that /authorize sent straight to the IdP, returning the callback's answer.
func (e *env) finish(t *testing.T, res *http.Response) *http.Response {
	t.Helper()
	var login *http.Cookie
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "byw_login_") {
			login = c
		}
	}
	idpRes, err := e.fake.HTTPClient().Get(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	return e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{login})
}

// A static client is asked once: the page says so, and the next sign-in of the same user for the
// same request goes straight to the IdP and returns a code, audited as remembered consent.
func TestAStaticClientIsAskedOnceThenRemembered(t *testing.T) {
	counted := &consentOutcomes{}
	e := newEnv(t, withRemember(t, counted))
	if p := e.showConsent(t, nil); !strings.Contains(p.body, "remember your choice for this app for 30 days") {
		t.Fatalf("the page does not say the answer is remembered: %s", p.body)
	}
	h := e.remember(t, nil)
	if h == nil || !h.HttpOnly || !h.Secure || h.SameSite != http.SameSiteLaxMode || !strings.HasPrefix(h.Name, "__Host-") || h.MaxAge != int(ConsentLifetime.Seconds()) ||
		h.Path != "/" || h.Domain != "" {
		t.Fatalf("hint cookie %+v: want __Host-, HttpOnly, Secure, SameSite=Lax, Path=/, no Domain, 30 days", h)
	}
	e.now = e.now.Add(ConsentLifetime - 1)
	res := e.authorizeWith(t, nil, h)
	if !skipped(res) {
		t.Fatalf("second sign-in: %d to %q, want straight to the IdP", res.StatusCode, res.Header.Get("Location"))
	}
	back := e.finish(t, res)
	loc, _ := url.Parse(back.Header.Get("Location"))
	if back.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), clientCB) || !strings.HasPrefix(loc.Query().Get("code"), token.CodePrefix) {
		t.Fatalf("remembered sign-in: %d to %s", back.StatusCode, loc)
	}
	e.oneAuditEvent(t, "consent_remembered", map[string]any{"outcome": "success", "client_id": clientID, "client_trust": "verified",
		"user_key": "*", "grant_id": "*"})
	// A remembered sign-in renews nothing: the 30 days run from the Allow.
	if hintIn(e, back) != nil {
		t.Fatal("a remembered sign-in renewed the hint")
	}
	g, _ := e.st.Grant(context.Background(), e.st.ids[len(e.st.ids)-1])
	if c, err := e.st.Consent(context.Background(), store.ConsentKey{Issuer: g.Issuer, Subject: g.Subject, ClientID: clientID,
		Redirect: registration.RedirectKey(clientCB), Resource: resourceID}); err != nil || !c.ExpiresAt.Equal(t0.Add(ConsentDelay+ConsentLifetime)) {
		t.Fatalf("consent after a remembered sign-in: %+v %v, want it to expire 30 days after the Allow", c, err)
	}
	if got, want := counted.list(), []string{"verified shown", "verified shown", "verified granted", "verified remembered"}; !slices.Equal(got, want) {
		t.Fatalf("consent outcomes %v, want %v", got, want)
	}
}

// The page is shown again for anything the remembered consent does not cover, and whenever the
// hint or the registry cannot be trusted.
func TestTheConsentPageReturnsForWhatIsNotRemembered(t *testing.T) {
	sealHint := func(e *env, plain string) string {
		v, err := e.b.cfg.ConsentHintBox.Seal([]byte(plain), e.now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for name, tc := range map[string]struct {
		later  url.Values
		before func(e *env, h **http.Cookie) // changes the world between the two sign-ins
	}{
		"a wider scope":     {later: url.Values{"scope": {"mcp offline_access"}}},
		"another scope":     {later: url.Values{"scope": {"offline_access"}}},
		"another client":    {later: url.Values{"client_id": {otherClientID}}},
		"another redirect":  {later: url.Values{"redirect_uri": {webCB}}, before: func(e *env, _ **http.Cookie) { e.reg.reregister(clientID, webCB) }},
		"prompt=consent":    {later: url.Values{"prompt": {"login consent"}}},
		"after 30 days":     {before: func(e *env, _ **http.Cookie) { e.now = e.now.Add(ConsentLifetime) }},
		"trust withdrawn":   {before: func(e *env, _ **http.Cookie) { e.reg.demote(clientID) }},
		"the store is down": {before: func(e *env, _ **http.Cookie) { e.st.down.Store(true) }},
		"without the hint":  {before: func(_ *env, h **http.Cookie) { *h = nil }},
		"a tampered hint": {before: func(_ *env, h **http.Cookie) {
			v := []byte((*h).Value)
			v[len(v)/2] = map[bool]byte{true: 'B', false: 'A'}[v[len(v)/2] == 'A'] // always another character
			(*h).Value = string(v)                                                 //nolint:gosec // G124: a forged hint the test sends, not a cookie the proxy sets
		}},
		"a hint without its issuer": {before: func(e *env, h **http.Cookie) {
			(*h).Value = sealHint(e, `{"i":"","s":"`+user(e).Subject+`"}`) //nolint:gosec // G124: a forged hint the test sends, not a cookie the proxy sets
		}},
		"another proxy's hint for this user": {before: func(e *env, h **http.Cookie) {
			ring, _ := keyRing(t)
			other, _ := token.NewBox(ring, "consent-hint", e.cfg.Now)
			v, _ := other.Seal([]byte(`{"i":"`+user(e).Issuer+`","s":"`+user(e).Subject+`"}`), e.now.Add(time.Hour))
			(*h).Value = v //nolint:gosec // G124: a forged hint the test sends, not a cookie the proxy sets
		}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withRemember(t, nil))
			h := e.remember(t, nil)
			if tc.before != nil {
				tc.before(e, &h)
			}
			if res := e.authorizeWith(t, tc.later, h); res.StatusCode != http.StatusOK {
				t.Fatalf("authorize: %d to %q, want the consent page", res.StatusCode, res.Header.Get("Location"))
			}
		})
	}
}

// Domain CIMD hosts and DCR clients are asked every time (ASVS 5.0.0 10.7.1): no hint is set, the
// page does not promise to remember, nothing is stored, and a hint from another client does not
// carry over.
func TestAnUnverifiedClientIsAskedEveryTime(t *testing.T) {
	counted := &consentOutcomes{}
	e := newEnv(t, withRemember(t, counted))
	as := url.Values{"client_id": {unverifiedID}}
	if p := e.showConsent(t, as); strings.Contains(p.body, "remember your choice") {
		t.Fatal("the page for an unverified client promises to remember")
	}
	if h := e.remember(t, as); h != nil {
		t.Fatalf("a hint was set for an unverified client: %+v", h)
	}
	if got, want := counted.list(), []string{"not-verified shown", "not-verified shown", "not-verified granted"}; !slices.Equal(got, want) {
		t.Fatalf("consent outcomes %v, want %v (labelled with the client's trust)", got, want)
	}
	// Even with the hint a verified client left in the browser, the unverified client is asked.
	h := e.remember(t, nil)
	if res := e.authorizeWith(t, as, h); res.StatusCode != http.StatusOK {
		t.Fatalf("unverified client with a valid hint: %d, want the consent page", res.StatusCode)
	}
	g, _ := e.st.Grant(context.Background(), firstGrant(e.st))
	if _, err := e.st.Consent(context.Background(), store.ConsentKey{Issuer: g.Issuer, Subject: g.Subject, ClientID: unverifiedID,
		Redirect: registration.RedirectKey(clientCB), Resource: resourceID}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a consent was stored for an unverified client: %v", err)
	}
}

// A loopback client is remembered whatever port it listens on next time (Claude Code picks a new
// one every run; ADR-0009 §2).
func TestALoopbackClientIsRememberedOnAnyPort(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, url.Values{"client_id": {loopbackID}, "redirect_uri": {"http://127.0.0.1:53124/callback"}})
	if res := e.authorizeWith(t, url.Values{"client_id": {loopbackID}, "redirect_uri": {"http://127.0.0.1:61000/callback"}}, h); !skipped(res) {
		t.Fatalf("another loopback port: %d, want remembered", res.StatusCode)
	}
}

// Someone else signing in behind a stale hint gets no code: the page is shown for the request, the
// hint is cleared, and nothing is stored for them.
func TestADifferentUserBehindAStaleHintGetsThePageAndNoCode(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, nil)
	grants := len(e.st.ids)
	e.fake.Set(fakeidp.WithUser(fakeidp.User{OID: fakeidp.NewGUID(), Name: "Mallory"}))
	res := e.authorizeWith(t, nil, h)
	if !skipped(res) {
		t.Fatalf("authorize with the hint: %d, want straight to the IdP", res.StatusCode)
	}
	back := e.finish(t, res)
	body, _ := io.ReadAll(back.Body)
	if back.StatusCode != http.StatusOK || back.Header.Get("Location") != "" || !flowRE.Match(body) {
		t.Fatalf("callback for another user: %d to %q, want the consent page", back.StatusCode, back.Header.Get("Location"))
	}
	// A browser drops a __Host- cookie only for a deletion with the same Secure and Path.
	if c := hintIn(e, back); c == nil || c.MaxAge >= 0 || !c.Secure || c.Path != "/" || !c.HttpOnly {
		t.Fatalf("hint not cleared: %+v", c)
	}
	if len(e.st.ids) != grants {
		t.Fatal("a grant was created for the user behind a stale hint")
	}
	if rec := e.oneAuditEvent(t, "consent_remembered", map[string]any{"outcome": "failure", "reason": hintUserMismatch, "client_id": clientID, "user_key": "*"}); rec["client_trust"] != nil {
		t.Fatalf("a failure record carries client_trust: %v", rec)
	}

	// Allow on that page starts a new IdP sign-in (the first is spent) and gives Mallory a code.
	m := flowRE.FindSubmatch(body)
	var binding *http.Cookie
	for _, c := range back.Cookies() {
		if c.Name == e.b.bindingCookie() {
			binding = c
		}
	}
	e.now = e.now.Add(ConsentDelay)
	allow := e.answer(t, consentPage{flow: html.UnescapeString(string(m[1])), binding: binding}, "allow", nil)
	first, _ := url.Parse(res.Header.Get("Location"))
	second, _ := url.Parse(allow.Header.Get("Location"))
	if allow.StatusCode != http.StatusSeeOther || second.Query().Get("state") == "" || second.Query().Get("state") == first.Query().Get("state") {
		t.Fatalf("Allow after the mismatch: %d, IdP state %q (first %q), want a new sign-in", allow.StatusCode, second.Query().Get("state"), first.Query().Get("state"))
	}
	done := e.finish(t, allow)
	if loc, _ := url.Parse(done.Header.Get("Location")); done.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("Mallory's sign-in after Allow: %d to %s", done.StatusCode, loc)
	}
	if n := len(e.auditEvents(t, "consent_remembered")); n != 1 {
		t.Fatalf("%d consent_remembered records, want only the failure", n)
	}
	// The failure names who actually signed in, never the user the hint named.
	mallory, _ := e.st.Grant(context.Background(), e.st.ids[len(e.st.ids)-1])
	if got := e.auditEvents(t, "consent_remembered")[0]["user_key"]; got != mallory.Subject || got == user(e).Subject {
		t.Fatalf("mismatch record user_key = %v, want the signed-in user %s, not the hinted %s", got, mallory.Subject, user(e).Subject)
	}
}

// Revoking the grant (the client's /revoke) forgets the consent: the next sign-in asks again.
func TestRevokingTheGrantForgetsTheConsent(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, url.Values{"scope": {"mcp offline_access"}})
	// Redeem the remembered sign-in's code for tokens, then revoke them.
	res := e.authorizeWith(t, url.Values{"scope": {"mcp offline_access"}}, h)
	back := e.finish(t, res)
	loc, _ := url.Parse(back.Header.Get("Location"))
	tok, body := e.redeem(t, loc.Query().Get("code"), nil)
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("redeem: %d %v", tok.StatusCode, body)
	}
	if r := e.revokeToken(t, body["refresh_token"].(string), clientID); r.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", r.StatusCode)
	}
	if res := e.authorizeWith(t, url.Values{"scope": {"mcp offline_access"}}, h); res.StatusCode != http.StatusOK {
		t.Fatalf("authorize after /revoke: %d, want the consent page", res.StatusCode)
	}
}

// A consent expires 30 days after its Allow even while the hint stays fresh: another client's
// later Allow renewed the hint, not this client's consent.
func TestAConsentExpiresWhileTheHintIsStillFresh(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	e.remember(t, nil) // clientID, day 0
	first, err := e.st.Consent(context.Background(), store.ConsentKey{Issuer: user(e).Issuer, Subject: user(e).Subject, ClientID: clientID,
		Redirect: registration.RedirectKey(clientCB), Resource: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(10 * 24 * time.Hour)
	h := e.remember(t, url.Values{"client_id": {otherClientID}}) // day 10: the hint now lasts to day 40
	e.now = first.ExpiresAt.Add(-1)
	if res := e.authorizeWith(t, nil, h); !skipped(res) {
		t.Fatalf("authorize just before the first consent expires: %d, want remembered", res.StatusCode)
	}
	e.now = first.ExpiresAt
	if res := e.authorizeWith(t, nil, h); res.StatusCode != http.StatusOK {
		t.Fatalf("authorize as the first consent expires: %d, want the consent page", res.StatusCode)
	}
	if res := e.authorizeWith(t, url.Values{"client_id": {otherClientID}}, h); !skipped(res) {
		t.Fatalf("authorize for the client consented on day 10: %d, want remembered", res.StatusCode)
	}
}

// The callback checks again before trusting a remembered consent: an app removed, its redirect or
// trust withdrawn, or the consent forgotten (revoke-user) during the sign-in gets no code, and
// neither does a registry that cannot be read.
func TestARememberedSignInGetsNoCodeUnlessTheCallbackCanConfirmTheClientAndConsent(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(t *testing.T, e *env)
		status int
	}{
		"the client removed":     {func(_ *testing.T, e *env) { e.reg.remove(clientID) }, http.StatusBadRequest},
		"its redirect withdrawn": {func(_ *testing.T, e *env) { e.reg.reregister(clientID, webCB) }, http.StatusBadRequest},
		"its trust withdrawn":    {func(_ *testing.T, e *env) { e.reg.demote(clientID) }, http.StatusOK},
		"the store down":         {func(_ *testing.T, e *env) { e.st.down.Store(true) }, http.StatusOK},
		"the registry down":      {func(_ *testing.T, e *env) { e.reg.fail() }, http.StatusInternalServerError},
		"consent forgotten by revoke-user": {func(t *testing.T, e *env) {
			if err := e.st.RevokeSubject(context.Background(), user(e).Subject, e.now.Add(1), e.now); err != nil {
				t.Fatal(err)
			}
		}, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withRemember(t, nil))
			h := e.remember(t, nil)
			grants := len(e.st.ids)
			res := e.authorizeWith(t, nil, h)
			if !skipped(res) {
				t.Fatal("not remembered before the change")
			}
			tc.change(t, e)
			back := e.finish(t, res)
			if back.StatusCode != tc.status || back.Header.Get("Location") != "" || len(e.st.ids) != grants {
				t.Fatalf("callback: %d to %q, %d new grants; want %d, no redirect, no grant", back.StatusCode, back.Header.Get("Location"), len(e.st.ids)-grants, tc.status)
			}
			if rec := e.oneAuditEvent(t, "consent_remembered", map[string]any{"outcome": "failure", "reason": hintNotRemembered}); rec["client_trust"] != nil {
				t.Fatalf("a failure record carries client_trust: %v", rec)
			}
		})
	}
}

// Remembering that fails is not a failed sign-in: the code is issued, and no hint is set, so the
// user is simply asked next time.
func TestAFailureToRememberStillIssuesTheCode(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	e.st.rememberDown.Store(true)
	c, cb := e.startLogin(t, nil)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	if loc, _ := url.Parse(res.Header.Get("Location")); res.StatusCode != http.StatusFound || loc.Query().Get("code") == "" || hintIn(e, res) != nil {
		t.Fatalf("callback with remembering down: %d to %s, hint %v", res.StatusCode, loc, hintIn(e, res))
	}
}

// In development mode on loopback http the hint cookie drops the __Host- prefix and Secure, like
// the other cookies (ADR-0010 §10), and still works.
func TestAConsentIsRememberedOverPlainHTTPInDevelopmentMode(t *testing.T) {
	e := newEnv(t, withRemember(t, nil), func(c *Config) { c.SecureCookies = false })
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay)
	h := hintIn(e, e.finish(t, e.answer(t, p, "allow", nil)))
	if h == nil || !strings.HasPrefix(h.Name, "byw_hint_") || h.Secure {
		t.Fatalf("hint cookie %+v: want no prefix and not Secure", h)
	}
	if res := e.authorizeWith(t, nil, h); !skipped(res) {
		t.Fatalf("second sign-in in development mode: %d, want remembered", res.StatusCode)
	}
}

// Each answer on the page is counted with the client's trust level.
func TestConsentAnswersAreCounted(t *testing.T) {
	counted := &consentOutcomes{}
	e := newEnv(t, withRemember(t, counted))
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay)
	e.answer(t, p, "deny", nil)
	if got, want := counted.list(), []string{"verified shown", "verified denied"}; !slices.Equal(got, want) {
		t.Fatalf("consent outcomes %v, want %v", got, want)
	}
}

// user is the signed-in user of the first grant: the one a hint names.
func user(e *env) store.Grant {
	g, _ := e.st.Grant(context.Background(), firstGrant(e.st))
	return g
}

// What a remembered consent covers still skips the page: fewer scopes than approved, and prompt
// values other than consent (only prompt=consent forces the page; prompt=none is #126).
func TestARememberedConsentCoversLessAndOtherPrompts(t *testing.T) {
	for name, later := range map[string]url.Values{
		"a subset of the approved scopes": {"scope": {"mcp"}},
		"prompt=login":                    {"scope": {"mcp offline_access"}, "prompt": {"login"}},
		"prompt=select_account":           {"scope": {"mcp offline_access"}, "prompt": {"select_account"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withRemember(t, nil))
			h := e.remember(t, url.Values{"scope": {"mcp offline_access"}})
			res := e.authorizeWith(t, later, h)
			if !skipped(res) {
				t.Fatalf("authorize: %d, want remembered", res.StatusCode)
			}
			if back := e.finish(t, res); back.StatusCode != http.StatusFound || !strings.Contains(back.Header.Get("Location"), "code=") {
				t.Fatalf("callback: %d to %q, want a code", back.StatusCode, back.Header.Get("Location"))
			}
		})
	}
}
