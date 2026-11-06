package broker

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/registration"
)

var tagRE = regexp.MustCompile(`<[^>]*>`)

// visibleText is the page's text as a reader sees it: tags stripped, entities decoded, spaces
// collapsed.
func visibleText(body string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tagRE.ReplaceAllString(body, " "))), " ")
}

// consentEvents names the audit event of each answer.
var consentEvents = map[string]string{"allow": "consent_granted", "deny": "consent_denied"}

// consentAudit is the one consent record named event, for clientID (verified).
func (e *env) consentAudit(t *testing.T, event, outcome string) {
	t.Helper()
	e.oneAuditEvent(t, event, map[string]any{"outcome": outcome, "client_id": clientID, "client_trust": "verified"})
}

func TestAuthorizeShowsTheConsentPageBeforeTheIdP(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	text := visibleText(p.body)
	for _, want := range []string{
		"Test app wants to use mcp.example.com as you",
		"Test app (Trusted by your operator)",
		"an app on this computer",
		"Only allow this if you just started connecting from an app on this computer.",
		"If you allow, you'll sign in with Microsoft Entra next.",
		"Requested permissions: mcp openid profile email offline_access",
		// Without operator wording the page claims the broadest access, never less.
		"It will be able to Use mcp.example.com as you, with everything you can do there.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("consent page lacks %q in %q", want, text)
		}
	}
	if strings.Contains(text, "Run by") {
		t.Error("the page names an operator although none is configured")
	}
	if !strings.Contains(p.body, StylesheetPath) {
		t.Error("consent page does not link the stylesheet")
	}
	// The reference on the page finds the request in the logs (ADR-0021 §2).
	if p.requestID == "" || !strings.Contains(text, "Reference: "+p.requestID) {
		t.Errorf("consent page does not show its request ID %q: %s", p.requestID, text)
	}
	e.consentAudit(t, "consent_shown", "success")
	e.oneAuditEvent(t, "consent_shown", map[string]any{"request_id": p.requestID})
	if len(e.idpOps) != 0 {
		t.Fatalf("IdP contacted before Allow: %v", e.idpOps)
	}
}

// The page states how long access lasts: the grant's lifetime with offline_access (refresh tokens),
// otherwise one access token's.
func TestConsentPageLifetimeFollowsWhatTheGrantWillLast(t *testing.T) {
	if AccessLifetime != time.Hour {
		t.Fatalf("AccessLifetime is %v: update lifetimeText's \"up to 1 hour\"", AccessLifetime)
	}
	for _, tc := range []struct {
		scope, want string
	}{
		{"mcp offline_access", "up to " + strconv.Itoa(int(GrantLifetime/(24*time.Hour))) + " days"},
		{"mcp", "up to 1 hour"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			text := visibleText(newEnv(t).showConsent(t, url.Values{"scope": {tc.scope}}).body)
			if !strings.Contains(text, tc.want+",") {
				t.Fatalf("consent page lacks %q: %s", tc.want, text)
			}
		})
	}
}

func TestConsentBindsThePageToTheBrowserWithAHostOnlyCookie(t *testing.T) {
	c := newEnv(t).showConsent(t, nil).binding
	// A browser drops a __Host- cookie that carries a Domain.
	if !strings.HasPrefix(c.Name, "__Host-mcpap_consent_") || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" ||
		c.Domain != "" || c.MaxAge != int(FlowLifetime.Seconds()) {
		t.Fatalf("binding cookie %+v: want __Host- prefix, HttpOnly, Secure, SameSite=Lax, Path=/, lasting the flow's lifetime", c)
	}
}

// Browsers send cookies regardless of port, so two proxies on one host must not accept each
// other's binding cookie.
func TestAProxyOnAnotherPortOfTheSameHostIgnoresThisOnesBindingCookie(t *testing.T) {
	a := newEnv(t)
	b := newEnv(t, func(c *Config) { c.Issuer, c.Origin = issuer+":8443", issuer+":8443" })
	fromA := a.showConsent(t, nil).binding
	res := b.do(t, "GET", "/authorize?"+authorizeQuery(nil).Encode(), nil, []*http.Cookie{fromA})
	body, _ := io.ReadAll(res.Body)
	got := res.Cookies()
	if len(got) != 1 || got[0].Name == fromA.Name {
		t.Fatalf("proxy on :8443 set %v; want its own binding cookie, not %s", got, fromA.Name)
	}
	b.now = b.now.Add(ConsentDelay)
	ans := b.answer(t, consentPage{flow: flowOf(t, string(body)), binding: fromA}, "allow", http.Header{"Origin": {issuer + ":8443"}})
	if title := pageTitle(t, ans); ans.StatusCode != http.StatusForbidden || title != "This consent page was opened in another browser." {
		t.Fatalf("answer with the other proxy's cookie: %d %q", ans.StatusCode, title)
	}
}

// Development mode on loopback http (ADR-0010 §10): Safari drops Secure cookies over http, so
// neither the binding nor the login cookie is Secure or __Host-.
func TestDevelopmentModeCookiesWorkOverLoopbackHTTP(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SecureCookies = false })
	p := e.showConsent(t, nil)
	if c := p.binding; !strings.HasPrefix(c.Name, "mcpap_consent_") || c.Secure {
		t.Fatalf("binding cookie %+v: want no prefix and not Secure", c)
	}
	e.now = e.now.Add(ConsentDelay)
	res := e.answer(t, p, "allow", nil)
	if got := res.Cookies(); res.StatusCode != http.StatusSeeOther || len(got) != 1 || !strings.HasPrefix(got[0].Name, "mcpap_login_") || got[0].Secure {
		t.Fatalf("allow: %d, cookies %+v", res.StatusCode, got)
	}
}

// Every HTML page the broker serves, consent or error, is locked down the same way and styled.
func TestBrokerPagesCannotRunScriptsBeFramedOrCachedAndAreStyled(t *testing.T) {
	for _, c := range []struct {
		name, query string
		status      int
	}{
		{"consent page", authorizeQuery(nil).Encode(), http.StatusOK},
		{"error page", authorizeQuery(url.Values{"client_id": {"nobody"}}).Encode(), http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := newEnv(t).do(t, "GET", "/authorize?"+c.query, nil, nil)
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != c.status || !strings.Contains(string(body), StylesheetPath) {
				t.Fatalf("%d, want %d with the stylesheet linked", res.StatusCode, c.status)
			}
			want := map[string]string{
				"Content-Security-Policy": "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'self'; img-src 'self'",
				"X-Frame-Options":         "DENY",
				"Cache-Control":           "no-store",
				"Referrer-Policy":         "same-origin", // no-referrer makes browsers post Origin: null
				"X-Content-Type-Options":  "nosniff",
			}
			for k, v := range want {
				if res.Header.Get(k) != v {
					t.Errorf("%s = %q, want %q", k, res.Header.Get(k), v)
				}
			}
		})
	}
}

func TestConsentPageKeepsItsLinkToTheOpeningApp(t *testing.T) {
	res := newEnv(t).do(t, "GET", "/authorize?"+authorizeQuery(nil).Encode(), nil, nil)
	if body, _ := io.ReadAll(res.Body); res.StatusCode != http.StatusOK || !flowRE.Match(body) {
		t.Fatalf("authorize did not show the consent page: %d", res.StatusCode)
	}
	if res.Header.Get("Cross-Origin-Opener-Policy") != "" {
		t.Error("COOP set: it would cut the page off from the app that opened it (ADR-0010 §6)")
	}
}

func TestAnHTTPSAppIsNamedByItsHostWithoutTheLoopbackWarning(t *testing.T) {
	text := visibleText(newEnv(t).showConsent(t, url.Values{"client_id": {webClientID}, "redirect_uri": {webCB}}).body)
	if !strings.Contains(text, "Returns to app.example.org") || strings.Contains(text, "Only allow this if") {
		t.Fatalf("https app page: %s", text)
	}
}

func TestTheReturnDestinationIsShownReadablyAndLoopbackIsFlagged(t *testing.T) {
	for _, c := range []struct {
		name, in, want string
		loopback       bool
	}{
		{"an https redirect names its host", "https://app.example.org/cb?x=1", "app.example.org", false},
		{"an IPv4 loopback redirect is an app on this computer", "http://127.0.0.1:43210/callback", "an app on this computer", true},
		{"an IPv6 loopback redirect is an app on this computer", "http://[::1]:1/cb", "an app on this computer", true},
		{"an unparseable redirect is shown as sent", "://bad", "://bad", false},
		{"a Unicode host is shown beside its punycode", "https://bücher.example/cb", "bücher.example (xn--bcher-kva.example)", false},
		{"a punycode host is shown beside its Unicode", "https://xn--bcher-kva.example/cb", "bücher.example (xn--bcher-kva.example)", false},
		{"a full-width dot shows the real host", "https://app.example.org\u3002evil.com/cb", "app.example.org\u3002evil.com (app.example.org.evil.com)", false},
		{"an empty punycode label names no host", "https://xn--.example/cb", "xn--.example", false},
		{"an invisible character alone shows the host once", "https://a\u00adb.example/cb", "ab.example", false},
		{"a zero-width joiner shows the real host", "https://a\u200db.com/cb", "ab.com (xn--ab-m1t.com)", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, loopback := returnsTo(c.in); got != c.want || loopback != c.loopback {
				t.Fatalf("returnsTo(%q) = %q, %v; want %q, %v", c.in, got, loopback, c.want, c.loopback)
			}
		})
	}
}

func TestConsentPageUsesOperatorWording(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.UpstreamName, c.ScopeText, c.OperatorName = "Team\u202e dashboards", "Read and query your team's dashboards.", "Contoso IT"
	})
	body := e.showConsent(t, nil).body
	if strings.Contains(body, "\u202e") {
		t.Error("a bidi override in the upstream name reached the page")
	}
	text := visibleText(body)
	for _, want := range []string{"Test app wants to use Team dashboards as you", "Read and query your team's dashboards.", "Run by Contoso IT."} {
		if !strings.Contains(text, want) {
			t.Errorf("consent page lacks %q in %q", want, text)
		}
	}
}

// The user must always see which upstream the app will act on.
func TestAnInvisibleUpstreamNameFallsBackToThePublicHost(t *testing.T) {
	text := visibleText(newEnv(t, func(c *Config) { c.UpstreamName = "\u200b\u202e " }).showConsent(t, nil).body)
	for _, want := range []string{"wants to use mcp.example.com as you", "Use mcp.example.com as you"} {
		if !strings.Contains(text, want) {
			t.Errorf("consent page lacks %q: %s", want, text)
		}
	}
}

func TestClientNamesAreSanitisedForDisplay(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"a plain name is shown unchanged", "Claude Code", "Claude Code"},
		{"control characters go", "Evil\x00\x1b[31m app", "Evil[31m app"},
		{"bidi overrides go", "abc\u202egnp.exe", "abcgnp.exe"},
		{"whitespace collapses", "  a \t\n b  ", "a b"},
		{"a name of only invisible characters falls back", "\u200b", "fallback"},
		{"an empty name falls back", "", "fallback"},
		{"80 characters at most", strings.Repeat("x", 100), strings.Repeat("x", 79) + "…"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := displayName(c.in, "fallback"); got != c.want {
				t.Fatalf("displayName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestAnUnverifiedAppShowsItsCleanedNameLabelledNotVerified(t *testing.T) {
	body := newEnv(t).showConsent(t, url.Values{"client_id": {unverifiedID}}).body
	if strings.ContainsAny(body, "\u202e\x1b") {
		t.Fatal("control or bidi characters from the client name reached the page")
	}
	if text := visibleText(body); !strings.Contains(text, "Free Tools[0m Helper (Not verified)") {
		t.Fatalf("unverified app page: %s", text)
	}
}

func TestEachTrustLevelHasAPlainLabelAndUnknownIsNotVerified(t *testing.T) {
	for level, want := range map[registration.TrustLevel]string{
		registration.Verified: "Trusted by your operator", registration.Domain: "Identified by its web address",
		registration.NotVerified: "Not verified", "": "Not verified",
	} {
		if got := trustLabel(level); got != want {
			t.Errorf("trustLabel(%q) = %q, want %q", level, got, want)
		}
	}
}

// Deny needs no delay: the clock is not advanced.
func TestDenyReturnsAccessDeniedToTheClientAtOnce(t *testing.T) {
	e := newEnv(t)
	res := e.answer(t, e.showConsent(t, nil), "deny", nil)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("deny: %d", res.StatusCode)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), clientCB+"?") || q.Get("error") != "access_denied" || q.Get("state") != "client-state" || q.Get("iss") != issuer {
		t.Fatalf("deny redirected to %s", loc)
	}
	if len(res.Cookies()) != 0 {
		t.Fatalf("deny set cookies: %v", res.Cookies())
	}
	e.consentAudit(t, "consent_denied", "failure")
	if len(e.idpOps) != 0 {
		t.Fatalf("IdP contacted on Deny: %v", e.idpOps)
	}
}

func TestAllowWithinTheDelayShowsThePageAgain(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay - time.Millisecond)
	res := e.answer(t, p, "allow", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(visibleText(string(body)), "Take a moment to check the details") || len(res.Cookies()) != 0 {
		t.Fatalf("early allow: %d, cookies %v, %s", res.StatusCode, res.Cookies(), body)
	}
	e.noAuditEvent(t, "consent_granted") // a postponed click is not a decision
	again := consentPage{flow: flowOf(t, string(body)), binding: p.binding}
	e.now = e.now.Add(time.Millisecond)
	if res := e.answer(t, again, "allow", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("allow from the page shown again, 1 s after the first showing: %d (the delay restarted?)", res.StatusCode)
	}
}

// A click that lands on Allow too early is not an answer: the user can still Deny.
func TestAnEarlyAllowDoesNotStopTheUserFromDenying(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay - time.Millisecond)
	body, _ := io.ReadAll(e.answer(t, p, "allow", nil).Body)
	again := consentPage{flow: flowOf(t, string(body)), binding: p.binding}
	res := e.answer(t, again, "deny", nil)
	if loc, _ := url.Parse(res.Header.Get("Location")); res.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("deny after an early allow: %d %s", res.StatusCode, loc)
	}
}

func TestAllowSendsTheUserToTheIdPAndAudits(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay)
	res := e.answer(t, p, "allow", nil)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("allow: %d, Cache-Control %q", res.StatusCode, res.Header.Get("Cache-Control"))
	}
	if loc, _ := url.Parse(res.Header.Get("Location")); loc.Host != "login.microsoftonline.com" {
		t.Fatalf("allow redirected to %s", loc)
	}
	e.consentAudit(t, "consent_granted", "success")
}

// failOnceIdP fails the first AuthCodeURL, as an IdP outage would.
type failOnceIdP struct {
	IdP
	mu     sync.Mutex
	failed bool
}

func (f *failOnceIdP) AuthCodeURL(ctx context.Context, l idp.Login) (string, error) {
	f.mu.Lock()
	first := !f.failed
	f.failed = true
	f.mu.Unlock()
	if first {
		return "", &idp.Error{UserMessage: "Microsoft Entra is not answering."}
	}
	return f.IdP.AuthCodeURL(ctx, l)
}

func TestAnIdPOutageAtAllowCanBeRetried(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.IdP = &failOnceIdP{IdP: c.IdP} })
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay)
	res := e.answer(t, p, "allow", nil)
	if title := pageTitle(t, res); res.StatusCode != http.StatusBadGateway || len(res.Cookies()) != 0 || title != "Microsoft Entra is not answering." {
		t.Fatalf("allow during the outage: %d %q, cookies %v", res.StatusCode, title, res.Cookies())
	}
	if res := e.answer(t, p, "allow", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("retried allow: %d", res.StatusCode)
	}
}

// A double click submits twice; the browser shows the second answer, so it must be the first one
// again (FastMCP #5774).
func TestRepeatedAnswerRepeatsTheResponse(t *testing.T) {
	for _, c := range []struct {
		action string
		status int
		lands  func(*url.URL) bool
	}{
		{"allow", http.StatusSeeOther, func(u *url.URL) bool { return u.Host == "login.microsoftonline.com" }},
		{"deny", http.StatusFound, func(u *url.URL) bool { return u.Query().Get("error") == "access_denied" }},
	} {
		t.Run(c.action, func(t *testing.T) {
			e := newEnv(t)
			p := e.showConsent(t, nil)
			e.now = e.now.Add(ConsentDelay)
			first, second := e.answer(t, p, c.action, nil), e.answer(t, p, c.action, nil)
			loc, _ := url.Parse(first.Header.Get("Location"))
			if first.StatusCode != c.status || !c.lands(loc) {
				t.Fatalf("first %s: %d %s", c.action, first.StatusCode, loc)
			}
			if second.StatusCode != first.StatusCode || second.Header.Get("Location") != first.Header.Get("Location") {
				t.Fatalf("second %s: %d %s, first %d %s", c.action, second.StatusCode, second.Header.Get("Location"), first.StatusCode, loc)
			}
			// One decision, one audit record.
			e.oneAuditEvent(t, consentEvents[c.action], nil)
		})
	}
}

func TestAChangedAnswerIsRefused(t *testing.T) {
	for _, c := range []struct {
		name, first, then string
		status            int
		delay             time.Duration
	}{
		{"deny then allow", "deny", "allow", http.StatusFound, ConsentDelay},
		{"allow then deny", "allow", "deny", http.StatusSeeOther, ConsentDelay},
		// Refused outright, not shown again for the delay.
		{"deny then allow at once", "deny", "allow", http.StatusFound, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			p := e.showConsent(t, nil)
			e.now = e.now.Add(c.delay)
			if res := e.answer(t, p, c.first, nil); res.StatusCode != c.status {
				t.Fatalf("first answer: %d, want %d", res.StatusCode, c.status)
			}
			res := e.answer(t, p, c.then, nil)
			if title := pageTitle(t, res); res.StatusCode != http.StatusConflict || title != "You already answered this request." {
				t.Fatalf("changed answer: %d %q", res.StatusCode, title)
			}
			e.oneAuditEvent(t, consentEvents[c.first], nil)
			e.noAuditEvent(t, consentEvents[c.then])
		})
	}
}

// tamperFlow changes one character in the middle of the sealed flow, so it always differs.
func tamperFlow(f string) string {
	i := len(f) / 2
	c := byte('A')
	if f[i] == 'A' {
		c = 'B'
	}
	return f[:i] + string(c) + f[i+1:]
}

func TestConsentRefusesAnAnswerFromOutsideItsPage(t *testing.T) {
	for _, c := range []struct {
		name    string
		headers http.Header
	}{
		{"no Origin", http.Header{"Origin": {""}}},
		{"null Origin", http.Header{"Origin": {"null"}}},
		{"another Origin", http.Header{"Origin": {"https://evil.example"}}},
		{"two Origins, ours first", http.Header{"Origin": {issuer, "https://evil.example"}}},
		{"our host on another port", http.Header{"Origin": {issuer + ":8443"}}},
		{"cross-site fetch", http.Header{"Sec-Fetch-Site": {"cross-site"}}},
		{"same-site fetch", http.Header{"Sec-Fetch-Site": {"same-site"}}},
		{"no Sec-Fetch-Site and another Origin", http.Header{"Sec-Fetch-Site": {""}, "Origin": {"https://evil.example"}}},
	} {
		for _, action := range []string{"allow", "deny"} {
			t.Run(c.name+"/"+action, func(t *testing.T) {
				e := newEnv(t)
				p := e.showConsent(t, nil)
				e.now = e.now.Add(ConsentDelay)
				res := e.answer(t, p, action, c.headers)
				if title := pageTitle(t, res); res.StatusCode != http.StatusForbidden || len(res.Cookies()) != 0 ||
					res.Header.Get("Location") != "" || title != "This answer did not come from the proxy's consent page." {
					t.Fatalf("%d %q, cookies %v", res.StatusCode, title, res.Cookies())
				}
				e.noAuditEvent(t, consentEvents[action])
			})
		}
	}
}

func TestConsentRefusesAnAnswerWhoseBrowserFlowOrClientChanged(t *testing.T) {
	for _, c := range []struct {
		name   string
		edit   func(e *env, p *consentPage)
		status int
		title  string
	}{
		{"no binding cookie", func(_ *env, p *consentPage) { p.binding = nil }, http.StatusForbidden,
			"This consent page was opened in another browser."},
		{"another browser's binding cookie", func(_ *env, p *consentPage) { p.binding = testCookie(p.binding.Name, strings.Repeat("0", 32)) },
			http.StatusForbidden, "This consent page was opened in another browser."},
		{"tampered flow", func(_ *env, p *consentPage) { p.flow = tamperFlow(p.flow) }, http.StatusBadRequest, "This consent page has expired."},
		{"expired flow", func(e *env, _ *consentPage) { e.now = e.now.Add(FlowLifetime) }, http.StatusBadRequest, "This consent page has expired."},
		{"client removed since the page was shown", func(e *env, _ *consentPage) { e.reg.remove(clientID) },
			http.StatusBadRequest, "This app is not registered with the proxy."},
		{"redirect URI no longer registered", func(e *env, _ *consentPage) { e.reg.reregister(clientID, "http://127.0.0.1:1/other") },
			http.StatusBadRequest, "This app asked to return to an address the proxy does not allow."},
	} {
		for _, action := range []string{"allow", "deny"} {
			t.Run(c.name+"/"+action, func(t *testing.T) {
				e := newEnv(t)
				p := e.showConsent(t, nil)
				e.now = e.now.Add(ConsentDelay)
				c.edit(e, &p)
				res := e.answer(t, p, action, nil)
				if title := pageTitle(t, res); res.StatusCode != c.status || len(res.Cookies()) != 0 || res.Header.Get("Location") != "" || title != c.title {
					t.Fatalf("%d %q, cookies %v; want %d %q", res.StatusCode, title, res.Cookies(), c.status, c.title)
				}
				e.noAuditEvent(t, consentEvents[action])
			})
		}
	}
}

// A registry outage is the proxy's fault, not an unregistered app.
func TestARegistryOutageIsAServerError(t *testing.T) {
	t.Run("at authorize", func(t *testing.T) {
		e := newEnv(t)
		e.reg.fail()
		res := e.do(t, "GET", "/authorize?"+authorizeQuery(nil).Encode(), nil, nil)
		if title := pageTitle(t, res); res.StatusCode != http.StatusInternalServerError || res.Header.Get("Location") != "" ||
			title != "Something went wrong on the proxy." {
			t.Fatalf("%d %q, Location %q", res.StatusCode, title, res.Header.Get("Location"))
		}
		if !strings.Contains(e.logs.String(), "broker error") {
			t.Errorf("no broker error logged: %s", e.logs)
		}
	})
	t.Run("at consent", func(t *testing.T) {
		e := newEnv(t)
		p := e.showConsent(t, nil)
		e.now = e.now.Add(ConsentDelay)
		e.reg.fail()
		res := e.answer(t, p, "allow", nil)
		if title := pageTitle(t, res); res.StatusCode != http.StatusInternalServerError || len(res.Cookies()) != 0 || title != "Something went wrong on the proxy." {
			t.Fatalf("%d %q", res.StatusCode, title)
		}
	})
}

func fillAnswers(a *answers, now time.Time) {
	for i := range maxFlows {
		a.record("filler-"+strconv.Itoa(i), true, now, now.Add(time.Minute))
	}
}

func TestABrowserWithoutFetchMetadataCanStillAllow(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay)
	if res := e.answer(t, p, "allow", http.Header{"Sec-Fetch-Site": {""}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("allow from a browser without Fetch Metadata: %d", res.StatusCode)
	}
}

func TestConsentRejectsAnUnreadableAnswer(t *testing.T) {
	for _, c := range []struct {
		name, action string
		edit         func(*consentPage)
	}{
		{"unknown action", "maybe", nil},
		{"body over 16 KiB", "allow", func(p *consentPage) { p.flow += strings.Repeat("A", 16<<10) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			p := e.showConsent(t, nil)
			if c.edit != nil {
				c.edit(&p)
			}
			res := e.answer(t, p, c.action, nil)
			if title := pageTitle(t, res); res.StatusCode != http.StatusBadRequest || title != "This answer could not be read." {
				t.Fatalf("%d %q", res.StatusCode, title)
			}
		})
	}
}

func TestConsentAcceptsOnlyPOST(t *testing.T) {
	res := newEnv(t).do(t, "GET", "/consent", nil, nil)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "POST" {
		t.Fatalf("GET /consent: %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
}

func TestTwoConsentPagesInOneBrowserCanEachBeAllowedSeparately(t *testing.T) {
	e := newEnv(t)
	first := e.showConsent(t, nil)
	res := e.do(t, "GET", "/authorize?"+authorizeQuery(nil).Encode(), nil, []*http.Cookie{first.binding})
	body, _ := io.ReadAll(res.Body)
	// The browser holds whatever cookie the proxy last set; both pages must work with it.
	held := first.binding
	if got := res.Cookies(); len(got) == 1 {
		held = got[0]
	}
	first.binding = held
	second := consentPage{flow: flowOf(t, string(body)), binding: held}
	if second.flow == first.flow {
		t.Fatal("the second page reused the first flow")
	}
	e.now = e.now.Add(ConsentDelay)
	var targets []string
	for _, p := range []consentPage{first, second} {
		res := e.answer(t, p, "allow", nil)
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("allow: %d", res.StatusCode)
		}
		targets = append(targets, res.Header.Get("Location"))
	}
	if targets[0] == targets[1] {
		t.Fatal("two parallel flows sent the same IdP request")
	}
}

func flowOf(t *testing.T, body string) string {
	t.Helper()
	m := flowRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no consent form in %s", body)
	}
	return html.UnescapeString(m[1])
}

func TestAMalformedBindingCookieIsReplacedWithAWorkingOne(t *testing.T) {
	e := newEnv(t)
	name := e.showConsent(t, nil).binding.Name
	res := e.do(t, "GET", "/authorize?"+authorizeQuery(nil).Encode(), nil, []*http.Cookie{testCookie(name, "short")})
	body, _ := io.ReadAll(res.Body)
	got := res.Cookies()
	if len(got) != 1 || got[0].Value == "short" {
		t.Fatalf("binding cookie %v: want a fresh value", got)
	}
	e.now = e.now.Add(ConsentDelay)
	if ans := e.answer(t, consentPage{flow: flowOf(t, string(body)), binding: got[0]}, "allow", nil); ans.StatusCode != http.StatusSeeOther {
		t.Fatalf("allow with the fresh cookie: %d", ans.StatusCode)
	}
}

// Anyone can mint flows, so a flood must not lock real users out, and an answer given before the
// flood stays remembered, even when the flood's pages were shown earlier and expire sooner.
func TestAFullAnswerTableForgetsTheFlowAnsweredLast(t *testing.T) {
	a := newAnswers()
	a.record("victim", false, t0, t0.Add(10*time.Minute))
	for i := range maxFlows - 1 {
		a.record("flood-"+strconv.Itoa(i), true, t0, t0.Add(5*time.Minute))
	}
	if ok, _, evicted := a.record("new", true, t0, t0.Add(5*time.Minute)); !ok || !evicted {
		t.Fatalf("full table: ok %v evicted %v, want the new flow accepted by evicting one", ok, evicted)
	}
	if _, kept := a.prior("flood-"+strconv.Itoa(maxFlows-2), t0); kept {
		t.Fatal("the flow answered last before the new one was kept")
	}
	for _, id := range []string{"victim", "flood-0", "new"} {
		if _, kept := a.prior(id, t0); !kept {
			t.Errorf("%s was forgotten", id)
		}
	}
	if _, _, evicted := a.record("one more", true, t0, t0.Add(time.Minute)); !evicted {
		t.Fatal("the table grew past its bound")
	}
}

// Two answers to one flow can both pass the first check; the table itself must still refuse the
// second, different one.
func TestTheAnswerTableAcceptsTheSameAnswerAgainAndRefusesAnother(t *testing.T) {
	a := newAnswers()
	expires := t0.Add(FlowLifetime)
	if ok, _, _ := a.record("x", true, t0, expires); !ok {
		t.Fatal("the first answer was refused")
	}
	if ok, _, _ := a.record("x", true, t0, expires); !ok {
		t.Fatal("the same answer again was refused")
	}
	if ok, _, _ := a.record("x", false, t0, expires); ok {
		t.Fatal("a different answer was accepted")
	}
	if _, kept := a.prior("x", expires); kept {
		t.Fatal("an expired flow is still remembered")
	}
	if ok, _, _ := a.record("x", false, expires, expires.Add(FlowLifetime)); !ok {
		t.Fatal("an answer after the flow expired was refused")
	}
}

// Two identical answers arriving together: both proceed, exactly one is the decision that is
// audited.
func TestConcurrentSameAnswersRecordOneDecision(t *testing.T) {
	a := newAnswers()
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	firsts, oks := 0, 0
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, first, _ := a.record("x", true, t0, t0.Add(FlowLifetime))
			mu.Lock()
			defer mu.Unlock()
			if ok {
				oks++
			}
			if first {
				firsts++
			}
		}()
	}
	wg.Wait()
	if oks != n || firsts != 1 {
		t.Fatalf("%d of %d answers proceeded and %d were first; want all to proceed and exactly 1 first", oks, n, firsts)
	}
}

func TestExpiredAnswersMakeRoomForNewFlowsWithoutForgettingLiveOnes(t *testing.T) {
	a := newAnswers()
	fillAnswers(a, t0) // expire at t0+1m
	later := t0.Add(2 * time.Minute)
	for i := range maxFlows {
		if ok, _, evicted := a.record("new-"+strconv.Itoa(i), true, later, later.Add(time.Minute)); !ok || evicted {
			t.Fatalf("record %d: ok %v evicted %v, want room from expired flows, no live flow forgotten", i, ok, evicted)
		}
	}
}

func TestAFloodOfAnswersDoesNotLockOutAUser(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	e.now = e.now.Add(ConsentDelay)
	fillAnswers(e.b.answers, e.now)
	if res := e.answer(t, p, "allow", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("allow with a full table: %d", res.StatusCode)
	}
	if !strings.Contains(e.logs.String(), "consent answer table full") {
		t.Errorf("no warning about the full table in %s", e.logs)
	}
}

func TestTechnicalDetailsListTheClientsScopesThenTheIdPsEachOnce(t *testing.T) {
	text := visibleText(newEnv(t).showConsent(t, url.Values{"scope": {"mcp offline_access"}}).body)
	if !strings.Contains(text, "Requested permissions: mcp offline_access openid profile email api://") || strings.Count(text, "offline_access") != 1 {
		t.Fatalf("technical details: %s", text)
	}
}

func TestNewRequiresTheConsentSettings(t *testing.T) {
	for name, clear := range map[string]func(*Config){
		"consent box": func(c *Config) { c.ConsentBox = nil },
		"origin":      func(c *Config) { c.Origin = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := newEnv(t).b.cfg
			clear(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted a configuration without the " + name)
			}
		})
	}
}

func TestTheStylesheetIsServedLocallyAndOnlyToGETAndHEAD(t *testing.T) {
	e := newEnv(t)
	res := e.do(t, "GET", StylesheetPath, nil, nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(string(body), "button") {
		t.Fatalf("stylesheet: %d %s %q", res.StatusCode, res.Header.Get("Content-Type"), body)
	}
	if res := e.do(t, "HEAD", StylesheetPath, nil, nil); res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("HEAD stylesheet: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if res := e.do(t, "POST", StylesheetPath, url.Values{}, nil); res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST stylesheet: %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
}

// testCookie is a cookie a browser would send back; only name and value reach the server.
func testCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
}
