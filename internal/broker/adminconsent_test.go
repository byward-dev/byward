package broker

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ADR-0017 §5 and its 2026-11-07 amendment: the admin-consent redirect shows a page and logs at
// info that it is unverified; it records no audit event and never uses the returned tenant.
func TestAdminConsentRedirectShowsAPageAndTrustsNothing(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	cases := []struct {
		name      string
		query     url.Values
		status    int
		title     string
		logReason string
		notLogged string
	}{
		{"granted", url.Values{"admin_consent": {"True"}, "tenant": {tenant}, "scope": {"https://graph.microsoft.com/User.Read"}},
			http.StatusOK, "Administrator consent recorded", `"reason":"granted"`, ""},
		{"Entra's error redirect also says admin_consent=True", url.Values{"admin_consent": {"True"}, "tenant": {tenant},
			"error": {"consent_required"}, "error_description": {"AADSTS65004: User declined to consent"}},
			http.StatusBadRequest, "Administrator consent was not granted", `"reason":"error consent_required"`, "AADSTS65004"},
		{"an error value that is not an OAuth code is not logged", url.Values{"admin_consent": {"True"}, "error": {"<script>alert(1)</script>"}},
			http.StatusBadRequest, "Administrator consent was not granted", `"reason":"error"`, "script"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			res := e.do(t, "GET", "/callback/entra?"+c.query.Encode(), nil, nil)
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != c.status || !strings.Contains(string(body), c.title) {
				t.Fatalf("%d %s, want %d with %q", res.StatusCode, body, c.status, c.title)
			}
			if res.Header.Get("Content-Security-Policy") == "" {
				t.Error("the page has no Content-Security-Policy")
			}
			logs := e.logs.String()
			if !strings.Contains(logs, "admin consent redirect received (unverified)") || !strings.Contains(logs, c.logReason) {
				t.Errorf("logs %s: want the unverified redirect with %s", logs, c.logReason)
			}
			if c.notLogged != "" && strings.Contains(logs+string(body), c.notLogged) {
				t.Errorf("%q reached the log or the page", c.notLogged)
			}
			if strings.Contains(logs+string(body)+e.audit.String(), tenant) {
				t.Error("the redirect's tenant was used")
			}
			if strings.Contains(e.audit.String(), "consent") {
				t.Errorf("the unverifiable redirect wrote an audit record: %s", e.audit.String())
			}
		})
	}
}

// The /callback rate limit covers the admin-consent redirect.
func TestAdminConsentRedirectIsRateLimited(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Limiter = stubLimiter{endpoints: map[string]bool{"callback": true}} })
	res := e.do(t, "GET", "/callback/entra?admin_consent=True", nil, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 from the callback's rate limit", res.StatusCode)
	}
	if strings.Contains(e.logs.String(), "admin consent redirect received") {
		t.Error("a rate-limited redirect was still handled")
	}
}

// A sign-in callback is a sign-in callback even with a stray admin_consent parameter: it carries a
// code, so its login is checked as at any callback, and no consent page is shown.
func TestASignInCallbackWithAdminConsentIsStillASignIn(t *testing.T) {
	e := newEnv(t)
	res := e.do(t, "GET", "/callback/entra?"+url.Values{"admin_consent": {"True"}, "code": {"x"}, "state": {"bogus"}}.Encode(), nil, nil)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "Administrator consent") {
		t.Fatalf("%d %s, want the sign-in's 400 for a missing login, not the admin-consent page", res.StatusCode, body)
	}
	if strings.Contains(e.logs.String(), "admin consent redirect received") {
		t.Error("a sign-in callback was handled as the admin-consent redirect")
	}
}
