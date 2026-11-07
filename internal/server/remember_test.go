package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// The wiring end to end: the static client answers the consent page once; its next sign-in, on
// another loopback port, goes straight to the IdP and back with a code, and the consent metric
// counts it as remembered.
func TestTheWiredServerRemembersAStaticClientsConsent(t *testing.T) {
	const public = "https://mcp.example.com"
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/entra"}}
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app))
	orig := newBroker
	t.Cleanup(func() { newBroker = orig })
	newBroker = func(c broker.Config) (*broker.Broker, error) {
		prov, err := entra.New(entra.Config{Tenant: fake.TenantID(), ClientID: app.ID, ClientAuth: idp.ClientSecret("s3cret"),
			RedirectURL: public + "/callback/entra", HTTPClient: fake.HTTPClient()})
		if err != nil {
			return nil, err
		}
		c.IdP, c.IdPScopes = prov, prov.Scope()
		return orig(c)
	}
	cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(srv.Public.Handler)
	t.Cleanup(h.Close)

	b := newTestBrowser(t, h.URL, public)
	send := b.send
	viaIdP := func(res *http.Response) *http.Response {
		t.Helper()
		idpRes, err := fake.HTTPClient().Get(res.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		_ = idpRes.Body.Close()
		cb, _ := url.Parse(idpRes.Header.Get("Location"))
		return send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, res.Cookies())
	}
	authorize := func(port string, cookies []*http.Cookie) *http.Response {
		q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1:" + port + "/callback"}, "response_type": {"code"},
			"code_challenge": {pkce("verifier-0123456789-0123456789-0123456789-abc")}, "code_challenge_method": {"S256"}}
		return send(http.MethodGet, "/authorize?"+q.Encode(), nil, cookies)
	}

	page := authorize("53124", nil)
	body := readAll(t, page)
	if page.StatusCode != http.StatusOK || !strings.Contains(body, "remember your choice for this app for 30 days") {
		t.Fatalf("first sign-in: %d, want the page saying the choice is remembered", page.StatusCode)
	}
	allow := b.allow(page, body)
	back := viaIdP(allow)
	var hint []*http.Cookie
	for _, c := range back.Cookies() {
		if strings.Contains(c.Name, "byw_hint_") && c.MaxAge > 0 {
			hint = append(hint, c)
		}
	}
	if back.StatusCode != http.StatusFound || len(hint) != 1 {
		t.Fatalf("first callback: %d, hint cookies %d", back.StatusCode, len(hint))
	}

	again := authorize("61000", hint)
	if again.StatusCode != http.StatusSeeOther || !strings.Contains(again.Header.Get("Location"), "/oauth2/v2.0/authorize") {
		t.Fatalf("second sign-in on another port: %d to %q, want straight to the IdP", again.StatusCode, again.Header.Get("Location"))
	}
	if code := viaIdP(again); code.StatusCode != http.StatusFound || !strings.Contains(code.Header.Get("Location"), "code=") {
		t.Fatalf("remembered callback: %d to %q", code.StatusCode, code.Header.Get("Location"))
	}
	scrape := httptest.NewRequest("GET", "/metrics", nil)
	scrape.Host = "127.0.0.1:9090"
	m := httptest.NewRecorder()
	srv.Internal.Handler.ServeHTTP(m, scrape)
	if !strings.Contains(m.Body.String(), `byward_consent_total{outcome="remembered",trust="verified"} 1`) {
		t.Fatalf("remembered sign-in not counted:\n%s", m.Body)
	}
}
