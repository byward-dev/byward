package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/downstream"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/upstream/relay"
)

const oboPublic = "https://mcp.example.com"

// oboEnv is the proxy with On-Behalf-Of to Microsoft Graph, its Entra adapter reaching the fake
// IdP through its HTTP client, in front of an upstream that records what it receives.
type oboEnv struct {
	fake  *fakeidp.IdP
	proxy *Servers
	srv   *httptest.Server
	logs  *syncBuffer

	mu      sync.Mutex
	headers []http.Header // what the upstream received
}

func newOBOEnv(t *testing.T, scopes string, opts ...fakeidp.Option) *oboEnv {
	t.Helper()
	return newOBOEnvWith(t, scopes, nil, opts...)
}

// newOBOEnvWith is newOBOEnv with extra settings.
func newOBOEnvWith(t *testing.T, scopes string, env []string, opts ...fakeidp.Option) *oboEnv {
	t.Helper()
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{oboPublic + "/callback/entra"}}
	e := &oboEnv{fake: fakeidp.New(t, fakeidp.Entra, append([]fakeidp.Option{fakeidp.WithClient(app)}, opts...)...), logs: &syncBuffer{}}
	// The one Entra provider (sign-in and On-Behalf-Of) reaches the fake through its HTTP client.
	origProvider := newEntraProvider
	newEntraProvider = func(c entra.Config) (*entra.Provider, error) {
		c.Tenant, c.ClientID, c.ClientAuth, c.HTTPClient = e.fake.TenantID(), app.ID, idp.ClientSecret("s3cret"), e.fake.HTTPClient()
		return entra.New(c)
	}
	t.Cleanup(func() { newEntraProvider = origProvider })
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.headers = append(e.headers, r.Header.Clone())
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(up.Close)
	settings := append(authEnv(t), "BYWARD_PUBLIC_URL="+oboPublic+"/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp", "BYWARD_OBO_SCOPES="+scopes)
	cfg, _, err := config.Load(nil, append(settings, env...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logging.New(e.logs, "json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s.closeStore != nil {
			_ = s.closeStore()
		}
	})
	e.proxy = s
	e.srv = httptest.NewServer(s.Public.Handler)
	t.Cleanup(e.srv.Close)
	return e
}

// send makes a request to the proxy as the browser or client would, for host mcp.example.com.
// Cookies are passed explicitly: the proxy's are Secure (an https public URL) and this server is
// plain http, so a cookie jar would not send them.
func (e *oboEnv) send(t *testing.T, c *http.Client, method, path string, body io.Reader, header http.Header, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	r, _ := http.NewRequest(method, e.srv.URL+path, body)
	r.Host = "mcp.example.com"
	for k, v := range header {
		r.Header[k] = v
	}
	for _, ck := range cookies {
		r.AddCookie(ck)
	}
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// metrics scrapes the internal listener.
func (e *oboEnv) metrics() string {
	m := httptest.NewRecorder()
	scrape := httptest.NewRequest("GET", "/metrics", nil)
	scrape.Host = "127.0.0.1:9090" // the internal listener answers only IP or listed hosts
	e.proxy.Internal.Handler.ServeHTTP(m, scrape)
	return m.Body.String()
}

var oboFlow = regexp.MustCompile(`name="flow" value="([^"]+)"`)

// signIn runs the sign-in of the static client test-app and returns the token response.
func (e *oboEnv) signIn(t *testing.T) map[string]any {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := "verifier-0123456789-0123456789-0123456789-abc"
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1:7777/callback"}, "response_type": {"code"},
		"state": {"s"}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}, "scope": {"mcp"}}
	page := e.send(t, c, "GET", "/authorize?"+q.Encode(), nil, nil)
	pageBody := readAll(t, page)
	flow := oboFlow.FindStringSubmatch(pageBody)
	if page.StatusCode != http.StatusOK || flow == nil {
		t.Fatalf("consent page: status %d, flow field found %v\n%s", page.StatusCode, flow != nil, pageBody)
	}
	time.Sleep(broker.ConsentDelay + 100*time.Millisecond) // Allow is accepted only after the delay
	allow := e.send(t, c, "POST", "/consent", strings.NewReader(url.Values{"flow": {html.UnescapeString(flow[1])}, "action": {"allow"}}.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {oboPublic}, "Sec-Fetch-Site": {"same-origin"}}, page.Cookies()...)
	if allow.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent answer: %d %s", allow.StatusCode, readAll(t, allow))
	}
	signedIn, err := e.fake.HTTPClient().Get(allow.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = signedIn.Body.Close()
	cb, _ := url.Parse(signedIn.Header.Get("Location"))
	back := e.send(t, c, "GET", cb.Path+"?"+cb.RawQuery, nil, nil, allow.Cookies()...)
	ret, _ := url.Parse(back.Header.Get("Location"))
	if back.StatusCode != http.StatusFound || ret.Query().Get("code") == "" {
		t.Fatalf("callback: %d %q", back.StatusCode, back.Header.Get("Location"))
	}
	tok := e.send(t, c, "POST", "/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {ret.Query().Get("code")},
		"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1:7777/callback"}, "code_verifier": {verifier}}.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	var body map[string]any
	if err := json.NewDecoder(tok.Body).Decode(&body); err != nil || tok.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", tok.StatusCode, err)
	}
	return body
}

// mcp sends an MCP request with the access token (and any extra headers) and returns the response.
func (e *oboEnv) mcp(t *testing.T, access, body string, extra http.Header) (int, string) {
	t.Helper()
	h := http.Header{"Authorization": {"Bearer " + access}, "Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}}
	for k, v := range extra {
		h[k] = v
	}
	res := e.send(t, http.DefaultClient, "POST", "/mcp", strings.NewReader(body), h)
	return res.StatusCode, readAll(t, res)
}

const graphUserRead = "https://graph.microsoft.com/User.Read"

const oboToolsCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"whoami"}}`

// ADR-0017: every request to the HTTP upstream carries a token for Microsoft Graph obtained On
// Behalf Of the signed-in user, in its own header (a client's copy is removed), from the cache
// after the first; the proxy's access token does not outlive the stored IdP token.
func TestUpstreamGetsADownstreamTokenOnBehalfOfTheUser(t *testing.T) {
	const idpLife = 20 * time.Minute
	e := newOBOEnv(t, graphUserRead, fakeidp.WithTokenLifetime(idpLife))
	tokens := e.signIn(t)
	if got := tokens["expires_in"].(float64); got > (idpLife - broker.IdPTokenMargin).Seconds() {
		t.Fatalf("expires_in %v: the access token outlives the IdP token it rides on", got)
	}
	access := tokens["access_token"].(string)
	for range 2 {
		if status, body := e.mcp(t, access, oboToolsCall, http.Header{"X-Byward-Downstream-Token": {"Bearer forged"}}); status != http.StatusOK {
			t.Fatalf("MCP request: %d %s", status, body)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.headers) != 2 {
		t.Fatalf("upstream got %d requests, want 2", len(e.headers))
	}
	first := e.headers[0].Values("X-Byward-Downstream-Token")
	if len(first) != 1 || !strings.HasPrefix(first[0], "Bearer ") || strings.Contains(first[0], "forged") {
		t.Fatalf("downstream header %q: want our token alone, the client's removed", first)
	}
	tok := strings.TrimPrefix(first[0], "Bearer ")
	claims := jwtClaims(t, tok)
	if claims["aud"] != fakeidp.GraphAppID || claims["scp"] != "User.Read" {
		t.Fatalf("downstream token aud %v scp %v, want Microsoft Graph User.Read", claims["aud"], claims["scp"])
	}
	if second := e.headers[1].Get("X-Byward-Downstream-Token"); second != first[0] {
		t.Error("the second request got a different token: the cache was not used")
	}
	if strings.Contains(e.logs.String(), tok) {
		t.Error("the downstream token reached the log")
	}
	if !strings.Contains(e.logs.String(), `"msg":"On-Behalf-Of","reason":"downstream API https://graph.microsoft.com;`) {
		t.Errorf("the startup log does not name the downstream API; log: %s", e.logs)
	}
	// The identity assertion (ADR-0016) still reaches the upstream beside the downstream token.
	assertion, isBearer := strings.CutPrefix(e.headers[0].Get("Authorization"), "Bearer ")
	if !isBearer || assertion == tok {
		t.Fatal("the upstream got no identity assertion beside the downstream token")
	}
	if sub, _ := jwtClaims(t, assertion)["sub"].(string); !strings.HasPrefix(sub, e.fake.TenantID()+":") {
		t.Fatalf("assertion sub %q, want the signed-in user's key in tenant %s", sub, e.fake.TenantID())
	}
	// No token passthrough: neither the proxy's access token nor the user's IdP token (the
	// assertion, scp access_as_user) reaches the upstream.
	for name, values := range e.headers[0] {
		for _, v := range values {
			bearer, isBearer := strings.CutPrefix(v, "Bearer ")
			if strings.Contains(v, access) || (isBearer && strings.Count(bearer, ".") == 2 && jwtClaims(t, bearer)["scp"] == "access_as_user") {
				t.Errorf("header %s carries an inbound token", name)
			}
		}
	}
	metrics := e.metrics()
	for _, want := range []string{`byward_downstream_tokens_total{outcome="issued"} 1`, `byward_downstream_tokens_total{outcome="cached"} 1`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// ADR-0017 §5 (2026-11-07 amendment): Entra's refusals are answered in the proxy's name, as an
// upstream refusal is (ADR-0025), never as 401 or 403; nothing reaches the upstream; the operator
// gets the admin-consent URL for the user's tenant.
func TestDownstreamRefusalsAreAnsweredInTheProxysName(t *testing.T) {
	cases := []struct {
		name      string
		failure   *fakeidp.Failure
		request   string
		want      string // in the response body
		logWant   string
		auditWant string
	}{
		{"consent missing, tools/call", &fakeidp.ConsentRequired, oboToolsCall,
			`"isError":true`, `"admin_consent_url":"https://login.microsoftonline.com/`, `"reason":"consent_required"`},
		{"Conditional Access, another method", &fakeidp.InteractionRequired, `{"jsonrpc":"2.0","id":"a","method":"tools/list"}`,
			`"data":{"downstream":"interaction_required"}`, "Conditional Access", `"reason":"interaction_required"`},
		{"Entra unavailable", &fakeidp.TemporarilyUnavailable, oboToolsCall,
			"temporarily unavailable", `"reason":"unavailable"`, `"reason":"unavailable"`},
		{"any other refusal", &fakeidp.InvalidAssertion, oboToolsCall,
			"could not get access to https://graph.microsoft.com on your behalf", `"idp_error_code":50013`, `"reason":"failed"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newOBOEnv(t, graphUserRead)
			access := e.signIn(t)["access_token"].(string)
			e.fake.Set(fakeidp.FailToken(fakeidp.GrantJWTBearer, c.failure))
			status, body := e.mcp(t, access, c.request, nil)
			if status != http.StatusOK || !strings.Contains(body, c.want) || !json.Valid([]byte(body)) {
				t.Fatalf("answer %d %s, want 200 with %s", status, body, c.want)
			}
			e.mu.Lock()
			reached := len(e.headers)
			e.mu.Unlock()
			if reached != 0 {
				t.Fatalf("the upstream got %d requests without a downstream token", reached)
			}
			logs := e.logs.String()
			if !strings.Contains(logs, c.logWant) || !strings.Contains(logs, `"event":"downstream_token_refused"`) || !strings.Contains(logs, c.auditWant) {
				t.Fatalf("logs lack %s, the audit record or %s:\n%s", c.logWant, c.auditWant, logs)
			}
			// No token in the log: not the proxy's access token, nor any JWT (the assertion included).
			if strings.Contains(logs, access) || strings.Contains(logs, "eyJ") {
				t.Error("a token reached the log")
			}
			if c.failure.Claims != "" && strings.Contains(logs, "polids") {
				t.Error("the claims challenge reached the log")
			}
			if c.failure == &fakeidp.ConsentRequired && !strings.Contains(logs, "/"+e.fake.TenantID()+"/v2.0/adminconsent") {
				t.Error("the admin-consent URL is not for the user's tenant")
			}
			if c.failure != &fakeidp.ConsentRequired && strings.Contains(logs, "admin_consent_url") {
				t.Error("an admin-consent URL for a refusal consent would not fix")
			}
			outcome := strings.TrimSuffix(strings.TrimPrefix(c.auditWant, `"reason":"`), `"`)
			if want := `byward_downstream_tokens_total{outcome="` + outcome + `"} 1`; !strings.Contains(e.metrics(), want) {
				t.Errorf("metrics lack %s", want)
			}
		})
	}
}

// Each user gets a downstream token of their own through the middleware: a second user is never
// served the first one's cached token.
func TestEachUserGetsTheirOwnDownstreamToken(t *testing.T) {
	e := newOBOEnv(t, graphUserRead)
	oids := []string{fakeidp.NewGUID(), fakeidp.NewGUID()}
	var access []string
	for _, oid := range oids {
		e.fake.Set(fakeidp.WithUser(fakeidp.User{OID: oid}))
		access = append(access, e.signIn(t)["access_token"].(string))
	}
	for _, a := range []string{access[0], access[1], access[0]} {
		if status, body := e.mcp(t, a, oboToolsCall, nil); status != http.StatusOK {
			t.Fatalf("MCP request: %d %s", status, body)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, want := range []string{oids[0], oids[1], oids[0]} {
		tok := strings.TrimPrefix(e.headers[i].Get("X-Byward-Downstream-Token"), "Bearer ")
		if got := jwtClaims(t, tok)["oid"]; got != want {
			t.Fatalf("request %d: downstream token for oid %v, want %s", i, got, want)
		}
	}
	metrics := e.metrics()
	for _, want := range []string{`byward_downstream_tokens_total{outcome="issued"} 2`, `byward_downstream_tokens_total{outcome="cached"} 1`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// An app-only caller (ADR-0022) has no user to act on behalf of: it is relayed without a downstream
// token, and nothing is exchanged.
func TestAnAppOnlyCallerIsRelayedWithoutADownstreamToken(t *testing.T) {
	d := &downstreamTokens{
		cache: downstream.New(func(context.Context, string, string, []string) (downstream.Token, error) {
			t.Error("an exchange for an app-only caller")
			return downstream.Token{}, nil
		}, []string{graphUserRead}, 0, time.Now),
		header: "X-Byward-Downstream-Token", resource: "https://graph.microsoft.com",
		assertion: func(context.Context, string) (string, time.Time, error) {
			t.Error("a stored IdP token looked up for an app-only caller")
			return "", time.Time{}, nil
		},
		log: slog.New(slog.DiscardHandler),
	}
	var relayed *http.Request
	d.serve(httptest.NewRecorder(), httptest.NewRequest("POST", "/mcp", strings.NewReader(oboToolsCall)),
		resource.Identity{Subject: "tid:app-oid", ClientID: "app", PrincipalType: resource.PrincipalClient}, true,
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { relayed = r }))
	if relayed == nil {
		t.Fatal("the app-only request was not relayed")
	}
	h := http.Header{}
	d.inject(relayed.Context(), h)
	if v := h.Get("X-Byward-Downstream-Token"); v != "" {
		t.Fatalf("an app-only request got a downstream token %q", v)
	}
}

// A request without a signed-in Entra user, or whose grant holds no IdP token, is refused before
// any exchange, even when the user's token is cached, and never reaches the upstream.
func TestDownstreamRefusesARequestWithoutAUsableGrant(t *testing.T) {
	user := resource.Identity{Subject: "tid:oid", GrantID: "g", ClientID: "c"}
	cases := []struct {
		name      string
		id        resource.Identity
		ok        bool
		assertion error
	}{
		{"no identity", resource.Identity{}, false, nil},
		{"a subject that is not an Entra user key", resource.Identity{Subject: "nocolon", GrantID: "g"}, true, nil},
		{"no grant", resource.Identity{Subject: "tid:oid"}, true, nil},
		{"no IdP token in the grant", user, true, broker.ErrNoIdPAccessToken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exchanges := 0
			assertionErr := error(nil)
			d := &downstreamTokens{
				cache: downstream.New(func(context.Context, string, string, []string) (downstream.Token, error) {
					exchanges++
					return downstream.Token{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}, nil
				}, []string{graphUserRead}, 0, time.Now),
				header: "X-Byward-Downstream-Token", resource: "https://graph.microsoft.com",
				assertion: func(context.Context, string) (string, time.Time, error) {
					return "assertion", time.Now().Add(time.Hour), assertionErr
				},
				log: slog.New(slog.DiscardHandler),
			}
			relayed := 0
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { relayed++ })
			call := func(id resource.Identity, ok bool) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				d.serve(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(oboToolsCall)), id, ok, next)
				return w
			}
			call(user, true) // warm the cache for the user
			assertionErr = c.assertion
			before := exchanges
			w := call(c.id, c.ok)
			if relayed != 1 || exchanges != before || !strings.Contains(w.Body.String(), `"isError":true`) {
				t.Fatalf("relayed %d (want only the warm-up), %d new exchanges, answer %s", relayed, exchanges-before, w.Body)
			}
		})
	}
}

// A client that goes away while its exchange is in flight was not refused: no refusal is logged,
// audited or answered.
func TestAClientGoingAwayIsNotARefusal(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	logs := &syncBuffer{}
	d := &downstreamTokens{
		cache: downstream.New(func(context.Context, string, string, []string) (downstream.Token, error) {
			<-release
			return downstream.Token{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}, []string{graphUserRead}, 0, time.Now),
		header: "X-Byward-Downstream-Token", resource: "https://graph.microsoft.com",
		assertion: func(context.Context, string) (string, time.Time, error) {
			return "assertion", time.Now().Add(time.Hour), nil
		},
		log: slog.New(slog.NewJSONHandler(logs, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(ctx, "POST", "/mcp", strings.NewReader(oboToolsCall))
	d.serve(w, r, resource.Identity{Subject: "tid:oid", GrantID: "g"}, true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a cancelled request was relayed")
	}))
	if w.Body.Len() != 0 || strings.Contains(logs.String(), "no downstream token") {
		t.Fatalf("answer %q, logs %s: want neither for a client that went away", w.Body, logs)
	}
}

// With On-Behalf-Of off, the header is still removed from inbound requests, whatever else the
// upstream gets: an upstream that reads it must never get a client's value (ADR-0017 §3). The access
// token keeps its usual lifetime.
func TestDownstreamHeaderIsStrippedAndTokensUncappedWhenOnBehalfOfIsOff(t *testing.T) {
	cred := filepath.Join(t.TempDir(), "upstream-credential")
	if err := os.WriteFile(cred, []byte("k-123"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		env    []string
		forged http.Header // besides the downstream header
		want   map[string]string
	}{
		{"by default", nil, nil, nil},
		{"with the operator's upstream credential", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + cred, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			http.Header{"X-Api-Key": {"forged"}}, map[string]string{"X-Api-Key": "k-123"}},
		{"with plain identity headers", []string{"BYWARD_IDENTITY_HEADERS=true"},
			http.Header{config.HeaderSubject: {"forged"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newOBOEnvWith(t, "", c.env, fakeidp.WithTokenLifetime(20*time.Minute))
			tokens := e.signIn(t)
			if got := tokens["expires_in"].(float64); got != broker.AccessLifetime.Seconds() {
				t.Fatalf("expires_in %v, want the usual %v: the access token is capped at the IdP token only with On-Behalf-Of", got, broker.AccessLifetime.Seconds())
			}
			h := http.Header{"X-Byward-Downstream-Token": {"Bearer forged"}}
			for k, v := range c.forged {
				h[k] = v
			}
			if status, body := e.mcp(t, tokens["access_token"].(string), oboToolsCall, h); status != http.StatusOK {
				t.Fatalf("MCP request: %d %s", status, body)
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if len(e.headers) != 1 {
				t.Fatalf("the upstream got %d requests, want 1", len(e.headers))
			}
			got := e.headers[0]
			if v := got.Values("X-Byward-Downstream-Token"); len(v) != 0 {
				t.Fatalf("the upstream got %q, want no downstream header", v)
			}
			for k, want := range c.want {
				if v := got.Get(k); v != want {
					t.Errorf("%s = %q, want the proxy's %q", k, v, want)
				}
			}
			for k := range c.forged {
				if v := got.Get(k); v == "forged" {
					t.Errorf("%s reached the upstream with the client's value", k)
				}
			}
		})
	}
}

// jwtClaims decodes a JWT's payload without verifying it (the fake IdP issued it).
func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// doctor names the downstream API, the header and the consent it needs.
func TestDoctorDescribesOnBehalfOf(t *testing.T) {
	cfg := &config.Config{UpstreamURL: mustURL(t, "https://upstream.example/mcp"), AssertionHeader: "Authorization",
		OBOScopes: []string{graphUserRead}, OBOHeader: "X-Byward-Downstream-Token"}
	msg := upstreamResult(cfg, http.ProxyFromEnvironment).Message
	for _, want := range []string{"On-Behalf-Of", graphUserRead, "X-Byward-Downstream-Token", "admin consent"} {
		if !strings.Contains(msg, want) {
			t.Errorf("doctor says %q, missing %q", msg, want)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// #195: with the assertion moved, the downstream token may go in Authorization. The upstream then
// sees exactly one Authorization, the downstream token, never the client's proxy token.
func TestTheDownstreamTokenCanReplaceAuthorization(t *testing.T) {
	e := newOBOEnvWith(t, graphUserRead, []string{"BYWARD_ASSERTION_HEADER=X-Byward-Assertion", "BYWARD_OBO_HEADER=Authorization"})
	access := e.signIn(t)["access_token"].(string)
	if status, body := e.mcp(t, access, oboToolsCall, nil); status != http.StatusOK {
		t.Fatalf("MCP request: %d %s", status, body)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.headers) != 1 {
		t.Fatalf("the upstream got %d requests, want 1", len(e.headers))
	}
	got := e.headers[0].Values("Authorization")
	if len(got) != 1 || !strings.HasPrefix(got[0], "Bearer ") || strings.Contains(got[0], access) {
		t.Fatalf("Authorization %q: want exactly one, the downstream token, never the client's", got)
	}
	if aud := jwtClaims(t, strings.TrimPrefix(got[0], "Bearer "))["aud"]; aud != fakeidp.GraphAppID {
		t.Fatalf("Authorization carries a token for %v, want Microsoft Graph", aud)
	}
	if !strings.HasPrefix(e.headers[0].Get("X-Byward-Assertion"), "Bearer ") {
		t.Fatal("the identity assertion did not reach its own header")
	}
}

// #195: with OBO in Authorization a user's request carries the downstream token there, and an
// app-only caller's, which gets none, carries no Authorization at all; the client's copy is removed
// either way.
func TestWithOBOInAuthorizationTheUpstreamGetsTheDownstreamTokenOrNothing(t *testing.T) {
	var got []http.Header
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Clone())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{}}`)
	}))
	t.Cleanup(up.Close)
	cfg := &config.Config{UpstreamURL: mustURL(t, up.URL+"/mcp"), AssertionHeader: "X-Byward-Assertion", OBOHeader: "Authorization", UpstreamHeaderTimeout: time.Minute}
	log := slog.New(slog.DiscardHandler)
	d := &downstreamTokens{
		cache: downstream.New(func(context.Context, string, string, []string) (downstream.Token, error) {
			return downstream.Token{AccessToken: "downstream-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}, []string{graphUserRead}, 0, time.Now),
		header: cfg.OBOHeader, resource: "https://graph.microsoft.com", log: log,
		assertion: func(context.Context, string) (string, time.Time, error) {
			return "assertion", time.Now().Add(time.Hour), nil
		},
	}
	relayTo := httpUpstream(cfg, log, relay.WithInject(d.inject))
	for _, c := range []struct {
		name string
		id   resource.Identity
		want []string
	}{
		{"a user", resource.Identity{Subject: "tid:oid", GrantID: "g", PrincipalType: resource.PrincipalUser}, []string{"Bearer downstream-token"}},
		{"an app-only caller", resource.Identity{Subject: "tid:app", ClientID: "app", PrincipalType: resource.PrincipalClient}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			got = nil
			mu.Unlock()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.serve(w, r, c.id, true, relayTo) }))
			defer srv.Close()
			r, err := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(oboToolsCall))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer the-clients-proxy-token")
			r.Header.Set("Content-Type", "application/json")
			res, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			if len(got) != 1 {
				t.Fatalf("the upstream got %d requests, want 1 (serve answered %d)", len(got), res.StatusCode)
			}
			if a := got[0].Values("Authorization"); !slices.Equal(a, c.want) {
				t.Fatalf("Authorization %q, want %q", a, c.want)
			}
		})
	}
}

// #196: a refusal names the downstream API to the user; one addressed by its app ID is named as an
// application, so the user is not shown a bare GUID.
func TestRefusalsNameTheDownstreamAPI(t *testing.T) {
	for _, c := range []struct{ name, scope, want string }{
		{"Microsoft Graph", graphUserRead, "access to https://graph.microsoft.com"},
		{"an API of one's own", "api://00000000-0000-0000-0000-0000000000aa/Files.Read", "access to api://00000000-0000-0000-0000-0000000000aa"},
		{"an API addressed by its app ID", "6dae42f8-4368-4678-94ff-3960e28e3630/.default", "access to the application 6dae42f8-4368-4678-94ff-3960e28e3630"},
	} {
		t.Run(c.name, func(t *testing.T) {
			scopes := []string{c.scope}
			d := newDownstreamTokens(scopes, "X-Byward-Downstream-Token", nil, "entra",
				func(context.Context, string) (string, time.Time, error) {
					return "assertion", time.Now().Add(time.Hour), nil
				},
				slog.New(slog.DiscardHandler), Observability{})
			// The exchange fails as Entra does without admin consent (AADSTS65001).
			d.cache = downstream.New(func(context.Context, string, string, []string) (downstream.Token, error) {
				return downstream.Token{}, &idp.Error{Class: idp.SignInAgain, Code: entra.CodeConsentRequired}
			}, scopes, 0, time.Now)
			d.consentURL = func(string) string { return "https://login.microsoftonline.com/x/v2.0/adminconsent" }
			w := httptest.NewRecorder()
			d.serve(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(oboToolsCall)), resource.Identity{Subject: "tid:oid", GrantID: "g"}, true,
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("a refused request was relayed") }))
			if !strings.Contains(w.Body.String(), c.want) {
				t.Fatalf("answer %s does not name %q", w.Body, c.want)
			}
		})
	}
}
