package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/idp/entra"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/store/memory"
	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
	"github.com/corker/mcp-authproxy/internal/token"
)

const (
	issuer        = "https://mcp.example.com"
	resourceID    = "https://mcp.example.com/mcp"
	clientID      = "static-client"
	otherClientID = "other-client"
	clientCB      = "http://127.0.0.1:43210/callback"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// memStore is the in-memory store, recording created grant IDs so tests can find "the" grant.
type memStore struct {
	*memory.Store
	mu  sync.Mutex
	ids []string
}

func newMemStore() *memStore { return &memStore{Store: memory.New()} }

func (m *memStore) CreateGrant(ctx context.Context, g store.Grant) (store.Grant, error) {
	got, err := m.Store.CreateGrant(ctx, g)
	if err == nil {
		m.mu.Lock()
		m.ids = append(m.ids, g.ID)
		m.mu.Unlock()
	}
	return got, err
}

// staticClient is a minimal in-test public client. Authenticate mirrors the client-ID checks of
// registration's client authentication: a Basic user (form-encoded) and a form client_id must
// both name this client.
type staticClient struct{ id string }

func (c staticClient) ID() string                        { return c.id }
func (staticClient) Name() string                        { return "Test app" }
func (staticClient) Trust() registration.TrustLevel      { return registration.Verified }
func (staticClient) AuthMethod() registration.AuthMethod { return registration.None }
func (staticClient) RedirectAllowed(u string) error {
	if u != clientCB {
		return errors.New("registered " + clientCB + ", sent " + u)
	}
	return nil
}
func (c staticClient) Authenticate(_ context.Context, f url.Values, h http.Header, _ string, _ time.Time) error {
	if user, _, ok := (&http.Request{Header: h}).BasicAuth(); ok {
		if u, err := url.QueryUnescape(user); err != nil || u != c.id {
			return errors.New("Basic client ID mismatch")
		}
	}
	if id := f.Get("client_id"); id != "" && id != c.id {
		return errors.New("client_id mismatch")
	}
	return nil
}

type registry struct{}

func (registry) Client(_ context.Context, id string) (registration.Client, error) {
	if id != clientID && id != otherClientID {
		return nil, registration.ErrUnknownClient
	}
	return staticClient{id: id}, nil
}

type env struct {
	srv    *httptest.Server
	b      *Broker
	st     *memStore
	sealer *token.Sealer
	idpBox *token.Box
	fake   *fakeidp.IdP
	now    time.Time
}

func keyRing(t *testing.T) *token.KeyRing {
	t.Helper()
	dir := t.TempDir()
	k := make([]byte, token.KeySize)
	_, _ = rand.Read(k)
	if err := os.WriteFile(filepath.Join(dir, "k1"), []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := token.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{now: t0, st: newMemStore()}
	clock := func() time.Time { return e.now }
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{issuer + "/callback/entra"}}
	e.fake = fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app), fakeidp.WithClock(clock))
	prov, err := entra.New(entra.Config{Tenant: e.fake.TenantID(), ClientID: app.ID, ClientAuth: idp.ClientSecret("s3cret"),
		RedirectURL: issuer + "/callback/entra", HTTPClient: e.fake.HTTPClient(), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	ring := keyRing(t)
	res, _ := url.Parse(resourceID)
	e.sealer, _ = token.NewSealer(ring, resourceID)
	login, _ := token.NewBox(ring, "login", clock)
	e.idpBox, _ = token.NewBox(ring, "idp-tokens", clock)
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	e.b, err = New(Config{Issuer: issuer, Resource: res, Scope: "mcp", IdPName: "entra", IdP: prov, Clients: registry{},
		Store: e.st, Sealer: e.sealer, LoginBox: login, IdPTokenBox: e.idpBox, SecureCookies: true, Log: discard, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	e.b.Register(mux)
	// The logging middleware gives each request the ID that error pages show as the reference.
	e.srv = httptest.NewTLSServer(logging.Middleware(discard, mux))
	t.Cleanup(e.srv.Close)
	return e
}

// send runs r against the broker without following redirects.
func (e *env) send(t *testing.T, r *http.Request) *http.Response {
	t.Helper()
	c := e.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func (e *env) do(t *testing.T, method, path string, body url.Values, cookies []*http.Cookie) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(body.Encode())
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rdr)
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return e.send(t, r)
}

func (e *env) doBasic(t *testing.T, path string, body url.Values, user string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(body.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(user, "")
	return e.send(t, r)
}

const verifier = "verifier-0123456789-0123456789-0123456789-abc"

func challengeFor(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func challenge() string { return challengeFor(verifier) }

var titleRE = regexp.MustCompile(`<title>(.*?)</title>`)

// pageTitle is the title of the HTML page in res.
func pageTitle(t *testing.T, res *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(res.Body)
	m := titleRE.FindSubmatch(b)
	if m == nil {
		t.Fatalf("not an HTML page: %d %s", res.StatusCode, b)
	}
	return html.UnescapeString(string(m[1]))
}

// startLogin runs /authorize → fake Entra (auto-login) and returns the login cookie and the IdP's
// redirect to /callback/entra. A nil value in extra removes that parameter.
func (e *env) startLogin(t *testing.T, extra url.Values) (*http.Cookie, *url.URL) {
	t.Helper()
	q := url.Values{"client_id": {clientID}, "redirect_uri": {clientCB}, "response_type": {"code"},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"client-state"}}
	for k, v := range extra {
		q[k] = v
	}
	res := e.do(t, "GET", "/authorize?"+q.Encode(), nil, nil)
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("authorize: %d %s", res.StatusCode, b)
	}
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("authorize set %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if !strings.HasPrefix(c.Name, "__Host-mcpap_login_") || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("login cookie %+v: want __Host- prefix, HttpOnly, Secure, SameSite=Lax, Path=/", c)
	}
	idpRes, err := e.fake.HTTPClient().Get(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	if !strings.HasPrefix(cb.String(), issuer+"/callback/entra") {
		t.Fatalf("IdP redirected to %s", cb)
	}
	return c, cb
}

// signIn runs the whole login and returns the redirect to the MCP client.
func (e *env) signIn(t *testing.T, extra url.Values) *url.URL {
	t.Helper()
	c, cb := e.startLogin(t, extra)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("callback: %d %s", res.StatusCode, b)
	}
	cleared := false
	for _, rc := range res.Cookies() {
		cleared = cleared || (rc.Name == c.Name && rc.MaxAge < 0)
	}
	if !cleared {
		t.Fatalf("callback did not clear the login cookie: %v", res.Header.Values("Set-Cookie"))
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	return back
}

func (e *env) redeem(t *testing.T, code string, override url.Values) (*http.Response, map[string]any) {
	t.Helper()
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {clientCB}, "client_id": {clientID}, "code_verifier": {verifier}}
	for k, v := range override {
		f[k] = v
	}
	var res *http.Response
	if u := f.Get("__basic"); u != "" {
		f.Del("__basic")
		res = e.doBasic(t, "/token", f, u)
	} else {
		res = e.do(t, "POST", "/token", f, nil)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func TestStaticClientSignsInWithEntraAndGetsAProxyToken(t *testing.T) {
	e := newEnv(t)
	back := e.signIn(t, nil)
	q := back.Query()
	if !strings.HasPrefix(back.String(), clientCB+"?") || q.Get("state") != "client-state" || q.Get("iss") != issuer || !strings.HasPrefix(q.Get("code"), token.CodePrefix) {
		t.Fatalf("redirect back = %s", back)
	}
	res, body := e.redeem(t, q.Get("code"), nil)
	if res.StatusCode != 200 || body["token_type"] != "Bearer" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token: %d %v", res.StatusCode, body)
	}
	v, _ := token.NewValidator(e.sealer, e.b.Deny(), func() time.Time { return e.now })
	id, err := v.Validate(context.Background(), body["access_token"].(string))
	if err != nil || !strings.Contains(id.Subject, ":") {
		t.Fatalf("validate: %+v %v", id, err)
	}
	g, err := e.st.Grant(context.Background(), firstGrant(e.st))
	if err != nil || g.Subject != id.Subject || g.ClientID != clientID {
		t.Fatalf("grant %+v err %v", g, err)
	}
	plain, err := e.idpBox.Open(string(g.IdPTokens))
	if err != nil {
		t.Fatalf("stored IdP tokens do not open with the IdP-token box: %v", err)
	}
	var toks idp.Tokens
	if err := json.Unmarshal(plain, &toks); err != nil || strings.Count(toks.IDToken, ".") != 2 || toks.AccessToken == "" {
		t.Fatalf("stored IdP tokens decode to %v (err %v), want the IdP's ID and access tokens", toks, err)
	}
	if bytes.Contains(g.IdPTokens, []byte(toks.IDToken)) {
		t.Fatal("the raw ID token is stored in the clear")
	}
}

func firstGrant(m *memStore) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.ids) == 0 {
		return ""
	}
	return m.ids[0]
}

func TestReusedCodeRevokesTheGrant(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, nil).Query().Get("code")
	grant := firstGrant(e.st)
	_, first := e.redeem(t, code, nil)
	res, body := e.redeem(t, code, nil)
	if res.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", res.StatusCode, body)
	}
	v, _ := token.NewValidator(e.sealer, e.b.Deny(), func() time.Time { return e.now })
	if _, err := v.Validate(context.Background(), first["access_token"].(string)); err == nil {
		t.Fatal("the first access token still works after the code was reused")
	}
	if _, err := e.st.Grant(context.Background(), grant); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("grant still in the store after the code was reused: %v", err)
	}
}

func TestTokenEndpointRechecks(t *testing.T) {
	cases := []struct {
		name     string
		override url.Values
		want     string
		status   int
	}{
		{"wrong verifier", url.Values{"code_verifier": {strings.Repeat("x", 43)}}, "invalid_grant", 400},
		{"Basic user that does not decode", url.Values{"__basic": {"%zz"}}, "invalid_client", 401},
		{"Basic user differs from the form client_id", url.Values{"__basic": {otherClientID}}, "invalid_client", 401},
		{"wrong redirect", url.Values{"redirect_uri": {"http://127.0.0.1:43210/other"}}, "invalid_grant", 400},
		{"unknown client", url.Values{"client_id": {"nope"}}, "invalid_client", 401},
		{"foreign resource", url.Values{"resource": {"https://other.example/mcp"}}, "invalid_target", 400},
		{"refresh not yet", url.Values{"grant_type": {"refresh_token"}}, "unsupported_grant_type", 400},
		{"client credentials never", url.Values{"grant_type": {"client_credentials"}}, "unsupported_grant_type", 400},
		{"garbage code", url.Values{"code": {"mcpap_ac_garbage"}}, "invalid_grant", 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			code := e.signIn(t, nil).Query().Get("code")
			res, body := e.redeem(t, code, c.override)
			if res.StatusCode != c.status || body["error"] != c.want || !strings.Contains(body["error_description"].(string), "reference") {
				t.Fatalf("got %d %v", res.StatusCode, body)
			}
		})
	}
}

func TestExpiredCodeIsRejected(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, nil).Query().Get("code")
	e.now = e.now.Add(CodeLifetime + time.Second)
	if res, body := e.redeem(t, code, nil); res.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("got %d %v", res.StatusCode, body)
	}
}

func TestAuthorizeErrors(t *testing.T) {
	e := newEnv(t)
	base := url.Values{"client_id": {clientID}, "redirect_uri": {clientCB}, "response_type": {"code"},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"s"}}
	with := func(k, v string) string {
		q := url.Values{}
		for kk, vv := range base {
			q[kk] = vv
		}
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
		return "/authorize?" + q.Encode()
	}
	// Bad client or redirect: an error page, never a redirect (no open redirector).
	for p, title := range map[string]string{
		with("client_id", "nope"):                       "This app is not registered with the proxy.",
		with("redirect_uri", "https://evil.example/cb"): "This app asked to return to an address the proxy does not allow.",
	} {
		res := e.do(t, "GET", p, nil, nil)
		if res.StatusCode != 400 || res.Header.Get("Location") != "" || !strings.Contains(res.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d location=%q", p, res.StatusCode, res.Header.Get("Location"))
		}
		if got := pageTitle(t, res); got != title {
			t.Fatalf("%s: page %q, want %q", p, got, title)
		}
	}
	// Everything else redirects back with error, state and iss.
	for p, code := range map[string]string{
		with("response_type", "token"):         "unsupported_response_type",
		with("code_challenge_method", "plain"): "invalid_request",
		with("code_challenge", ""):             "invalid_request",
		with("resource", "https://other/mcp"):  "invalid_target",
		with("scope", "admin"):                 "invalid_scope",
	} {
		res := e.do(t, "GET", p, nil, nil)
		loc, _ := url.Parse(res.Header.Get("Location"))
		if res.StatusCode != 302 || loc.Query().Get("error") != code || loc.Query().Get("iss") != issuer || loc.Query().Get("state") != "s" {
			t.Fatalf("%s: %d %s", p, res.StatusCode, loc)
		}
	}
}

func TestAuthorizeAcceptsOurResource(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, url.Values{"resource": {resourceID}}).Query().Get("code")
	if res, body := e.redeem(t, code, url.Values{"resource": {resourceID}}); res.StatusCode != 200 {
		t.Fatalf("token: %d %v", res.StatusCode, body)
	}
}

func TestRepeatedScopesAreGrantedOnce(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, url.Values{"scope": {"mcp offline_access mcp"}}).Query().Get("code")
	if res, body := e.redeem(t, code, nil); res.StatusCode != 200 || body["scope"] != "mcp offline_access" {
		t.Fatalf("token: %d scope=%v", res.StatusCode, body["scope"])
	}
}

func TestWithoutStateTheRedirectBackHasNoState(t *testing.T) {
	e := newEnv(t)
	back := e.signIn(t, url.Values{"state": nil})
	if back.Query().Has("state") || back.Query().Get("code") == "" {
		t.Fatalf("redirect back = %s", back)
	}
}

func TestErrorPageEscapesInputAndIsLockedDown(t *testing.T) {
	e := newEnv(t)
	q := url.Values{"client_id": {clientID}, "redirect_uri": {clientCB + `"><script>x</script>`}}
	res := e.do(t, "GET", "/authorize?"+q.Encode(), nil, nil)
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 400 || bytes.Contains(b, []byte("<script>")) || !bytes.Contains(b, []byte("&lt;script&gt;")) {
		t.Fatalf("got %d %s", res.StatusCode, b)
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers %v", res.Header)
	}
}

func TestCallbackRejectsALoginItCannotTrust(t *testing.T) {
	const (
		expired  = "This sign-in has expired."
		noCookie = "This sign-in has expired or was started in another browser."
	)
	cases := []struct {
		name  string
		setup func(e *env, c *http.Cookie, q url.Values) []*http.Cookie
		title string
	}{
		{"no login cookie", func(*env, *http.Cookie, url.Values) []*http.Cookie { return nil }, noCookie},
		{"login cookie expired", func(e *env, c *http.Cookie, _ url.Values) []*http.Cookie {
			e.now = e.now.Add(LoginLifetime + time.Second)
			return []*http.Cookie{c}
		}, expired},
		{"login cookie tampered", func(_ *env, c *http.Cookie, _ url.Values) []*http.Cookie { //nolint:gosec // G124: a client-side copy of the broker's cookie, sent back with a tampered value
			v := []byte(c.Value)
			i := len(v) / 2
			if v[i] == 'A' {
				v[i] = 'B'
			} else {
				v[i] = 'A'
			}
			c.Value = string(v)
			return []*http.Cookie{c}
		}, expired},
		{"state differs after the cookie-name prefix", func(_ *env, c *http.Cookie, q url.Values) []*http.Cookie {
			st := []byte(q.Get("state"))
			if st[20] == '0' {
				st[20] = '1'
			} else {
				st[20] = '0'
			}
			q.Set("state", string(st))
			return []*http.Cookie{c}
		}, expired},
		{"state too short", func(_ *env, c *http.Cookie, q url.Values) []*http.Cookie {
			q.Set("state", "short")
			return []*http.Cookie{c}
		}, "This sign-in link is not valid."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			cookie, cb := e.startLogin(t, nil)
			q := cb.Query()
			cookies := c.setup(e, cookie, q)
			res := e.do(t, "GET", "/callback/entra?"+q.Encode(), nil, cookies)
			if got := pageTitle(t, res); res.StatusCode != 400 || got != c.title {
				t.Fatalf("got %d %q, want 400 %q", res.StatusCode, got, c.title)
			}
			if firstGrant(e.st) != "" {
				t.Fatal("a grant was created")
			}
		})
	}
}

func TestUserDeclinedAtTheIdPGoesBackToTheClient(t *testing.T) {
	e := newEnv(t)
	f := fakeidp.UserNotAssigned // error=access_denied
	e.fake.Set(fakeidp.FailAuthorize(&f))
	c, cb := e.startLogin(t, nil)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	loc, _ := url.Parse(res.Header.Get("Location"))
	q := loc.Query()
	if res.StatusCode != 302 || !strings.HasPrefix(loc.String(), clientCB+"?") || q.Get("error") != "access_denied" || q.Get("iss") != issuer || q.Get("state") != "client-state" {
		t.Fatalf("got %d %s", res.StatusCode, loc)
	}
}

func TestIdPTokenExchangeFailureShowsAPageWithAReference(t *testing.T) {
	e := newEnv(t)
	f := fakeidp.TemporarilyUnavailable
	e.fake.Set(fakeidp.FailToken(fakeidp.GrantAuthorizationCode, &f))
	c, cb := e.startLogin(t, nil)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	b, _ := io.ReadAll(res.Body)
	ref := res.Header.Get("X-Request-Id")
	if res.StatusCode != http.StatusBadGateway || ref == "" || !bytes.Contains(b, []byte("Reference: <code>"+ref+"</code>")) {
		t.Fatalf("got %d ref=%q %s", res.StatusCode, ref, b)
	}
	if firstGrant(e.st) != "" {
		t.Fatal("a grant was created")
	}
}

func TestMetadataAdvertisesTheBroker(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		res := e.do(t, "GET", p, nil, nil)
		var m map[string]any
		_ = json.NewDecoder(res.Body).Decode(&m)
		if m["issuer"] != issuer || m["token_endpoint"] != issuer+"/token" || m["authorization_response_iss_parameter_supported"] != true {
			t.Fatalf("%s: %v", p, m)
		}
	}
}

func TestCORSAndMethods(t *testing.T) {
	const md, origin = "/.well-known/oauth-authorization-server", "https://app.example"
	cases := []struct {
		name, method, path string
		status             int
		headers            map[string]string // "" means the header must be absent
	}{
		{"metadata preflight", "OPTIONS", md, 204, map[string]string{"Access-Control-Allow-Origin": origin, "Vary": "Origin", "Access-Control-Allow-Credentials": ""}},
		{"metadata POST", "POST", md, 405, map[string]string{"Allow": "GET, HEAD, OPTIONS"}},
		{"metadata HEAD", "HEAD", md, 200, map[string]string{"Access-Control-Allow-Origin": origin}},
		{"token GET", "GET", "/token", 405, map[string]string{"Allow": "POST, OPTIONS"}},
	}
	e := newEnv(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(c.method, e.srv.URL+c.path, nil)
			r.Header.Set("Origin", origin)
			res := e.send(t, r)
			if res.StatusCode != c.status {
				t.Fatalf("status %d, want %d", res.StatusCode, c.status)
			}
			for k, want := range c.headers {
				if got := res.Header.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestPKCE(t *testing.T) {
	if pkceMatches(verifier+"x", challenge()) || pkceMatches(verifier, "") {
		t.Fatal("a wrong verifier or an empty challenge matched")
	}
	for n, want := range map[int]bool{42: false, 43: true, 128: true, 129: false} {
		v := strings.Repeat("a", n)
		if got := pkceMatches(v, challengeFor(v)); got != want {
			t.Errorf("verifier of %d characters: matches=%v, want %v", n, got, want)
		}
	}
}

func TestFailedBindingAfterConsumeRevokesTheGrant(t *testing.T) {
	for name, override := range map[string]url.Values{
		"wrong verifier":                {"code_verifier": {strings.Repeat("x", 43)}},
		"wrong redirect":                {"redirect_uri": {"http://127.0.0.1:43210/other"}},
		"code issued to another client": {"client_id": {otherClientID}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			code := e.signIn(t, nil).Query().Get("code")
			grant := firstGrant(e.st)
			if res, body := e.redeem(t, code, override); res.StatusCode != 400 || body["error"] != "invalid_grant" {
				t.Fatalf("got %d %v", res.StatusCode, body)
			}
			if _, err := e.st.Grant(context.Background(), grant); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("grant still exists after a misused code: %v", err)
			}
			if denied, _ := e.b.Deny().Denied(grant, "", time.Time{}); !denied {
				t.Fatal("grant not on the deny list")
			}
		})
	}
}
