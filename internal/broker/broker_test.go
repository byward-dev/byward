package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/idp/entra"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/store/memory"
	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
	"github.com/corker/mcp-authproxy/internal/token"
)

const (
	issuer     = "https://mcp.example.com"
	resourceID = "https://mcp.example.com/mcp"
	clientID   = "static-client"
	clientCB   = "http://127.0.0.1:43210/callback"
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

// staticClient is a minimal in-test public client until internal/registration lands.
type staticClient struct{}

func (staticClient) ID() string                          { return clientID }
func (staticClient) Name() string                        { return "Test app" }
func (staticClient) Trust() registration.TrustLevel      { return registration.Verified }
func (staticClient) AuthMethod() registration.AuthMethod { return registration.None }
func (staticClient) RedirectAllowed(u string) error {
	if u != clientCB {
		return errors.New("registered " + clientCB + ", sent " + u)
	}
	return nil
}
func (staticClient) Authenticate(_ context.Context, f url.Values, _ http.Header, _ string, _ time.Time) error {
	if f.Get("client_id") != clientID {
		return errors.New("client_id mismatch")
	}
	return nil
}

type registry struct{}

func (registry) Client(_ context.Context, id string) (registration.Client, error) {
	if id != clientID {
		return nil, registration.ErrUnknownClient
	}
	return staticClient{}, nil
}

type env struct {
	srv    *httptest.Server
	b      *Broker
	st     *memStore
	sealer *token.Sealer
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
	idpBox, _ := token.NewBox(ring, "idp-tokens", clock)
	e.b, err = New(Config{Issuer: issuer, Resource: res, Scope: "mcp", IdPName: "entra", IdP: prov, Clients: registry{},
		Store: e.st, Sealer: e.sealer, LoginBox: login, IdPTokenBox: idpBox, SecureCookies: true,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	e.b.Register(mux)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

// client is an HTTP client for the broker that never follows redirects; requests carry the
// public host so absolute URLs line up.
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
	c := e.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func (e *env) doBasic(t *testing.T, path string, body url.Values, user string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(body.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(user, "")
	c := e.srv.Client()
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

const verifier = "verifier-0123456789-0123456789-0123456789-abc"

func challenge() string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// signIn runs /authorize → fake Entra (auto-login) → /callback/entra and returns the redirect to
// the MCP client.
func (e *env) signIn(t *testing.T, extra url.Values) *url.URL {
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
	idpRes, err := e.fake.HTTPClient().Get(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	if !strings.HasPrefix(cb.String(), issuer+"/callback/entra") {
		t.Fatalf("IdP redirected to %s", cb)
	}
	res = e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, cookies)
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("callback: %d %s", res.StatusCode, b)
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
	if err != nil || g.Subject != id.Subject || g.ClientID != clientID || len(g.IdPTokens) == 0 || strings.Contains(string(g.IdPTokens), "eyJ") {
		t.Fatalf("grant %+v err %v (IdP tokens must be sealed)", g, err)
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
	_, first := e.redeem(t, code, nil)
	res, body := e.redeem(t, code, nil)
	if res.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", res.StatusCode, body)
	}
	v, _ := token.NewValidator(e.sealer, e.b.Deny(), func() time.Time { return e.now })
	if _, err := v.Validate(context.Background(), first["access_token"].(string)); err == nil {
		t.Fatal("the first access token still works after the code was reused")
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
	for _, p := range []string{with("client_id", "nope"), with("redirect_uri", "https://evil.example/cb")} {
		if res := e.do(t, "GET", p, nil, nil); res.StatusCode != 400 || res.Header.Get("Location") != "" || !strings.Contains(res.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d location=%q", p, res.StatusCode, res.Header.Get("Location"))
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

func TestCallbackWithoutTheLoginCookieAsksToStartAgain(t *testing.T) {
	e := newEnv(t)
	res := e.do(t, "GET", "/callback/entra?state=0123456789abcdef0123&code=x", nil, nil)
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 400 || !strings.Contains(string(b), "Start again from your app") {
		t.Fatalf("got %d %s", res.StatusCode, b)
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

func TestPKCE(t *testing.T) {
	if !pkceMatches(verifier, challenge()) || pkceMatches(verifier+"x", challenge()) || pkceMatches("short", challenge()) {
		t.Fatal("pkce")
	}
}

func TestFailedBindingAfterConsumeRevokesTheGrant(t *testing.T) {
	for name, override := range map[string]url.Values{
		"wrong verifier": {"code_verifier": {strings.Repeat("x", 43)}},
		"wrong redirect": {"redirect_uri": {"http://127.0.0.1:43210/other"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			code := e.signIn(t, nil).Query().Get("code")
			grant := firstGrant(e.st)
			if res, _ := e.redeem(t, code, override); res.StatusCode != 400 {
				t.Fatalf("got %d", res.StatusCode)
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
