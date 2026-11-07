package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/token"
)

const (
	issuer        = "https://mcp.example.com"
	resourceID    = "https://mcp.example.com/mcp"
	clientID      = "static-client"
	otherClientID = "other-client"
	clientCB      = "http://127.0.0.1:43210/callback"
	webClientID   = "web-client"
	unverifiedID  = "unverified-client"
	hostileName   = "Free \u202eTools\x1b[0m Helper"
	webCB         = "https://app.example.org/oauth/callback"
	loopbackID    = "loopback-client" // registered without a port, so any loopback port matches (ADR-0009 §2)
	loopbackCB    = "http://127.0.0.1/callback"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// memStore is the in-memory store, recording created grant IDs so tests can find "the" grant.
type memStore struct {
	*memory.Store
	mu   sync.Mutex
	ids  []string
	down atomic.Bool // every lookup and write fails, as in a store outage
	// revokeDown fails only RevokeGrant, rotateDown only RotateRefreshToken; reuseOnRotate makes
	// RotateRefreshToken report reuse without recording it, as when another replica won the race.
	revokeDown, rotateDown, reuseOnRotate atomic.Bool
	rememberDown                          atomic.Bool // RememberConsent fails
	// rewriteBlob, when set, replaces a new grant's sealed IdP-token blob, e.g. with the layout an
	// older proxy wrote.
	rewriteBlob func([]byte) []byte
	createDown  atomic.Bool // CreateGrant fails
	putCodeDown atomic.Bool // PutCode fails
	spendDown   atomic.Bool // SpendLogin fails
	consentDown atomic.Bool // Consent fails: the remembered-consent check, while the rest of the store works
}

var errStoreDown = errors.New("store down")

func (m *memStore) RefreshToken(ctx context.Context, h [32]byte, now time.Time) (store.RefreshToken, error) {
	if m.down.Load() {
		return store.RefreshToken{}, errStoreDown
	}
	return m.Store.RefreshToken(ctx, h, now)
}

func (m *memStore) RememberConsent(ctx context.Context, c store.Consent) error {
	if m.down.Load() || m.rememberDown.Load() {
		return errStoreDown
	}
	return m.Store.RememberConsent(ctx, c)
}

func (m *memStore) Consent(ctx context.Context, k store.ConsentKey) (store.Consent, error) {
	if m.down.Load() || m.consentDown.Load() {
		return store.Consent{}, errStoreDown
	}
	return m.Store.Consent(ctx, k)
}

func (m *memStore) Grant(ctx context.Context, id string) (store.Grant, error) {
	if m.down.Load() {
		return store.Grant{}, errStoreDown
	}
	return m.Store.Grant(ctx, id)
}

func (m *memStore) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	if m.down.Load() || m.revokeDown.Load() {
		return errStoreDown
	}
	return m.Store.RevokeGrant(ctx, id, at)
}

func (m *memStore) RotateRefreshToken(ctx context.Context, r store.RotateRequest) error {
	if m.down.Load() || m.rotateDown.Load() {
		return errStoreDown
	}
	if m.reuseOnRotate.Load() {
		return store.ErrReused
	}
	return m.Store.RotateRefreshToken(ctx, r)
}

// SetIdPTokens fails on a cancelled context, as the SQL store does.
func (m *memStore) SetIdPTokens(ctx context.Context, id string, sealed []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.Store.SetIdPTokens(ctx, id, sealed)
}

func (m *memStore) SpendLogin(ctx context.Context, h [32]byte, now, expiresAt time.Time) error {
	if m.down.Load() || m.spendDown.Load() {
		return errStoreDown
	}
	return m.Store.SpendLogin(ctx, h, now, expiresAt)
}

func (m *memStore) PutCode(ctx context.Context, c store.PendingCode) error {
	if m.putCodeDown.Load() {
		return errStoreDown
	}
	return m.Store.PutCode(ctx, c)
}

func newMemStore() *memStore { return &memStore{Store: memory.New()} }

func (m *memStore) CreateGrant(ctx context.Context, g store.Grant) (store.Grant, error) {
	if m.createDown.Load() {
		return store.Grant{}, errStoreDown
	}
	if m.rewriteBlob != nil {
		g.IdPTokens = m.rewriteBlob(g.IdPTokens)
	}
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
type staticClient struct {
	id, redirect, name string
	trust              registration.TrustLevel
	anyPort            bool // match the redirect as ADR-0009 does, any loopback port
}

func (c staticClient) ID() string                     { return c.id }
func (c staticClient) Name() string                   { return c.name }
func (c staticClient) Trust() registration.TrustLevel { return c.trust }
func (staticClient) AllowsRefresh() bool              { return true }

func (staticClient) AuthMethods() []registration.AuthMethod {
	return []registration.AuthMethod{registration.None}
}
func (c staticClient) RedirectAllowed(u string) error {
	if c.anyPort {
		return registration.MatchRedirect([]string{c.redirect}, u)
	}
	if u != c.redirect {
		return errors.New("registered " + c.redirect + ", sent " + u)
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
	// Mirrors registration's private_key_jwt rule: the assertion's sub (and iss) must be the client.
	if as := f.Get("client_assertion"); as != "" && assertionSubject(as) != c.id {
		return errors.New("assertion subject mismatch")
	}
	return nil
}

// registry knows clientID and otherClientID (loopback) and webClientID (https). A test can remove
// a client or change its redirect URI, as an operator would between page and answer.
type registry struct {
	mu       sync.Mutex
	removed  map[string]bool
	redirect map[string]string
	demoted  map[string]bool // clients whose trust the operator withdrew: NotVerified
	down     bool            // every lookup fails, as a store outage would
}

func (r *registry) Client(_ context.Context, id string) (registration.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return nil, errors.New("registry unavailable")
	}
	if r.removed[id] {
		return nil, registration.ErrUnknownClient
	}
	cb := map[string]string{clientID: clientCB, otherClientID: clientCB, webClientID: webCB, unverifiedID: clientCB, loopbackID: loopbackCB}[id]
	if alt, ok := r.redirect[id]; ok {
		cb = alt // a changed redirect, or a client a test added with reregister
	}
	if cb == "" {
		return nil, registration.ErrUnknownClient
	}
	if r.demoted[id] {
		return staticClient{id: id, redirect: cb, name: "Test app", trust: registration.NotVerified}, nil
	}
	if id == loopbackID {
		return staticClient{id: id, redirect: loopbackCB, name: "Loopback app", trust: registration.Verified, anyPort: true}, nil
	}
	if id == unverifiedID {
		return staticClient{id: id, redirect: cb, name: hostileName, trust: registration.NotVerified}, nil
	}
	return staticClient{id: id, redirect: cb, name: "Test app", trust: registration.Verified}, nil
}

func (r *registry) fail() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = true
}

// demote withdraws a client's trust, as removing its host from the trusted list does.
func (r *registry) demote(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.demoted == nil {
		r.demoted = map[string]bool{}
	}
	r.demoted[id] = true
}

func (r *registry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed[id] = true
}

func (r *registry) reregister(id, redirect string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.redirect[id] = redirect
}

type env struct {
	srv    *httptest.Server
	b      *Broker
	st     *memStore
	sealer *token.Sealer
	cfg    Config // as passed to New
	idpBox *token.Box
	keyDir string // the broker's sealing keys; a test may rotate them (rotateKeys)
	fake   *fakeidp.IdP
	reg    *registry
	now    time.Time
	audit  *syncBuffer // the audit stream, JSON lines
	logs   *syncBuffer // the operator log, JSON lines
	idpOps []string    // "operation outcome" per IdP call
}

// syncBuffer collects the broker's log lines across handler goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// keyRing writes one sealing key, k1, into a new directory and loads it.
func keyRing(t *testing.T) (*token.KeyRing, string) {
	t.Helper()
	dir := t.TempDir()
	addKey(t, dir, "k1")
	r, err := token.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func addKey(t *testing.T, dir, id string) {
	t.Helper()
	k := make([]byte, token.KeySize)
	_, _ = rand.Read(k)
	if err := os.WriteFile(filepath.Join(dir, id), []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newEnv builds a broker against the fake IdP; opts adjust its Config before New.
func newEnv(t *testing.T, opts ...func(*Config)) *env {
	t.Helper()
	e := &env{now: t0, st: newMemStore(), audit: &syncBuffer{}, logs: &syncBuffer{},
		reg: &registry{removed: map[string]bool{}, redirect: map[string]string{}}}
	clock := func() time.Time { return e.now }
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{issuer + "/callback/entra"}}
	e.fake = fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app), fakeidp.WithClock(clock))
	prov, err := entra.New(entra.Config{Tenant: e.fake.TenantID(), ClientID: app.ID, ClientAuth: idp.ClientSecret("s3cret"),
		RedirectURL: issuer + "/callback/entra", HTTPClient: e.fake.HTTPClient(), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	ring, keyDir := keyRing(t)
	e.keyDir = keyDir
	res, _ := url.Parse(resourceID)
	e.sealer, _ = token.NewSealer(ring, resourceID)
	login, _ := token.NewBox(ring, "login", clock)
	consent, _ := token.NewBox(ring, "consent", clock)
	e.idpBox, _ = token.NewBox(ring, "idp-tokens", clock)
	// The production loggers, so tests see only the attributes their allowlist keeps.
	cfg := Config{Issuer: issuer, Origin: issuer, Resource: res, Scope: "mcp", IdPName: "entra", IdPLabel: "Microsoft Entra",
		IdPScopes: prov.Scope(), IdP: prov, Clients: e.reg, Store: e.st, Sealer: e.sealer, LoginBox: login, IdPTokenBox: e.idpBox,
		ConsentBox: consent, SecureCookies: true, Log: logging.New(e.logs, "json"),
		Audit: audit.New(logging.New(e.audit, "json"), nil, clock), Now: clock,
		ObserveIdP: func(op, outcome string, _ time.Duration) { e.idpOps = append(e.idpOps, op+" "+outcome) }}
	for _, o := range opts {
		o(&cfg)
	}
	e.start(t, cfg)
	return e
}

// start builds the broker from cfg, syncs its deny list and serves it, as the proxy does at
// startup.
func (e *env) start(t *testing.T, cfg Config) {
	t.Helper()
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Deny().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.cfg, e.b = cfg, b
	mux := http.NewServeMux()
	e.b.Register(mux)
	// The logging middleware gives each request the ID that error pages show as the reference.
	e.srv = httptest.NewTLSServer(logging.Middleware(slog.New(slog.NewTextHandler(io.Discard, nil)), mux))
	t.Cleanup(e.srv.Close)
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

// authorizeQuery is a valid authorization request; a nil value in extra removes that parameter.
func authorizeQuery(extra url.Values) url.Values {
	q := url.Values{"client_id": {clientID}, "redirect_uri": {clientCB}, "response_type": {"code"},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"client-state"}}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

// consentPage is a shown consent page: its sealed flow and the binding cookie.
type consentPage struct {
	flow      string
	binding   *http.Cookie
	body      string
	requestID string // the X-Request-Id of the page's response
}

var flowRE = regexp.MustCompile(`name="flow" value="([^"]+)"`)

// showConsent runs /authorize and returns the consent page it shows.
func (e *env) showConsent(t *testing.T, extra url.Values) consentPage {
	t.Helper()
	res := e.do(t, "GET", "/authorize?"+authorizeQuery(extra).Encode(), nil, nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorize: %d %s", res.StatusCode, body)
	}
	m := flowRE.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no consent form in %s", body)
	}
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("authorize set %d cookies, want the binding cookie only", len(cookies))
	}
	return consentPage{flow: html.UnescapeString(string(m[1])), binding: cookies[0], body: string(body), requestID: res.Header.Get("X-Request-Id")}
}

// answer posts the consent form as the browser would: our Origin, same-origin, the binding cookie.
// headers replaces request headers; an empty value removes one.
func (e *env) answer(t *testing.T, p consentPage, action string, headers http.Header) *http.Response {
	t.Helper()
	r, _ := http.NewRequest("POST", e.srv.URL+"/consent", strings.NewReader(url.Values{"flow": {p.flow}, "action": {action}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", issuer)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range headers {
		if len(v) == 0 || v[0] == "" {
			r.Header.Del(k)
		} else {
			r.Header[http.CanonicalHeaderKey(k)] = v
		}
	}
	if p.binding != nil {
		r.AddCookie(p.binding)
	}
	return e.send(t, r)
}

// startLogin runs /authorize → consent (Allow, after the delay) → fake Entra (auto-login) and
// returns the login cookie and the IdP's redirect to /callback/entra.
func (e *env) startLogin(t *testing.T, extra url.Values) (*http.Cookie, *url.URL) {
	t.Helper()
	p := e.showConsent(t, extra)
	e.now = e.now.Add(ConsentDelay)
	res := e.answer(t, p, "allow", nil)
	if res.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("consent: %d %s", res.StatusCode, b)
	}
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("consent set %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if !strings.HasPrefix(c.Name, "__Host-byw_login_") || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
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
	secrets, err := unmarshalSecrets(plain)
	toks := secrets.Tokens
	if err != nil || strings.Count(toks.IDToken, ".") != 2 || toks.AccessToken == "" {
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
		{"refresh without a refresh token", url.Values{"grant_type": {"refresh_token"}}, "invalid_grant", 400},
		{"client credentials never", url.Values{"grant_type": {"client_credentials"}}, "unsupported_grant_type", 400},
		{"garbage code", url.Values{"code": {"byw_ac_garbage"}}, "invalid_grant", 400},
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
		spent bool // the login cookie sent is expired in the answer
	}{
		{"no login cookie", func(*env, *http.Cookie, url.Values) []*http.Cookie { return nil }, noCookie, false},
		{"login cookie expired", func(e *env, c *http.Cookie, _ url.Values) []*http.Cookie {
			e.now = e.now.Add(LoginLifetime + time.Second)
			return []*http.Cookie{c}
		}, expired, true},
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
		}, expired, true},
		{"state differs after the cookie-name prefix", func(_ *env, c *http.Cookie, q url.Values) []*http.Cookie {
			st := []byte(q.Get("state"))
			if st[20] == '0' {
				st[20] = '1'
			} else {
				st[20] = '0'
			}
			q.Set("state", string(st))
			return []*http.Cookie{c}
		}, expired, true},
		{"state too short", func(_ *env, c *http.Cookie, q url.Values) []*http.Cookie {
			q.Set("state", "short")
			return []*http.Cookie{c}
		}, "This sign-in link is not valid.", false},
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
			// A login cookie the state names is spent whether or not it opens (a state too short to name
			// one leaves the cookie alone); a browser deletes it only for the same name and path.
			if c.spent {
				var spent bool
				for _, set := range res.Cookies() {
					spent = spent || (set.Name == cookie.Name && set.Path == "/" && set.MaxAge < 0)
				}
				if !spent {
					t.Fatalf("the login cookie was not expired: %v", res.Cookies())
				}
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
			presenter := clientID // the audit names the client that presented the code
			if c := override.Get("client_id"); c != "" {
				presenter = c
			}
			e.oneAuditEvent(t, "grant_revoked", map[string]any{"outcome": "success", "client_id": presenter, "grant_id": grant})
		})
	}
}

// failingStore fails code redemption like an outage would.
type failingStore struct{ *memStore }

func (failingStore) ConsumeCode(context.Context, string, time.Time) (store.PendingCode, error) {
	return store.PendingCode{}, errors.New("database is locked")
}

func TestStoreOutageAtRedemptionIsAServerError(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, nil).Query().Get("code")
	e.b.cfg.Store = failingStore{e.st}
	res, body := e.redeem(t, code, nil)
	if res.StatusCode != 500 || body["error"] != "server_error" {
		t.Fatalf("got %d %v", res.StatusCode, body)
	}
}

func TestAssertionSubject(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for jwt, want := range map[string]string{
		enc(`{"alg":"RS256"}`) + "." + enc(`{"sub":"static-client","iss":"static-client"}`) + ".sig": "static-client",
		"not-a-jwt":              "",
		"a.%%%.c":                "",
		"a." + enc(`[1]`) + ".c": "",
	} {
		if got := assertionSubject(jwt); got != want {
			t.Errorf("%q: got %q want %q", jwt, got, want)
		}
	}
}

func assertionFor(sub string) string {
	enc := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
	return enc(`{"alg":"ES256"}`) + "." + enc(`{"iss":"`+sub+`","sub":"`+sub+`"}`) + ".sig"
}

func TestAssertionWithoutClientIDFindsTheClient(t *testing.T) {
	cases := []struct {
		name, sub, code string
		status          int
	}{
		{"assertion names the client", clientID, "", 200},
		{"assertion names another client", otherClientID, "invalid_grant", 400},
		{"assertion names nobody", "unknown", "invalid_client", 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			code := e.signIn(t, nil).Query().Get("code")
			res, body := e.redeem(t, code, url.Values{"client_id": nil,
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertionFor(c.sub)}})
			if res.StatusCode != c.status || (c.code != "" && body["error"] != c.code) {
				t.Fatalf("got %d %v", res.StatusCode, body)
			}
		})
	}
}

// noAuditEvent requires that no record named name was written.
func (e *env) noAuditEvent(t *testing.T, name string) {
	t.Helper()
	if recs := e.auditEvents(t, name); len(recs) != 0 {
		t.Fatalf("want no %s record, got %v", name, recs)
	}
}

// auditEvents returns the audit records with the given event name.
func (e *env) auditEvents(t *testing.T, name string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(e.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not JSON: %s", line)
		}
		if rec["log.type"] != "audit" {
			t.Fatalf("audit line without log.type=audit: %s", line)
		}
		if rec["event"] == name {
			out = append(out, rec)
		}
	}
	return out
}

// wantFields reports each audit field that differs from want, by name. A want value of "*" means
// the field must be present and non-empty.
func wantFields(t *testing.T, what string, rec map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		got, ok := rec[k]
		switch {
		case v == "*" && (!ok || got == ""):
			t.Errorf("%s.%s is missing", what, k)
		case v != "*" && got != v:
			t.Errorf("%s.%s = %v, want %v", what, k, got, v)
		}
	}
}

// oneAuditEvent requires exactly one record named name, checks its fields and returns it.
func (e *env) oneAuditEvent(t *testing.T, name string, want map[string]any) map[string]any {
	t.Helper()
	recs := e.auditEvents(t, name)
	if len(recs) != 1 {
		t.Fatalf("want 1 %s record, got %d: %v", name, len(recs), recs)
	}
	wantFields(t, name, recs[0], want)
	return recs[0]
}

func TestSignInAndRedemptionAreAudited(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, nil).Query().Get("code")
	if _, body := e.redeem(t, code, nil); body["access_token"] == nil {
		t.Fatalf("no token: %v", body)
	}
	grant := firstGrant(e.st)
	login := e.oneAuditEvent(t, "login", map[string]any{"outcome": "success", "client_id": clientID, "grant_id": grant,
		"idp": "entra", "user_key": "*", "request_id": "*", "remote_ip": "*"})
	if !strings.Contains(fmt.Sprint(login["user_key"]), ":") {
		t.Errorf("login.user_key = %v, want the tid:oid form", login["user_key"])
	}
	e.oneAuditEvent(t, "token_issued", map[string]any{"outcome": "success", "client_id": clientID, "grant_id": grant, "user_key": login["user_key"]})
	if strings.Contains(e.audit.String(), code) || strings.Contains(e.audit.String(), token.CodePrefix) {
		t.Fatal("the authorization code reached the audit stream")
	}
	if want := []string{"authorize success", "callback success"}; fmt.Sprint(e.idpOps) != fmt.Sprint(want) {
		t.Fatalf("IdP observations = %v, want %v", e.idpOps, want)
	}
}

func TestReusedCodeIsAuditedAsARevocation(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, nil).Query().Get("code")
	grant := firstGrant(e.st)
	e.redeem(t, code, nil)
	e.redeem(t, code, nil)
	revoked := e.oneAuditEvent(t, "grant_revoked", map[string]any{"outcome": "success", "client_id": clientID, "grant_id": grant})
	if !strings.Contains(fmt.Sprint(revoked["reason"]), "reused") {
		t.Errorf("grant_revoked.reason = %v, want it to say the code was reused", revoked["reason"])
	}
	e.oneAuditEvent(t, "token_rejected", map[string]any{"outcome": "failure", "reason": "invalid_grant"})
}

// ADR-0021 §2, §7: our request ID reaches Entra as client-request-id, comes back as correlation_id,
// and the failure is logged with the IdP's error code, trace ID and correlation ID.
func TestIdPFailureIsAuditedAndCorrelatesWithTheIdP(t *testing.T) {
	e := newEnv(t)
	f := fakeidp.InvalidClientSecret // AADSTS7000215; invalid_client counts as unavailable (ADR-0011)
	e.fake.Set(fakeidp.FailToken(fakeidp.GrantAuthorizationCode, &f))
	c, cb := e.startLogin(t, nil)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	ref := res.Header.Get("X-Request-Id")
	e.oneAuditEvent(t, "login", map[string]any{"outcome": "failure", "request_id": ref, "client_id": clientID})
	for _, want := range []string{`"correlation_id":"` + ref + `"`, `"trace_id":"`, `"idp_error_code":7000215`} {
		if !strings.Contains(e.logs.String(), want) {
			t.Errorf("the IdP failure log lacks %s (our request ID must come back as Entra's correlation_id): %s", want, e.logs.String())
		}
	}
	if want := "callback unavailable"; len(e.idpOps) != 2 || e.idpOps[1] != want {
		t.Fatalf("IdP observations = %v, want the callback to be %q", e.idpOps, want)
	}
}

func TestUserDeclinedIsAuditedAsAFailedLogin(t *testing.T) {
	e := newEnv(t)
	c, cb := e.startLogin(t, nil)
	q := url.Values{"state": {cb.Query().Get("state")}, "error": {"access_denied"}, "error_description": {"declined"}}
	e.do(t, "GET", "/callback/entra?"+q.Encode(), nil, []*http.Cookie{c})
	e.oneAuditEvent(t, "login", map[string]any{"outcome": "failure", "reason": "the user declined to sign in", "client_id": clientID})
}

// stubLimiter records the addresses it is asked about and refuses the endpoints it names.
type stubLimiter struct {
	endpoints map[string]bool
	seenIPs   *[]string
}

func (l stubLimiter) Allow(endpoint, ip string) (bool, time.Duration) {
	if l.seenIPs != nil {
		*l.seenIPs = append(*l.seenIPs, endpoint+" "+ip)
	}
	if l.endpoints[endpoint] {
		return false, 1500 * time.Millisecond
	}
	return true, 0
}

// RFC 6749 §4.1.2.1: a throttled /authorize with a trusted client and redirect tells the MCP client
// at once; RFC 6585: Retry-After in whole seconds, rounded up.
func TestThrottledAuthorizeRedirectsTemporarilyUnavailableToAValidClient(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"authorize": true}}
	res := e.do(t, "GET", "/authorize?"+authorizeQuery(nil).Encode(), nil, nil)
	loc, _ := res.Location()
	if res.StatusCode != http.StatusFound || loc == nil || !strings.HasPrefix(loc.String(), clientCB+"?") {
		t.Fatalf("throttled authorize = %d to %v, want a redirect to the client", res.StatusCode, loc)
	}
	q := loc.Query()
	for k, want := range map[string]string{"error": "temporarily_unavailable", "state": "client-state", "iss": issuer} {
		if q.Get(k) != want {
			t.Errorf("redirect %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if got := res.Header.Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2 (1.5 s rounded up)", got)
	}
	if len(res.Cookies()) != 0 {
		t.Error("a throttled authorize must not start a sign-in (no login cookie)")
	}
	e.oneAuditEvent(t, "rate_limited", map[string]any{"outcome": "failure", "reason": "authorize", "remote_ip": "*"})
}

// Without a client and redirect URI we trust there is nowhere safe to send the error: a throttled
// /authorize must never become an open redirect.
func TestThrottledAuthorizeWithoutATrustedRedirectShowsThe429Page(t *testing.T) {
	for name, override := range map[string]url.Values{
		"unknown client":            {"client_id": {"nobody"}},
		"unregistered redirect URI": {"redirect_uri": {"https://evil.example/cb"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"authorize": true}}
			res := e.do(t, "GET", "/authorize?"+authorizeQuery(override).Encode(), nil, nil)
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Location") != "" {
				t.Fatalf("throttled authorize = %d (Location %q), want 429 with no redirect", res.StatusCode, res.Header.Get("Location"))
			}
			if res.Header.Get("Retry-After") != "2" || res.Header.Get("Cache-Control") != "no-store" || !bytes.Contains(body, []byte("Too many sign-in attempts")) {
				t.Fatalf("429 page: Retry-After %q, Cache-Control %q, body %s", res.Header.Get("Retry-After"), res.Header.Get("Cache-Control"), body)
			}
		})
	}
}

func TestThrottledCallbackShowsThe429PageWithoutCallingTheIdPAndKeepsTheLoginForARetry(t *testing.T) {
	e := newEnv(t)
	c, cb := e.startLogin(t, nil)
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"callback": true}}
	before := len(e.idpOps)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "2" {
		t.Fatalf("throttled callback = %d, Retry-After %q; want 429 and 2", res.StatusCode, res.Header.Get("Retry-After"))
	}
	if len(e.idpOps) != before {
		t.Errorf("the IdP was called for a throttled callback: %v", e.idpOps[before:])
	}
	if firstGrant(e.st) != "" {
		t.Error("a grant was created by a throttled callback")
	}
	e.oneAuditEvent(t, "rate_limited", map[string]any{"outcome": "failure", "reason": "callback"})
	// An interactive login is not spent by the 429: the user's retry once the limit lifts finishes it.
	for _, set := range res.Cookies() {
		if set.Name == c.Name {
			t.Fatalf("the 429 touched the login cookie: %+v", set)
		}
	}
	e.b.cfg.Limiter = nil
	if retry := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c}); retry.StatusCode != http.StatusFound || !strings.Contains(retry.Header.Get("Location"), "code=") {
		t.Fatalf("the retry after the limit lifted: %d to %q, want a code", retry.StatusCode, retry.Header.Get("Location"))
	}
}

// The user's decision (#55 follow-up design): /token answers 429 + Retry-After + no-store with a
// JSON temporarily_unavailable, before the body is read.
func TestThrottledTokenIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"token": true}}
	// A body ParseForm rejects: a 400 would mean it was read before the limit.
	r, _ := http.NewRequest("POST", e.srv.URL+"/token", strings.NewReader("grant_type=%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := e.send(t, r)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled token with a malformed body = %d, want 429 (the limit comes before parsing)", res.StatusCode)
	}
	if rejected := e.auditEvents(t, "token_rejected"); len(rejected) != 0 {
		t.Errorf("the malformed body was parsed and audited: %v", rejected)
	}
}

func TestRetrySecondsRoundsUpToWholeSecondsAtLeastOne(t *testing.T) {
	for wait, want := range map[time.Duration]int{0: 1, time.Millisecond: 1, time.Second: 1, 1500 * time.Millisecond: 2,
		2 * time.Second: 2, 2*time.Second + time.Nanosecond: 3, 20 * time.Second: 20} {
		if got := retrySeconds(wait); got != want {
			t.Errorf("retrySeconds(%v) = %d, want %d", wait, got, want)
		}
	}
}

func TestThrottledTokenAnswers429JSONAndLeavesTheCodeUnused(t *testing.T) {
	e := newEnv(t)
	code := e.signIn(t, nil).Query().Get("code")
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"token": true}}
	res, body := e.redeem(t, code, nil)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "2" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("throttled token = %d, Retry-After %q, Cache-Control %q; want 429, 2, no-store",
			res.StatusCode, res.Header.Get("Retry-After"), res.Header.Get("Cache-Control"))
	}
	if body["error"] != "temporarily_unavailable" || !strings.Contains(fmt.Sprint(body["error_description"]), "reference ") {
		t.Errorf("throttled token body = %v, want temporarily_unavailable with a reference", body)
	}
	e.oneAuditEvent(t, "rate_limited", map[string]any{"outcome": "failure", "reason": "token"})
	if rejected := e.auditEvents(t, "token_rejected"); len(rejected) != 0 {
		t.Errorf("a throttled request was also audited as token_rejected: %v", rejected)
	}
	// The code was never redeemed, so it still works once the limit lifts.
	e.b.cfg.Limiter = nil
	if res, body := e.redeem(t, code, nil); res.StatusCode != 200 {
		t.Fatalf("after the limit the code must still redeem: %d %v", res.StatusCode, body)
	}
}

func TestEveryOAuthEndpointAsksTheLimiterByClientAddress(t *testing.T) {
	e := newEnv(t)
	var seen []string
	e.b.cfg.Limiter = stubLimiter{seenIPs: &seen}
	code := e.signIn(t, nil).Query().Get("code")
	_, body := e.redeem(t, code, nil)
	e.revokeToken(t, fmt.Sprint(body["access_token"]), clientID)
	want := []string{"authorize 127.0.0.1", "consent 127.0.0.1", "callback 127.0.0.1", "token 127.0.0.1", "revoke 127.0.0.1"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("limiter asked %q, want %q (each endpoint once, by client address)", seen, want)
	}
}

// A throttled consent answer is neither read nor recorded: the user starts again after Retry-After.
func TestThrottledConsentShowsThe429PageWithoutReadingTheAnswer(t *testing.T) {
	e := newEnv(t)
	p := e.showConsent(t, nil)
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"consent": true}}
	res := e.answer(t, p, "allow", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "2" || !bytes.Contains(body, []byte("Too many sign-in attempts")) {
		t.Fatalf("throttled consent = %d, Retry-After %q; want 429, 2 and the throttle page: %s", res.StatusCode, res.Header.Get("Retry-After"), body)
	}
	e.noAuditEvent(t, "consent_granted")
	e.noAuditEvent(t, "consent_denied")
	if firstGrant(e.st) != "" {
		t.Error("a throttled consent answer led to a grant")
	}
	e.oneAuditEvent(t, "rate_limited", map[string]any{"outcome": "failure", "reason": "consent"})
}

// The method comes first: a GET to /consent is a 405 and never spends the answer budget.
func TestConsentRejectsOtherMethodsBeforeAskingTheLimiter(t *testing.T) {
	e := newEnv(t)
	var seen []string
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"consent": true}, seenIPs: &seen}
	res := e.do(t, "GET", "/consent", nil, nil)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "POST" {
		t.Fatalf("GET /consent = %d, Allow %q; want 405 with Allow: POST", res.StatusCode, res.Header.Get("Allow"))
	}
	if len(seen) != 0 {
		t.Fatalf("the limiter was asked %v for a GET /consent, want not at all", seen)
	}
}

// The user's decision: /revoke answers as /token does, 429 + Retry-After + no-store + JSON
// temporarily_unavailable, before the body is read.
func TestThrottledRevokeIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.Limiter = stubLimiter{endpoints: map[string]bool{"revoke": true}}
	r, _ := http.NewRequest("POST", e.srv.URL+"/revoke", strings.NewReader("token=%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := e.send(t, r)
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "2" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("throttled revoke = %d, Retry-After %q, Cache-Control %q; want 429, 2, no-store (and the body unread)",
			res.StatusCode, res.Header.Get("Retry-After"), res.Header.Get("Cache-Control"))
	}
	if body["error"] != "temporarily_unavailable" {
		t.Errorf("throttled revoke body = %v, want temporarily_unavailable", body)
	}
	e.noAuditEvent(t, "token_rejected")
	e.oneAuditEvent(t, "rate_limited", map[string]any{"outcome": "failure", "reason": "revoke"})
}

// Browsers drop a cookie over 4096 bytes (name, value and attributes); the sign-in would then fail
// at the callback as an expired login (#94).
func TestTheLargestRequestsFitTheLoginCookieAndComeBackUnchanged(t *testing.T) {
	prefix := "https://app.example.org/"
	maxID, maxRedirect := strings.Repeat("c", registration.MaxClientIDLen), prefix+strings.Repeat("a", registration.MaxRedirectURILen-len(prefix))
	for _, c := range []struct {
		name, redirect string
		setup          func(*env)
		query          url.Values
	}{
		// Not HTML-escaped: one byte each.
		{"a 512-character state of HTML characters", clientCB, nil, url.Values{"state": {strings.Repeat("<", maxState)}}},
		// JSON escapes each to two bytes.
		{"a 512-character state of quotes and backslashes", clientCB, nil, url.Values{"state": {strings.Repeat(`"\`, maxState/2)}}},
		{"every field at its registration limit", maxRedirect, func(e *env) { e.reg.reregister(maxID, maxRedirect) },
			url.Values{"client_id": {maxID}, "redirect_uri": {maxRedirect}, "scope": {"mcp offline_access"}, "state": {strings.Repeat("&", maxState)}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.setup != nil {
				c.setup(e)
			}
			cookie, cb := e.startLogin(t, c.query)
			if set := cookie.String(); len(set) >= 4096 {
				t.Fatalf("login cookie is %d bytes with its attributes, want under 4096", len(set))
			}
			res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{cookie})
			back, _ := url.Parse(res.Header.Get("Location"))
			if res.StatusCode != http.StatusFound || back.Scheme+"://"+back.Host+back.Path != c.redirect ||
				back.Query().Get("state") != c.query.Get("state") || back.Query().Get("code") == "" {
				t.Fatalf("callback: %d, Location %q", res.StatusCode, res.Header.Get("Location"))
			}
		})
	}
}

// The bound itself: a login of exactly maxLoginJSON bytes, sealed with the longest key ID, gives a
// login cookie (as startLogin sets it, name and attributes included) under 4096 bytes.
func TestALoginAtTheSizeBoundFitsTheBrowserCookieLimit(t *testing.T) {
	dir := t.TempDir()
	k := make([]byte, token.KeySize)
	_, _ = rand.Read(k)
	if err := os.WriteFile(filepath.Join(dir, strings.Repeat("k", 64)), []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := token.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *Config) { c.LoginBox, _ = token.NewBox(ring, "login", c.Now) })
	l := login{ClientID: clientID, RedirectURI: clientCB, Challenge: challenge(), Scopes: []string{"mcp", "offline_access"},
		IdPState: randomID() + randomID(), Nonce: randomID(), Verifier: randomID() + randomID(), State: "a"}
	base, err := encodeLogin(l)
	if err != nil {
		t.Fatal(err)
	}
	l.State = strings.Repeat("a", maxLoginJSON-len(base)+1)
	if plain, err := encodeLogin(l); err != nil || len(plain) != maxLoginJSON {
		t.Fatalf("padded login is %d bytes (%v), want exactly %d", len(plain), err, maxLoginJSON)
	}
	rec := httptest.NewRecorder()
	e.b.startLogin(rec, httptest.NewRequest("POST", issuer+"/consent", nil), l, e.now)
	set := rec.Header().Get("Set-Cookie")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(set, "__Host-byw_login_") {
		t.Fatalf("startLogin: %d, Set-Cookie %.40q", rec.Code, set)
	}
	if len(set) >= 4096 {
		t.Fatalf("a %d-byte login makes a %d-byte cookie, want under 4096", maxLoginJSON, len(set))
	}
}

func TestALoginIsKeptUpToTheSizeBoundAndRefusedOneByteOver(t *testing.T) {
	// A one-character state, so the state key is present; each further character adds one byte.
	base, err := encodeLogin(login{State: "a"})
	if err != nil {
		t.Fatal(err)
	}
	pad := maxLoginJSON - len(base) + 1
	if _, err := encodeLogin(login{State: strings.Repeat("a", pad)}); err != nil {
		t.Fatalf("a login of exactly %d bytes was refused: %v", maxLoginJSON, err)
	}
	if _, err := encodeLogin(login{State: strings.Repeat("a", pad+1)}); !errors.Is(err, errLoginTooLarge) {
		t.Fatalf("a login of %d bytes: %v, want errLoginTooLarge", maxLoginJSON+1, err)
	}
}

func TestAStateMayHoldOnlyVisibleASCIIAndSpacesOrBeEmpty(t *testing.T) {
	for s, want := range map[string]bool{"": true, " ": true, "~": true, "a b~!": true,
		"\x1f": false, "\t": false, "\x7f": false, "é": false, "\u2028": false} {
		if got := validState(s); got != want {
			t.Errorf("validState(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestAuthorizeRefusesARequestItCannotKeepInTheLoginCookie(t *testing.T) {
	prefix := "https://app.example.org/"
	// The longest client ID and redirect URI, made of characters JSON escapes.
	id, redirect := strings.Repeat(`\`, registration.MaxClientIDLen), prefix+strings.Repeat(`\`, registration.MaxRedirectURILen-len(prefix))
	for _, c := range []struct {
		name, desc string
		setup      func(*env)
		query      url.Values
	}{
		{"an invisible character in state", "state may only contain visible ASCII characters and spaces (RFC 6749 Appendix A.5)", nil,
			url.Values{"state": {"a\x01b"}}},
		{"state over 512 bytes", "state is longer than 512 bytes", nil, url.Values{"state": {strings.Repeat("a", maxState+1)}}},
		{"every field at its limit, made of characters JSON escapes", "the request is too large", func(e *env) { e.reg.reregister(id, redirect) },
			url.Values{"client_id": {id}, "redirect_uri": {redirect}, "state": {strings.Repeat(`"`, maxState)}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.setup != nil {
				c.setup(e)
			}
			res := e.do(t, "GET", "/authorize?"+authorizeQuery(c.query).Encode(), nil, nil)
			q := func() url.Values { loc, _ := url.Parse(res.Header.Get("Location")); return loc.Query() }()
			if res.StatusCode != http.StatusFound || q.Get("error") != "invalid_request" || q.Get("error_description") != c.desc ||
				q.Get("iss") != issuer || len(res.Cookies()) != 0 {
				t.Fatalf("%d %v, cookies %v", res.StatusCode, q, res.Cookies())
			}
		})
	}
}

// Collect drops revocations after store.RevocationRetention, so it must outlive what they still
// guard: access tokens (validated without a store read, so only the deny list refuses them, until
// exp plus the validator's leeway) and logins in flight when revoke-user ran (a retained cut-off
// refuses their grant). Refresh tokens need no revocation row: revoking deletes them with the
// grant (storetest RevokeGrantDeletesItsRowsAndRecordsARevocation, RevokeSubjectCutsOffEarlierGrants).
func TestRevocationsOutliveTheTokensAndLoginsTheyCover(t *testing.T) {
	for name, lifetime := range map[string]time.Duration{"access token": AccessLifetime + token.Leeway, "login": LoginLifetime} {
		if store.RevocationRetention <= lifetime {
			t.Errorf("store.RevocationRetention %v is shorter than the %s lifetime %v", store.RevocationRetention, name, lifetime)
		}
	}
}

// A login is used once on the server (#150): replaying a callback with a kept copy of the login
// cookie after it signed in, at any time the cookie still opens, gets the expired-sign-in page, not
// a second answer, and never reaches the IdP.
func TestAReplayedCallbackIsRefusedByTheServer(t *testing.T) {
	e := newEnv(t)
	c, cb := e.startLogin(t, nil)
	if res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c}); res.StatusCode != http.StatusFound {
		t.Fatalf("first callback: %d", res.StatusCode)
	}
	before := len(e.idpOps)
	e.now = e.now.Add(LoginLifetime / 2) // the sealed login still opens
	replay := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	if got := pageTitle(t, replay); replay.StatusCode != http.StatusBadRequest || got != "This sign-in has expired." {
		t.Fatalf("replay: %d %q, want 400 This sign-in has expired.", replay.StatusCode, got)
	}
	if len(e.idpOps) != before {
		t.Fatalf("the replay reached the IdP: %v", e.idpOps[before:])
	}
}

// When the used login cannot be recorded, the callback goes no further: no IdP call and no grant.
func TestACallbackWhoseLoginCannotBeRecordedStops(t *testing.T) {
	e := newEnv(t)
	c, cb := e.startLogin(t, nil)
	e.st.spendDown.Store(true)
	before := len(e.idpOps)
	if res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c}); res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("callback with the store down: %d, want 500", res.StatusCode)
	}
	if len(e.idpOps) != before || firstGrant(e.st) != "" {
		t.Fatalf("the callback went on: IdP calls %v, grant %q", e.idpOps[before:], firstGrant(e.st))
	}
}
