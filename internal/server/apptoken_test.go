package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

const callerSecret = "caller-secret"

// appProxy is the proxy, wired as in production with app-only tokens on, in front of a fake HTTP
// upstream, with a fake Entra tenant where withRole holds the MCP.Invoke app role on the proxy's
// app and noRole holds none.
type appProxy struct {
	srv              *httptest.Server
	public           http.Handler
	internal         http.Handler
	cfg              *config.Config
	env              []string
	fake             *fakeidp.IdP
	up               *fakeupstream.Server
	logs             *syncBuffer
	withRole, noRole fakeidp.Client
}

// newAppProxy builds the proxy; settings, given the proxy with its callers registered, adds or
// replaces settings (nil: none).
func newAppProxy(t *testing.T, settings func(*appProxy) []string) *appProxy {
	t.Helper()
	p := &appProxy{logs: &syncBuffer{}}
	p.withRole = fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{callerSecret}, AppRoles: map[string][]string{fixtureClientID: {"MCP.Invoke"}}}
	p.noRole = fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{callerSecret}}
	p.fake = fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}, RedirectURIs: []string{"https://mcp.example.com/callback/entra"}}),
		fakeidp.WithClient(p.withRole), fakeidp.WithClient(p.noRole))
	p.withRole, _ = p.fake.Client(p.withRole.ID)
	p.noRole, _ = p.fake.Client(p.noRole.ID)
	orig := idpHTTPClient
	idpHTTPClient = p.fake.HTTPClient()
	t.Cleanup(func() { idpHTTPClient = orig })
	p.up = fakeupstream.New()
	t.Cleanup(p.up.Close)
	upstream := p.up.URL + "/mcp"
	var extra []string
	if settings != nil {
		extra = settings(p)
	}
	extra = slices.DeleteFunc(extra, func(kv string) bool {
		u, ok := strings.CutPrefix(kv, "BYWARD_UPSTREAM_URL=")
		if ok {
			upstream = u
		}
		return ok
	})
	p.env = append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+upstream,
		"BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=MCP.Invoke")
	cfg, _, err := config.Load(nil, append(p.env, extra...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	p.cfg = cfg
	s, err := New(cfg, slog.New(slog.NewJSONHandler(p.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.closeStore() })
	p.public, p.internal = s.Public.Handler, s.Internal.Handler
	p.srv = httptest.NewServer(s.Public.Handler)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *appProxy) token(t *testing.T, c fakeidp.Client) string {
	t.Helper()
	return p.fake.AppToken(t, c.ID, callerSecret, fixtureClientID)
}

// mcp sends one MCP request with tok and returns the response, its body read.
func (p *appProxy) mcp(t *testing.T, tok string) *http.Response {
	t.Helper()
	res, _ := mcpPost(t, p.srv, tok, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	return res
}

func (p *appProxy) metric(t *testing.T, line string) bool {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	p.internal.ServeHTTP(w, r)
	return strings.Contains(w.Body.String(), line)
}

// An app with the required role reaches the upstream as a client principal: the assertion is
// byward's, for the service principal, with the caller's application ID and its app role; its
// first use is audited once and every use is counted (ADR-0022 §5, §7).
func TestAnAppWithTheRoleReachesTheUpstreamAsAClientPrincipal(t *testing.T) {
	p := newAppProxy(t, nil)
	tok := p.token(t, p.withRole)
	for range 2 {
		if res := p.mcp(t, tok); res.StatusCode != http.StatusOK {
			t.Fatalf("MCP request: %d", res.StatusCode)
		}
	}
	got, _ := p.up.Last()
	raw, _ := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
	if raw == tok {
		t.Fatal("the caller's token reached the upstream")
	}
	c := verified(t, jwks(t, p.public, "mcp.example.com"), raw, p.cfg.UpstreamURL.String())
	if c["iss"] != "https://mcp.example.com" || c["sub"] != fixtureTenant+":"+p.withRole.ServicePrincipalID || c["client_id"] != p.withRole.ID ||
		c["principal_type"] != "client" || !reflect.DeepEqual(c["roles"], []any{"MCP.Invoke"}) {
		t.Fatalf("assertion claims %v", c)
	}
	l := p.logs.String()
	if n := strings.Count(l, `"event":"app_token_accepted"`); n != 1 || !strings.Contains(l, `"user_key":"`+fixtureTenant+":"+p.withRole.ServicePrincipalID+`"`) || strings.Contains(l, tok) {
		t.Fatalf("want one app_token_accepted record naming the service principal, and no token, got %d:\n%s", n, l)
	}
	if !p.metric(t, `byward_app_tokens_total{outcome="accepted"} 2`) {
		t.Fatal("accepted app tokens not counted")
	}
	if !strings.Contains(l, "accepting Entra app-only tokens with app roles MCP.Invoke") {
		t.Fatalf("startup does not say app-only tokens are on:\n%s", l)
	}
}

// With plain identity headers on, an app reaches the upstream marked as a client there too, so an
// upstream reading only the headers never takes it for a user (ADR-0016 §5).
func TestAnAppIsAClientInThePlainIdentityHeaders(t *testing.T) {
	p := newAppProxy(t, func(*appProxy) []string { return []string{"BYWARD_IDENTITY_HEADERS=true"} })
	if res := p.mcp(t, p.token(t, p.withRole)); res.StatusCode != http.StatusOK {
		t.Fatalf("MCP request: %d", res.StatusCode)
	}
	got, _ := p.up.Last()
	if got.Header.Get(config.HeaderPrincipalType) != "client" || got.Header.Get(config.HeaderSubject) != percentEncode(fixtureTenant+":"+p.withRole.ServicePrincipalID) {
		t.Fatalf("plain headers %v", got.Header)
	}
}

// Entra issues a token to a caller with no role assignment (ADR-0022 Context); the app gate
// refuses it with 403, and nothing reaches the upstream.
func TestAnAppWithoutTheRoleIsForbiddenAndNeverReachesTheUpstream(t *testing.T) {
	p := newAppProxy(t, nil)
	res := p.mcp(t, p.token(t, p.noRole))
	if res.StatusCode != http.StatusForbidden || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`) {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	if _, reached := p.up.Last(); reached {
		t.Fatal("the upstream was reached")
	}
	if !strings.Contains(p.logs.String(), `"reason":"denied_role"`) || !p.metric(t, `byward_app_tokens_total{outcome="denied_role"} 1`) {
		t.Fatalf("refusal not recorded:\n%s", p.logs.String())
	}
}

// The client allowlist reaches the app gate from BYWARD_APP_CLIENT_IDS (azp). (The tenant rule
// cannot be reached here: a single-tenant proxy refuses other tenants' tokens before the gate.)
func TestTheAppClientAllowlistComesFromItsSetting(t *testing.T) {
	for name, tc := range map[string]struct {
		settings func(*appProxy) []string
		status   int
		reason   string
	}{
		"the caller on the client list": {func(p *appProxy) []string { return []string{"BYWARD_APP_CLIENT_IDS=" + p.withRole.ID} }, http.StatusOK, ""},
		"the caller not on it":          {func(p *appProxy) []string { return []string{"BYWARD_APP_CLIENT_IDS=" + p.noRole.ID} }, http.StatusForbidden, "denied_client"},
	} {
		t.Run(name, func(t *testing.T) {
			p := newAppProxy(t, tc.settings)
			if res := p.mcp(t, p.token(t, p.withRole)); res.StatusCode != tc.status || (tc.reason != "" && !strings.Contains(p.logs.String(), `"reason":"`+tc.reason+`"`)) {
				t.Fatalf("%d, want %d with %s:\n%s", res.StatusCode, tc.status, tc.reason, p.logs.String())
			}
		})
	}
}

// A user's delegated Entra token for the proxy's own scope is never accepted at the MCP endpoint:
// users go through the broker (ADR-0022 Consequences).
func TestAUsersEntraTokenIsRefusedAtTheMCPEndpoint(t *testing.T) {
	p := newAppProxy(t, nil)
	now := time.Now()
	delegated := p.fake.Mint(map[string]any{"iss": "https://login.microsoftonline.com/" + fixtureTenant + "/v2.0", "aud": fixtureClientID, "tid": fixtureTenant,
		"oid": fakeidp.NewGUID(), "sub": "pairwise", "azp": p.withRole.ID, "ver": "2.0", "scp": "access_as_user", "idtyp": "user", "roles": []string{"MCP.Invoke"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if res := p.mcp(t, delegated); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%d, want 401", res.StatusCode)
	}
	if !strings.Contains(p.logs.String(), `"reason":"delegated"`) {
		t.Fatalf("not recorded as delegated:\n%s", p.logs.String())
	}
}

// With app-only tokens off (the default) an app-only token is just an invalid token.
func TestAnAppTokenIsRefusedWhileAppOnlyTokensAreOff(t *testing.T) {
	caller := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{callerSecret}, AppRoles: map[string][]string{fixtureClientID: {"MCP.Invoke"}}}
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant), fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID}), fakeidp.WithClient(caller))
	tok := fake.AppToken(t, caller.ID, callerSecret, fixtureClientID)
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.closeStore() })
	srv := httptest.NewServer(s.Public.Handler)
	t.Cleanup(srv.Close)
	if res, _ := mcpPost(t, srv, tok, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); res.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(res.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
}

// An app-only token is worth nothing at the broker's OAuth endpoints (ADR-0022 §9, invariant 19):
// /token offers neither client_credentials nor jwt-bearer and takes it as no code or refresh
// token, /revoke acts on nothing, and /authorize ignores it and shows the consent page; the
// token still works at the MCP endpoint afterwards.
func TestAnAppTokenIsRefusedAtEveryOAuthEndpoint(t *testing.T) {
	p := newAppProxy(t, nil)
	tok := p.token(t, p.withRole)
	post := func(path string, form url.Values, bearer bool) (int, map[string]any) {
		r, _ := http.NewRequest(http.MethodPost, p.srv.URL+path, strings.NewReader(form.Encode()))
		r.Host = "mcp.example.com"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if bearer {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var body map[string]any
		b, _ := io.ReadAll(res.Body)
		_ = json.Unmarshal(b, &body)
		return res.StatusCode, body
	}
	for name, tc := range map[string]struct {
		path      string
		form      url.Values
		bearer    bool
		status    int
		errorCode string
	}{
		"client credentials": {"/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"test-app"}}, true, http.StatusBadRequest, "unsupported_grant_type"},
		"jwt-bearer":         {"/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {tok}, "client_id": {"test-app"}}, false, http.StatusBadRequest, "unsupported_grant_type"},
		"token exchange":     {"/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {tok}, "client_id": {"test-app"}}, false, http.StatusBadRequest, "unsupported_grant_type"},
		"as a code":          {"/token", url.Values{"grant_type": {"authorization_code"}, "code": {tok}, "client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "code_verifier": {strings.Repeat("v", 43)}}, true, http.StatusBadRequest, "invalid_grant"},
		"as a refresh token": {"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {"test-app"}}, true, http.StatusBadRequest, "invalid_grant"},
		"revoked":            {"/revoke", url.Values{"token": {tok}, "client_id": {"test-app"}}, true, http.StatusOK, ""},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := post(tc.path, tc.form, tc.bearer)
			if status != tc.status || (tc.errorCode != "" && body["error"] != tc.errorCode) || body["access_token"] != nil {
				t.Fatalf("%s: %d %v, want %d %s", tc.path, status, body, tc.status, tc.errorCode)
			}
		})
	}
	t.Run("authorize", func(t *testing.T) {
		q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"}, "scope": {"mcp"},
			"code_challenge": {pkce(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"}}
		r, _ := http.NewRequest(http.MethodGet, p.srv.URL+"/authorize?"+q.Encode(), nil)
		r.Host = "mcp.example.com"
		r.Header.Set("Authorization", "Bearer "+tok)
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(t, res)
		if res.StatusCode != http.StatusOK || !strings.Contains(body, "Allow") || res.Header.Get("Location") != "" {
			t.Fatalf("authorize with an app token: %d to %q, want the consent page", res.StatusCode, res.Header.Get("Location"))
		}
	})
	if res := p.mcp(t, tok); res.StatusCode != http.StatusOK {
		t.Fatalf("the app token stopped working at /mcp: %d", res.StatusCode)
	}
}

// revoke-user takes a service principal's tid:oid, and the app's tokens issued before it stop
// working at once, instead of only when Entra's token lifetime ends (ADR-0022 §5).
func TestRevokeUserCutsAnAppOffAtOnce(t *testing.T) {
	p := newAppProxy(t, nil)
	// The cut-off is in whole seconds and takes in its own second, so the fake's clock dates the
	// tokens clearly before and after it.
	p.fake.Set(fakeidp.WithClock(func() time.Time { return time.Now().Add(-2 * time.Second) }))
	before := p.token(t, p.withRole)
	replica := func() *auth {
		a, err := buildAuth(p.cfg, discard, Observability{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stop(t, a) })
		return a
	}
	if _, err := replica().validator.Validate(context.Background(), before); err != nil {
		t.Fatalf("before revoke-user: %v", err)
	}
	key := fixtureTenant + ":" + p.withRole.ServicePrincipalID
	if user, err := RevokeUser(context.Background(), p.cfg, discard, key); err != nil || user != key {
		t.Fatalf("RevokeUser = %q, %v", user, err)
	}
	if _, err := replica().validator.Validate(context.Background(), before); !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf("after revoke-user: %v, want invalid", err)
	}
	p.fake.Set(fakeidp.WithClock(func() time.Time { return time.Now().Add(2 * time.Second) }))
	if _, err := replica().validator.Validate(context.Background(), p.token(t, p.withRole)); err != nil {
		t.Fatalf("a token issued after the cut-off: %v", err)
	}
}

// A user and an app with the same tid:oid never share an MCP session: the session ID the user's
// initialize got is refused for the app (invariant 13).
func TestAnAppCannotResumeAUsersSessionWithTheSameSubject(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(mcpsession.Header, "upstream-session-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":0,"result":{}}`))
	}))
	t.Cleanup(up.Close)
	p := newAppProxy(t, func(*appProxy) []string { return []string{"BYWARD_UPSTREAM_URL=" + up.URL + "/mcp"} })
	key := fixtureTenant + ":" + p.withRole.ServicePrincipalID
	user := sealAccessFor(t, p.cfg, p.env, "g1", key, time.Now())
	res, _ := mcpPost(t, p.srv, user, "", initializeBody)
	session := res.Header.Get(mcpsession.Header)
	if res.StatusCode != http.StatusOK || session == "" {
		t.Fatalf("the user's initialize: %d, session %q", res.StatusCode, session)
	}
	app := p.token(t, p.withRole)
	if res, _ := mcpPost(t, p.srv, user, session, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("the user resuming their session: %d", res.StatusCode)
	}
	if res, _ := mcpPost(t, p.srv, app, session, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); res.StatusCode != http.StatusNotFound {
		t.Fatalf("the app resuming the user's session: %d, want 404", res.StatusCode)
	}
}
