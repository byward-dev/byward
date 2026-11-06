//go:build integration

package server

import (
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// realClientID is the static client the real open-source clients use: public (no secret), with
// loopback redirects on any port (ADR-0009 §2), as a native client registers.
const realClientID = "real-client"

// echoTool is the upstream's one tool; a client that calls it through byward gets its text back.
// Every client asks it for realClientText.
const (
	echoTool       = "echo"
	realClientText = "hello through byward"
)

// realClientEnv is byward running in-process on a loopback port, signed in through the fake IdP
// (the Entra adapter reaches it through its HTTP client, never a configurable endpoint), in front
// of a real MCP server (go-sdk) with one tool.
type realClientEnv struct {
	// MCPURL is the protected MCP endpoint, e.g. http://127.0.0.1:41234/mcp.
	MCPURL string
	fake   *fakeidp.IdP
	public string

	// upstreamURL is BYWARD_UPSTREAM_URL, the audience of the identity assertion; proxy serves
	// the JWKS that verifies it.
	upstreamURL string
	proxy       http.Handler

	mu           sync.Mutex
	upstreamAuth []string // the Authorization header of every request the upstream received
	echoed       []string // the text of every echo call the upstream answered
}

// requireOneToolCallWithOnlyTheAssertion fails the test unless the upstream itself answered exactly
// one echo call with realClientText (what a client prints is not proof the call went through
// byward), unless every request reached it with byward's identity assertion and never the client's
// own token (AGENTS.md security rules, ADR-0016 §2), and unless byward still refuses requests
// without a token it issued.
func (e *realClientEnv) requireOneToolCallWithOnlyTheAssertion(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	echoed, auth := append([]string(nil), e.echoed...), append([]string(nil), e.upstreamAuth...)
	e.mu.Unlock()
	if len(echoed) != 1 || echoed[0] != realClientText {
		t.Fatalf("the upstream answered echo calls %q, want exactly one with %q", echoed, realClientText)
	}
	u, err := url.Parse(e.MCPURL)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks(t, e.proxy, u.Host)
	for _, h := range auth {
		raw, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || strings.HasPrefix(raw, "byw_") {
			t.Fatalf("the upstream got Authorization of %d chars that is not byward's assertion; the client's token must never pass through", len(h))
		}
		if c := verified(t, set, raw, e.upstreamURL); c["client_id"] != realClientID {
			t.Fatalf("assertion for client %v, want %s", c["client_id"], realClientID)
		}
	}
	e.requireTokenStillRequired(t)
}

// requireTokenStillRequired checks that after the sign-in byward still refuses a request with no
// token or a token it did not issue (401 with the discovery challenge), and that neither reaches
// the upstream: a lane where every client passes must not pass with token validation switched off.
func (e *realClientEnv) requireTokenStillRequired(t *testing.T) {
	t.Helper()
	for name, auth := range map[string]string{"no token": "", "a token byward did not issue": "Bearer garbage"} {
		req, _ := http.NewRequest(http.MethodPost, e.MCPURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), "resource_metadata") {
			t.Fatalf("%s: %d %q, want 401 with the resource_metadata challenge", name, res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.echoed) != 1 {
		t.Fatalf("after the refused requests the upstream has answered %d echo calls, want still 1", len(e.echoed))
	}
}

func newRealClientEnv(t *testing.T) *realClientEnv {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	public := "http://" + ln.Addr().String()
	env := &realClientEnv{MCPURL: public + "/mcp", public: public}

	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/entra"}}
	env.fake = fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app))
	captureBroker(t, func(c broker.Config) broker.Config {
		prov, err := entra.New(entra.Config{Tenant: env.fake.TenantID(), ClientID: app.ID, ClientAuth: idp.ClientSecret("s3cret"),
			RedirectURL: public + "/callback/entra", HTTPClient: env.fake.HTTPClient()})
		if err != nil {
			t.Fatal(err)
		}
		c.IdP, c.IdPScopes = prov, prov.Scope()
		return c
	})

	upstream := mcp.NewServer(&mcp.Implementation{Name: "byward-test-upstream", Version: "1.0.0"}, nil)
	type echoIn struct {
		Text string `json:"text"`
	}
	mcp.AddTool(upstream, &mcp.Tool{Name: echoTool, Description: "returns its text"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			env.mu.Lock()
			env.echoed = append(env.echoed, in.Text)
			env.mu.Unlock()
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
		})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, nil)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		env.upstreamAuth = append(env.upstreamAuth, r.Header.Get("Authorization"))
		env.mu.Unlock()
		mcpHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(up.Close)

	settings := authEnv(t)
	clients := setting(settings, "BYWARD_STATIC_CLIENTS_FILE")
	if err := os.WriteFile(clients, []byte(`{"clients":[{"client_id":"`+realClientID+`","client_name":"Real client",`+
		`"token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback","http://127.0.0.1/oauth/callback","http://localhost/callback"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// http on loopback needs --dev (ADR-0010); the relaxations it brings are irrelevant here.
	cfg, _, err := config.Load([]string{"--dev"}, append(settings, "BYWARD_PUBLIC_URL="+env.MCPURL, "BYWARD_UPSTREAM_URL="+up.URL+"/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	env.upstreamURL, env.proxy = cfg.UpstreamURL.String(), s.Public.Handler
	t.Cleanup(func() {
		if s.closeStore != nil {
			_ = s.closeStore()
		}
	})
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: s.Public.Handler, ReadHeaderTimeout: 10 * time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)
	return env
}

var consentFlow = regexp.MustCompile(`name="flow" value="([^"]+)"`)

// browse is what a user's browser does with an authorization URL: show the consent page, allow
// after the consent delay, sign in at the IdP (the fake IdP signs in at once) and follow the
// callback. It returns the client's redirect URL, with the code, without following it.
func (e *realClientEnv) browse(authorize string) (string, error) {
	if !strings.HasPrefix(authorize, e.public+"/") {
		return "", fmt.Errorf("authorization URL %q is not on byward (%s)", authorize, e.public)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	page, err := c.Get(authorize) //nolint:gosec // G704: checked above to be on byward's own loopback address
	if err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	flow := consentFlow.FindSubmatch(body)
	if page.StatusCode != http.StatusOK || flow == nil {
		return "", fmt.Errorf("consent page: %d %s", page.StatusCode, body)
	}
	time.Sleep(broker.ConsentDelay + 100*time.Millisecond) // Allow is accepted only after the delay
	form := url.Values{"flow": {html.UnescapeString(string(flow[1]))}, "action": {"allow"}}
	req, _ := http.NewRequest(http.MethodPost, e.public+"/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.public)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	toIdP, err := redirect("consent answer", http.StatusSeeOther)(c.Do(req))
	if err != nil {
		return "", err
	}
	toCallback, err := redirect("IdP sign-in", http.StatusFound)(e.fake.HTTPClient().Get(toIdP))
	if err != nil {
		return "", err
	}
	return redirect("callback", http.StatusFound)(c.Get(toCallback)) //nolint:gosec // G704: the fake IdP's redirect to byward
}

// redirect checks that a browser step answered with status and a Location, and returns it; any
// other answer is an error naming the step, with the response body.
func redirect(step string, status int) func(*http.Response, error) (string, error) {
	return func(res *http.Response, err error) (string, error) {
		if err != nil {
			return "", fmt.Errorf("%s: %w", step, err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
		_ = res.Body.Close()
		if res.StatusCode != status || res.Header.Get("Location") == "" {
			return "", fmt.Errorf("%s: %d, want %d with a Location: %s", step, res.StatusCode, status, body)
		}
		return res.Header.Get("Location"), nil
	}
}
