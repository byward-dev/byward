package clientsim

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Env is the proxy under test as a client reaches it.
type Env struct {
	// Public is the proxy's public origin (https://mcp.example.com); MCPPath its MCP endpoint path.
	Public, MCPPath string
	// Do sends a request to the proxy and does not follow redirects.
	Do func(*http.Request) (*http.Response, error)
	// Browser follows the redirect to the IdP and returns the IdP's redirect back to the proxy, as
	// the user's browser does after the user signs in.
	Browser func(location string) (*http.Response, error)
	// ClientID is the client ID the client registered with (the static client's, or the CIMD
	// document's URL).
	ClientID string
	// ConsentDelay is how long the broker refuses an Allow after showing the consent page.
	ConsentDelay time.Duration
}

// Session is what a signed-in client holds.
type Session struct {
	AccessToken string
	Discovered  []string // the well-known paths the client requested, with their status
}

// SignIn drives the proxy the way p's client does, from the first unauthenticated MCP request to an
// access token, and fails t where the proxy answers differently than that client needs.
func SignIn(t *testing.T, e Env, p Profile) Session {
	t.Helper()
	var s Session
	first := e.send(t, mcpRequest(e, ""))
	_ = first.Body.Close()
	if first.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%s: first MCP request got %d, want 401 (the client starts sign-in only on 401)", p.Client, first.StatusCode)
	}
	challenge := first.Header.Get("WWW-Authenticate")
	if p.UsesChallenge && !strings.Contains(challenge, `resource_metadata="`) {
		t.Fatalf("%s: the 401 has no resource_metadata to follow: %q", p.Client, challenge)
	}

	var prm, asm map[string]any
	for _, path := range p.Discovery {
		if strings.HasSuffix(path, "/") {
			path += strings.TrimPrefix(e.MCPPath, "/")
		}
		res := e.send(t, get(e, path))
		s.Discovered = append(s.Discovered, path+" "+res.Status)
		if res.StatusCode != http.StatusOK {
			_ = res.Body.Close()
			continue
		}
		doc := decode(t, res)
		switch {
		case strings.HasPrefix(path, "/.well-known/oauth-protected-resource") && prm == nil:
			prm = doc
		case strings.HasPrefix(path, "/.well-known/oauth-authorization-server") && asm == nil:
			asm = doc
		}
	}
	if prm == nil || asm == nil {
		t.Fatalf("%s: discovery in its order %v found no protected resource or authorization server metadata", p.Client, s.Discovered)
	}
	servers, _ := prm["authorization_servers"].([]any)
	if len(servers) == 0 || (p.FirstAuthorizationServerOnly && servers[0] != asm["issuer"]) {
		t.Fatalf("%s: authorization_servers %v, issuer %v: the client uses the first entry only", p.Client, servers, asm["issuer"])
	}
	if p.Registration == CIMD {
		methods, _ := asm["token_endpoint_auth_methods_supported"].([]any)
		if asm["client_id_metadata_document_supported"] != true || (p.CIMDNeedsNone && !slices.Contains(methods, any("none"))) {
			t.Fatalf("%s: the metadata does not offer CIMD the way the client needs (flag %v, methods %v); it would fall back to DCR",
				p.Client, asm["client_id_metadata_document_supported"], methods)
		}
	}
	resource, _ := prm["resource"].(string)

	verifier := randomString(t)
	q := url.Values{"client_id": {e.ClientID}, "redirect_uri": {p.RedirectURI}, "response_type": {"code"}, "state": {randomString(t)},
		"code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}}
	if p.Scope != "" {
		q.Set("scope", p.Scope)
	}
	if p.SendsResource {
		q.Set("resource", resource)
	}
	page := e.send(t, get(e, pathOf(t, asm["authorization_endpoint"])+"?"+q.Encode()))
	body := readAll(t, page)
	flow := regexp.MustCompile(`name="flow" value="([^"]+)"`).FindStringSubmatch(body)
	if page.StatusCode != http.StatusOK || flow == nil {
		t.Fatalf("%s: /authorize answered %d without a consent page: %.300s", p.Client, page.StatusCode, body)
	}
	time.Sleep(e.ConsentDelay + 100*time.Millisecond) // the user reads the page; Allow works only after the delay
	allow := e.form(t, "/consent", url.Values{"flow": {html.UnescapeString(flow[1])}, "action": {"allow"}}, page.Cookies(),
		http.Header{"Origin": {e.Public}, "Sec-Fetch-Site": {"same-origin"}})
	_ = allow.Body.Close()
	if allow.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: consent Allow answered %d", p.Client, allow.StatusCode)
	}
	idp, err := e.Browser(allow.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idp.Body.Close()
	cb, err := url.Parse(idp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	back := e.send(t, withCookies(get(e, cb.Path+"?"+cb.RawQuery), allow.Cookies()))
	_ = back.Body.Close()
	ret, err := url.Parse(back.Header.Get("Location"))
	if err != nil || back.StatusCode != http.StatusFound || !strings.HasPrefix(ret.String(), p.RedirectURI) {
		t.Fatalf("%s: callback answered %d, Location %q; want the client's redirect URI %s", p.Client, back.StatusCode, back.Header.Get("Location"), p.RedirectURI)
	}
	if iss := ret.Query().Get("iss"); iss != asm["issuer"] { // RFC 9207: clients that check iss reject anything else
		t.Fatalf("%s: the redirect's iss %q is not the metadata issuer %v", p.Client, iss, asm["issuer"])
	}

	tq := url.Values{"grant_type": {"authorization_code"}, "code": {ret.Query().Get("code")}, "client_id": {e.ClientID},
		"redirect_uri": {p.RedirectURI}, "code_verifier": {verifier}}
	if p.SendsResource {
		tq.Set("resource", resource)
	}
	tok := e.form(t, pathOf(t, asm["token_endpoint"]), tq, nil, nil)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tok.Body).Decode(&tokens); err != nil || tok.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("%s: /token answered %d (%v)", p.Client, tok.StatusCode, err)
	}
	_ = tok.Body.Close()
	s.AccessToken = tokens.AccessToken
	return s
}

// Call sends one JSON-RPC request to the MCP endpoint with the session's token.
func Call(t *testing.T, e Env, s Session, body string) *http.Response {
	t.Helper()
	r := mcpRequest(e, body)
	r.Header.Set("Authorization", "Bearer "+s.AccessToken)
	return e.send(t, r)
}

// WantNoAuthLoop checks a response to an authenticated MCP request against what p's client does next:
// a client that treats 403 as an auth failure, or reruns its headersHelper on 401, would sign in or
// re-register again, so a request the proxy accepted must not come back as either.
func WantNoAuthLoop(t *testing.T, p Profile, res *http.Response) {
	t.Helper()
	switch {
	case res.StatusCode == http.StatusForbidden && p.Treats403AsAuthFailure:
		t.Fatalf("%s: 403 to a signed-in request; the client would drop its token and sign in again", p.Client)
	case res.StatusCode == http.StatusUnauthorized:
		t.Fatalf("%s: 401 to a signed-in request; the client would sign in again", p.Client)
	}
}

func mcpRequest(e Env, body string) *http.Request {
	if body == "" {
		body = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"sim","version":"0"}}}`
	}
	r, _ := http.NewRequest(http.MethodPost, e.Public+e.MCPPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r
}

func get(e Env, path string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, e.Public+path, nil)
	return r
}

func (e Env) form(t *testing.T, path string, v url.Values, cookies []*http.Cookie, h http.Header) *http.Response {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, e.Public+path, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, vs := range h {
		r.Header[k] = vs
	}
	return e.send(t, withCookies(r, cookies))
}

func (e Env) send(t *testing.T, r *http.Request) *http.Response {
	t.Helper()
	res, err := e.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func withCookies(r *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func pathOf(t *testing.T, v any) string {
	t.Helper()
	s, _ := v.(string)
	u, err := url.Parse(s)
	if err != nil || s == "" {
		t.Fatalf("metadata URL %v", v)
	}
	return u.Path
}

func decode(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	return m
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func randomString(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func s256(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
