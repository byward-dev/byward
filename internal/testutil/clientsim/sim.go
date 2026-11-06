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

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
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
	// ConsentDelay is how long the broker refuses an Allow after showing the consent page.
	ConsentDelay time.Duration
}

// Credentials are what the client registered with.
type Credentials struct {
	ClientID string // the static client's ID, or the CIMD document's URL
	// Signer, KeyID and Alg sign the client's assertion when it authenticates with private_key_jwt:
	// the key its jwks_uri publishes, and the algorithm its document names.
	Signer     *fakeidp.Certificate
	KeyID, Alg string
}

// Session is what a signed-in client holds.
type Session struct {
	AccessToken string
}

// metadata is what discovery found.
type metadata struct {
	prm, asm map[string]any
	scope    string // the scope the challenge named, if any
}

// SignIn drives the proxy the way p's client does, from the first unauthenticated MCP request to an
// access token, and fails t where the proxy answers differently than that client needs.
func SignIn(t *testing.T, e Env, p Profile, c Credentials) Session {
	t.Helper()
	m := discover(t, e, p)
	verifier := randomString(t)
	code := authorize(t, e, p, c, m, verifier)
	return Session{AccessToken: redeem(t, e, p, c, m, code, verifier)}
}

// discover makes the first MCP request, reads the 401, and fetches the metadata in the client's order.
func discover(t *testing.T, e Env, p Profile) metadata {
	t.Helper()
	first := e.send(t, mcpRequest(e, p, ""))
	_ = first.Body.Close()
	if first.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%s: first MCP request got %d, want 401 (the client starts sign-in only on 401)", p.Client, first.StatusCode)
	}
	var m metadata
	challenge := first.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") { // clients parse a Bearer challenge (RFC 6750 §3)
		t.Fatalf("%s: the 401's challenge %q is not a Bearer challenge", p.Client, challenge)
	}
	m.scope = param(challenge, "scope")
	var tried []string
	paths := p.Discovery
	followed := false
	if u := param(challenge, "resource_metadata"); p.UsesChallenge && u != "" {
		paths, followed = []string{e.onProxy(t, u)}, true // the challenge's URL; Discovery only without one (MCP authorization)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "/") {
			path += strings.TrimPrefix(e.MCPPath, "/")
		}
		res := e.send(t, get(e, path))
		tried = append(tried, path+" "+res.Status)
		if res.StatusCode == http.StatusOK {
			m.prm = decode(t, res)
			break
		}
		_ = res.Body.Close()
		if followed {
			t.Fatalf("%s: the challenge's resource_metadata does not answer: %v", p.Client, tried)
		}
	}
	if m.prm == nil {
		t.Fatalf("%s: no protected resource metadata in the client's order %v", p.Client, tried)
	}
	if r, _ := m.prm["resource"].(string); r != e.Public+e.MCPPath { // RFC 9728 §3.3: clients reject any other
		t.Fatalf("%s: PRM resource %q is not the URL the client called, %s", p.Client, r, e.Public+e.MCPPath)
	}
	servers, _ := m.prm["authorization_servers"].([]any)
	issuer, _ := firstString(servers)
	if issuer == "" {
		t.Fatalf("%s: PRM has no authorization_servers", p.Client)
	}
	m.asm = authServerMetadata(t, e, p, issuer)
	if m.asm["issuer"] != issuer { // RFC 8414 §3.3; OpenAI requires the exact string
		t.Fatalf("%s: authorization server metadata issuer %v is not the PRM's %q", p.Client, m.asm["issuer"], issuer)
	}
	if !slices.Contains(strs(m.asm["code_challenge_methods_supported"]), "S256") { // MCP authorization: clients MUST refuse otherwise
		t.Fatalf("%s: the metadata does not list S256 in code_challenge_methods_supported: %v", p.Client, m.asm["code_challenge_methods_supported"])
	}
	if p.NeedsIssSupported && m.asm["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("%s: the metadata does not advertise authorization_response_iss_parameter_supported; the client would not use its stable client ID", p.Client)
	}
	if p.Registration == CIMD {
		if m.asm["client_id_metadata_document_supported"] != true || (p.CIMDNeedsNone && !slices.Contains(methods(m.asm), "none")) {
			t.Fatalf("%s: the metadata does not offer CIMD the way the client needs (flag %v, methods %v); it would fall back to DCR",
				p.Client, m.asm["client_id_metadata_document_supported"], methods(m.asm))
		}
	}
	return m
}

// authServerMetadata fetches the authorization server's metadata from the issuer, RFC 8414 §3.1 path
// insertion, trying the well-known names in the client's order.
func authServerMetadata(t *testing.T, e Env, p Profile, issuer string) map[string]any {
	t.Helper()
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme+"://"+u.Host != e.Public {
		t.Fatalf("%s: the authorization server %q is not reachable through this proxy", p.Client, issuer)
	}
	for _, name := range p.ASMetadata {
		res := e.send(t, get(e, "/.well-known/"+name+strings.TrimSuffix(u.Path, "/")))
		if res.StatusCode == http.StatusOK {
			return decode(t, res)
		}
		_ = res.Body.Close()
	}
	t.Fatalf("%s: no authorization server metadata at %v for issuer %s", p.Client, p.ASMetadata, issuer)
	return nil
}

// authorize sends the user through /authorize, consent and the IdP, and returns the code.
func authorize(t *testing.T, e Env, p Profile, c Credentials, m metadata, verifier string) string {
	t.Helper()
	state := randomString(t)
	q := url.Values{"client_id": {c.ClientID}, "redirect_uri": {p.RedirectURI}, "response_type": {"code"}, "state": {state},
		"code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}}
	if s := scope(m); s != "" {
		q.Set("scope", s)
	}
	if p.AddsOfflineAccess {
		if !slices.Contains(strs(m.asm["scopes_supported"]), "offline_access") {
			t.Fatalf("%s: the metadata does not list offline_access; the client gets no refresh token and the user signs in again every hour", p.Client)
		}
		q.Set("scope", strings.TrimSpace(q.Get("scope")+" offline_access"))
	}
	if p.SendsResource {
		q.Set("resource", e.Public+e.MCPPath)
	}
	page := e.send(t, get(e, e.onProxy(t, m.asm["authorization_endpoint"])+"?"+q.Encode()))
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
	switch {
	case ret.Query().Get("state") != state: // every client rejects a callback with another state
		t.Fatalf("%s: the redirect's state %q is not the one sent", p.Client, ret.Query().Get("state"))
	case p.ChecksIss && ret.Query().Get("iss") != m.asm["issuer"]: // RFC 9207
		t.Fatalf("%s: the redirect's iss %q is not the metadata issuer %v", p.Client, ret.Query().Get("iss"), m.asm["issuer"])
	}
	return ret.Query().Get("code")
}

// redeem exchanges the code at /token the way the client authenticates there.
func redeem(t *testing.T, e Env, p Profile, c Credentials, m metadata, code, verifier string) string {
	t.Helper()
	endpoint, _ := m.asm["token_endpoint"].(string)
	tq := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {c.ClientID},
		"redirect_uri": {p.RedirectURI}, "code_verifier": {verifier}}
	if p.SendsResource {
		tq.Set("resource", e.Public+e.MCPPath)
	}
	// A client preferring private_key_jwt uses it when the server offers it (OpenAI: the intersection).
	if p.PrivateKeyJWT && slices.Contains(methods(m.asm), "private_key_jwt") {
		if c.Signer == nil {
			t.Fatalf("%s: private_key_jwt needs Credentials.Signer", p.Client)
		}
		now := time.Now()
		assertion, err := c.Signer.SignJWT(c.Alg, map[string]any{"kid": c.KeyID}, map[string]any{
			"iss": c.ClientID, "sub": c.ClientID, "aud": endpoint, "jti": randomString(t), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		tq.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		tq.Set("client_assertion", assertion)
	}
	tok := e.form(t, e.onProxy(t, endpoint), tq, nil, nil)
	defer func() { _ = tok.Body.Close() }()
	var tokens struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(tok.Body).Decode(&tokens); err != nil || tok.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("%s: /token answered %d (%v)", p.Client, tok.StatusCode, err)
	}
	if !strings.EqualFold(tokens.TokenType, "Bearer") { // RFC 6749 §5.1; OAuth libraries validate it
		t.Fatalf("%s: token_type %q, want Bearer", p.Client, tokens.TokenType)
	}
	if p.AddsOfflineAccess && tokens.RefreshToken == "" { // it asked for offline_access
		t.Fatalf("%s: no refresh_token for an offline_access request; the user would sign in again every hour", p.Client)
	}
	return tokens.AccessToken
}

// scope is the scope every profiled client sends: the challenge's, else the PRM's scopes_supported.
func scope(m metadata) string {
	if m.scope != "" {
		return m.scope
	}
	return strings.Join(strs(m.prm["scopes_supported"]), " ")
}

// strs returns the strings of a JSON array.
func strs(v any) []string {
	raw, _ := v.([]any)
	var out []string
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Call sends one JSON-RPC request to the MCP endpoint with the session's token.
func Call(t *testing.T, e Env, p Profile, s Session, body string) *http.Response {
	t.Helper()
	r := mcpRequest(e, p, body)
	r.Header.Set("Authorization", "Bearer "+s.AccessToken)
	return e.send(t, r)
}

// WantNoAuthLoop checks a response to an authenticated MCP request against what p's client does
// next: a 401 makes every client sign in again, and a 403 does too for clients that treat it as an
// auth failure, so a request the proxy accepted must not come back as either.
func WantNoAuthLoop(t testing.TB, p Profile, res *http.Response) {
	t.Helper()
	switch {
	case res.StatusCode == http.StatusForbidden && p.Treats403AsAuthFailure:
		t.Fatalf("%s: 403 to a signed-in request; the client would drop its token and sign in again", p.Client)
	case res.StatusCode == http.StatusUnauthorized:
		t.Fatalf("%s: 401 to a signed-in request; the client would sign in again", p.Client)
	}
}

func mcpRequest(e Env, p Profile, body string) *http.Request {
	if body == "" {
		body = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + p.ProtocolVersion +
			`","capabilities":{},"clientInfo":{"name":` + quote(p.Client) + `,"version":` + quote(p.Version) + `}}}`
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

// param returns a parameter of a WWW-Authenticate challenge (`name="value"`).
func param(challenge, name string) string {
	m := regexp.MustCompile(`(?:^|[ ,])` + regexp.QuoteMeta(name) + `="([^"]*)"`).FindStringSubmatch(challenge)
	if m == nil {
		return ""
	}
	return m[1]
}

func methods(asm map[string]any) []string { return strs(asm["token_endpoint_auth_methods_supported"]) }

func firstString(vs []any) (string, bool) {
	if len(vs) == 0 {
		return "", false
	}
	s, ok := vs[0].(string)
	return s, ok
}

// onProxy returns the path of an advertised URL, which must be on the proxy's public origin: the
// client goes wherever the URL says, so another host or scheme would not reach the proxy.
func (e Env) onProxy(t *testing.T, v any) string {
	t.Helper()
	s, _ := v.(string)
	u, err := url.Parse(s)
	if err != nil || s == "" || u.Scheme+"://"+u.Host != e.Public {
		t.Fatalf("advertised URL %v is not on the proxy's origin %s", v, e.Public)
	}
	return u.Path
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
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
