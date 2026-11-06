package fakeidp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testRedirect = "http://127.0.0.1:8080/callback/entra"
	testSecret   = "test-secret-value"
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// fixture is one fake IdP with the proxy's IdP app registered.
type fixture struct {
	idp    *IdP
	client Client
	tenant string // path segment for Entra endpoints
}

func newFixture(t *testing.T, profile Profile, opts ...Option) *fixture {
	t.Helper()
	c := Client{ID: NewGUID(), Secrets: []string{testSecret}, RedirectURIs: []string{testRedirect}}
	idp := New(t, profile, append([]Option{WithClient(c)}, opts...)...)
	c, _ = idp.Client(c.ID)
	return &fixture{idp: idp, client: c, tenant: idp.TenantID()}
}

func (f *fixture) ownScope() string { return "api://" + f.client.ID + "/access_as_user" }

func (f *fixture) loginScopes() string {
	return "openid profile email offline_access " + f.ownScope()
}

func noRedirects() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// authorize sends an authorization request and returns the response (no redirect followed).
func (f *fixture) authorize(t *testing.T, params url.Values) *http.Response {
	t.Helper()
	q := url.Values{
		"client_id":             {f.client.ID},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"scope":                 {f.loginScopes()},
		"state":                 {"state-1"},
		"nonce":                 {"nonce-1"},
		"code_challenge":        {s256(testVerifier)},
		"code_challenge_method": {"S256"},
	}
	for k, v := range params {
		if v == nil {
			q.Del(k)
		} else {
			q[k] = v
		}
	}
	resp, err := noRedirects().Get(f.idp.AuthorizeURL(f.tenant) + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// redirectQuery returns the query of a successful redirect back to the client.
func redirectQuery(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != testRedirect {
		t.Fatalf("redirected to %s, want %s", got, testRedirect)
	}
	return loc.Query()
}

func (f *fixture) code(t *testing.T, params url.Values) string {
	t.Helper()
	q := redirectQuery(t, f.authorize(t, params))
	if q.Get("code") == "" {
		t.Fatalf("no code in redirect: %v", q)
	}
	return q.Get("code")
}

type tokenResult struct {
	status int
	header http.Header
	body   map[string]any
}

func (r tokenResult) str(k string) string {
	s, _ := r.body[k].(string)
	return s
}

func postToken(t *testing.T, endpoint string, form url.Values, header http.Header) tokenResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("token response is not JSON: %v", err)
	}
	return tokenResult{status: resp.StatusCode, header: resp.Header, body: body}
}

// token posts form with the fixture's secret (client_secret_post) unless form sets its own auth.
func (f *fixture) token(t *testing.T, form url.Values) tokenResult {
	t.Helper()
	if !form.Has("client_assertion") && !form.Has("client_secret") {
		form.Set("client_secret", testSecret)
	}
	if !form.Has("client_id") {
		form.Set("client_id", f.client.ID)
	}
	return postToken(t, f.idp.TokenURL(f.tenant), form, nil)
}

func (f *fixture) redeem(t *testing.T, code string) tokenResult {
	t.Helper()
	return f.token(t, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {testVerifier},
	})
}

// login runs the whole code flow and returns a successful token response.
func (f *fixture) login(t *testing.T) tokenResult {
	t.Helper()
	r := f.redeem(t, f.code(t, nil))
	wantStatus(t, r, http.StatusOK)
	return r
}

func wantStatus(t *testing.T, r tokenResult, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body %v", r.status, status, r.body)
	}
}

// wantEntraError checks an AADSTS-shaped token error.
func wantEntraError(t *testing.T, r tokenResult, status int, errValue string, code int) {
	t.Helper()
	wantStatus(t, r, status)
	if got := r.str("error"); got != errValue {
		t.Errorf("error = %q, want %q", got, errValue)
	}
	codes, _ := r.body["error_codes"].([]any)
	if len(codes) != 1 || codes[0] != float64(code) {
		t.Errorf("error_codes = %v, want [%d]", r.body["error_codes"], code)
	}
	if want := "AADSTS" + itoa(code) + ":"; !strings.HasPrefix(r.str("error_description"), want) {
		t.Errorf("error_description = %q, want prefix %q", r.str("error_description"), want)
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// verified decodes a JWT after checking its RS256 signature against the IdP's published JWKS,
// independently of the fake's own JOSE code.
func (f *fixture) verified(t *testing.T, token string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	header, claims = decodePart(t, parts[0]), decodePart(t, parts[1])
	if header["alg"] != "RS256" {
		t.Fatalf("alg = %v", header["alg"])
	}
	pub := f.jwksKey(t, header["kid"].(string))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify against the JWKS: %v", err)
	}
	return header, claims
}

func (f *fixture) jwks(t *testing.T) []map[string]any {
	t.Helper()
	resp, err := http.Get(f.idp.JWKSURL(f.tenant))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	return set.Keys
}

func (f *fixture) jwksKey(t *testing.T, kid string) *rsa.PublicKey {
	t.Helper()
	for _, k := range f.jwks(t) {
		if k["kid"] != kid {
			continue
		}
		n, _ := base64.RawURLEncoding.DecodeString(k["n"].(string))
		e, _ := base64.RawURLEncoding.DecodeString(k["e"].(string))
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	t.Fatalf("kid %v not in JWKS", kid)
	return nil
}

func decodePart(t *testing.T, s string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func wantClaim(t *testing.T, claims map[string]any, k string, want any) {
	t.Helper()
	if got := claims[k]; !equalJSON(got, want) {
		t.Errorf("claim %s = %v, want %v", k, got, want)
	}
}

func equalJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func newClock() *Clock { return NewClock(time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)) }
