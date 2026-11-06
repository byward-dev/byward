package idp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
)

const secretish = "tok-SECRET-value"

var fixedNow = time.Unix(1_800_000_000, 0)

func TestTokensNeverFormatTheirValues(t *testing.T) {
	tok := Tokens{IDToken: secretish, AccessToken: secretish, RefreshToken: secretish, Expiry: time.Unix(0, 0)}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "tokens", tok)
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok), fmt.Sprintf("%v", &tok), buf.String()} {
		if strings.Contains(s, secretish) {
			t.Fatalf("token leaked: %s", s)
		}
	}
	if !strings.Contains(fmt.Sprint(Tokens{}), `RefreshToken:""`) {
		t.Error("empty tokens should show as empty, not redacted")
	}
}

func TestErrorStringOmitsDescription(t *testing.T) {
	e := &Error{Class: SignInAgain, OAuth: "invalid_grant", Code: 700082, Status: 400, TraceID: "t", CorrelationID: "c",
		Description: "AADSTS700082: user test.user@contoso.example"}
	s := e.Error()
	if strings.Contains(s, "contoso") {
		t.Fatalf("Error() leaks description: %s", s)
	}
	for _, want := range []string{"sign_in_again", "invalid_grant", "700082", "trace_id=t", "correlation_id=c"} {
		if !strings.Contains(s, want) {
			t.Errorf("Error() = %q lacks %q", s, want)
		}
	}
}

func TestClassOfUnwrapsAndDefaultsToFatal(t *testing.T) {
	if ClassOf(fmt.Errorf("wrap: %w", &Error{Class: SignInAgain})) != SignInAgain || ClassOf(errors.New("x")) != Fatal {
		t.Error("ClassOf does not unwrap")
	}
}

func TestGenericClass(t *testing.T) {
	for _, tc := range []struct {
		status int
		oauth  string
		want   Class
	}{
		{500, "", Unavailable}, {503, "temporarily_unavailable", Unavailable}, {429, "", Unavailable},
		{401, "invalid_client", Unavailable}, {400, "invalid_grant", SignInAgain}, {0, "login_required", SignInAgain},
		{400, "invalid_request", Fatal}, {0, "access_denied", Fatal},
	} {
		if got := GenericClass(tc.status, tc.oauth); got != tc.want {
			t.Errorf("GenericClass(%d, %q) = %v, want %v", tc.status, tc.oauth, got, tc.want)
		}
	}
}

func TestClientSecretPostsAndRedacts(t *testing.T) {
	c := ClientSecret(secretish)
	form := url.Values{}
	if err := c.Apply(form, "cid", "aud", fixedNow); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_id") != "cid" || form.Get("client_secret") != secretish {
		t.Fatalf("form = %v", form)
	}
	if s := fmt.Sprintf("%v %+v %#v", c, c, c); strings.Contains(s, secretish) {
		t.Fatalf("secret formatted: %s", s)
	}
	if err := ClientSecret("").Apply(url.Values{}, "cid", "aud", fixedNow); err == nil {
		t.Error("empty secret accepted")
	}
}

func TestPrivateKeyJWTAssertion(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	now := time.Unix(1_800_000_000, 0)
	ca, err := PrivateKeyJWT(cert.Key, cert.X509, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	if err := ca.Apply(form, "cid", "https://idp.example/token", now); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_assertion_type") != clientAssertionType || form.Get("client_id") != "cid" || form.Has("client_secret") {
		t.Fatalf("form = %v", form)
	}
	tok, err := jwt.ParseSigned(form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatal(err)
	}
	h := tok.Headers[0]
	if h.KeyID != "kid-1" || h.ExtraHeaders["x5t#S256"] != cert.ThumbprintSHA256() || h.ExtraHeaders["typ"] != "JWT" {
		t.Fatalf("header = %+v", h)
	}
	var c jwt.Claims
	if err := tok.Claims(&cert.Key.PublicKey, &c); err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "cid" || c.Subject != "cid" || !c.Audience.Contains("https://idp.example/token") || c.ID == "" ||
		c.Expiry.Time() != now.Add(5*time.Minute) || c.NotBefore.Time() != now {
		t.Fatalf("claims = %+v", c)
	}
	form2 := url.Values{}
	if err := ca.Apply(form2, "cid", "https://idp.example/token", now); err != nil {
		t.Fatal(err)
	}
	tok2, err := jwt.ParseSigned(form2.Get("client_assertion"), []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatal(err)
	}
	var c2 jwt.Claims
	if err := tok2.Claims(&cert.Key.PublicKey, &c2); err != nil {
		t.Fatal(err)
	}
	if c2.ID == c.ID {
		t.Error("jti not unique per assertion")
	}
}

func TestPrivateKeyJWTKeyTypes(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := PrivateKeyJWT(p256, nil, ""); err != nil {
		t.Errorf("P-256: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := PrivateKeyJWT(p384, nil, ""); err == nil {
		t.Error("P-384 accepted")
	}
}

func TestAssertionFileIsReadOnEveryCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	for _, v := range []string{"first.jwt.value\n", "second.jwt.value"} {
		if err := os.WriteFile(path, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		form := url.Values{}
		if err := AssertionFile(path).Apply(form, "cid", "aud", fixedNow); err != nil {
			t.Fatal(err)
		}
		if form.Get("client_assertion") != strings.TrimSpace(v) {
			t.Fatalf("assertion = %q", form.Get("client_assertion"))
		}
	}
	_ = os.WriteFile(path, []byte(" \n"), 0o600)
	if err := AssertionFile(path).Apply(url.Values{}, "cid", "aud", fixedNow); err == nil {
		t.Error("empty assertion file accepted")
	}
	if err := AssertionFile(filepath.Join(t.TempDir(), "missing")).Apply(url.Values{}, "cid", "aud", fixedNow); err == nil {
		t.Error("missing assertion file accepted")
	}
}

func TestGetJSONRetriesOnlyTransientStatuses(t *testing.T) {
	for name, tc := range map[string]struct {
		statuses []int
		wantErr  bool
		calls    int32
	}{
		"503 then 200":    {statuses: []int{503, 200}, calls: 2},
		"429 twice, 200":  {statuses: []int{429, 429, 200}, calls: 3},
		"always 500":      {statuses: []int{500, 500, 500, 500}, wantErr: true, calls: 3},
		"404 not retried": {statuses: []int{404, 200}, wantErr: true, calls: 1},
	} {
		t.Run(name, func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				i := n.Add(1) - 1
				w.WriteHeader(tc.statuses[i])
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer srv.Close()
			f := NewFetcher(nil)
			f.Backoff = 0
			var dst map[string]bool
			err := f.GetJSON(context.Background(), srv.URL, &dst)
			if (err != nil) != tc.wantErr || n.Load() != tc.calls {
				t.Fatalf("err = %v, calls = %d; want err %v, calls %d", err, n.Load(), tc.wantErr, tc.calls)
			}
		})
	}
}

func TestFetcherBoundsBodiesAndRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(`"` + strings.Repeat("a", MaxBodyBytes) + `"`))
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/ok":
			_, _ = w.Write([]byte(`{}`))
		case "/token-html":
			w.WriteHeader(502)
			_, _ = w.Write([]byte(`<html>bad gateway</html>`))
		}
	}))
	defer srv.Close()
	f := NewFetcher(nil)
	f.Backoff = 0
	var v any
	if err := f.GetJSON(context.Background(), srv.URL+"/big", &v); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized body: %v", err)
	}
	if err := f.GetJSON(context.Background(), srv.URL+"/redirect", &v); err == nil {
		t.Error("redirect followed")
	}
	if _, err := f.PostToken(context.Background(), srv.URL+"/token-html", url.Values{}, nil); err == nil {
		t.Error("non-JSON token response accepted")
	}
	if c := NewHTTPClient(); c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v", c.Timeout)
	}
}

func TestFetcherErrorsDoNotLeakQueries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	var v any
	err := NewFetcher(nil).GetJSON(context.Background(), srv.URL+"/x?code=SECRETCODE", &v)
	if err == nil || strings.Contains(err.Error(), "SECRETCODE") {
		t.Fatalf("err = %v", err)
	}
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingJWKS proxies the fake's JWKS and counts fetches.
func countingJWKS(t *testing.T, f *fakeidp.IdP) (string, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		resp, err := http.Get(f.JWKSURL(""))
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var body json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func TestKeySetRateLimitsRefetchForUnknownKid(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	url, n := countingJWKS(t, f)
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	ks := NewKeySet(NewFetcher(nil), url, c.Now)
	ctx := context.Background()

	kid := jwksKid(t, f)
	if _, err := ks.Key(ctx, kid); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := ks.Key(ctx, "unknown"); err == nil {
			t.Fatal("unknown kid found")
		}
	}
	if n.Load() != 1 {
		t.Fatalf("fetches = %d, want 1 (cached, rate-limited)", n.Load())
	}
	f.RotateKeys(t)
	c.Advance(MinJWKSRefresh)
	if _, err := ks.Key(ctx, jwksKid(t, f)); err != nil {
		t.Fatalf("rotated key not found after the interval: %v", err)
	}
	if n.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", n.Load())
	}
}

func TestKeySetKeepsLastGoodSetWhenRefreshFails(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(500)
			return
		}
		resp, _ := http.Get(f.JWKSURL(""))
		defer func() { _ = resp.Body.Close() }()
		var body json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	fe := NewFetcher(nil)
	fe.Backoff = 0
	ks := NewKeySet(fe, srv.URL, c.Now)
	kid := jwksKid(t, f)
	if _, err := ks.Key(context.Background(), kid); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	c.Advance(2 * MinJWKSRefresh)
	if _, err := ks.Key(context.Background(), "other"); err == nil || !strings.Contains(err.Error(), "refresh failed") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ks.Key(context.Background(), kid); err != nil {
		t.Fatalf("last good key lost: %v", err)
	}
}

func jwksKid(t *testing.T, f *fakeidp.IdP) string {
	t.Helper()
	resp, err := http.Get(f.JWKSURL(""))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set jose.JSONWebKeySet
	_ = json.NewDecoder(resp.Body).Decode(&set)
	return set.Keys[len(set.Keys)-1].KeyID
}

func TestReadCallback(t *testing.T) {
	l := Login{State: "s1"}
	for name, tc := range map[string]struct {
		q       url.Values
		wantIss string
		code    string
		oauth   string
		wantErr bool
	}{
		"code":           {q: url.Values{"state": {"s1"}, "code": {"c"}}, code: "c"},
		"error":          {q: url.Values{"state": {"s1"}, "error": {"access_denied"}}, oauth: "access_denied"},
		"state mismatch": {q: url.Values{"state": {"s2"}, "code": {"c"}}, wantErr: true},
		"no state":       {q: url.Values{"code": {"c"}}, wantErr: true},
		"iss ok":         {q: url.Values{"state": {"s1"}, "code": {"c"}, "iss": {"https://i"}}, wantIss: "https://i", code: "c"},
		"iss missing":    {q: url.Values{"state": {"s1"}, "code": {"c"}}, wantIss: "https://i", wantErr: true},
		"iss on error":   {q: url.Values{"state": {"s1"}, "error": {"x"}, "iss": {"https://evil"}}, wantIss: "https://i", wantErr: true},
		"empty":          {q: url.Values{"state": {"s1"}}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := ReadCallback(tc.q, l, tc.wantIss)
			if (err != nil) != tc.wantErr || r.Code != tc.code || r.Error != tc.oauth {
				t.Fatalf("result %+v, err %v", r, err)
			}
		})
	}
	if _, err := ReadCallback(url.Values{"code": {"c"}}, Login{}, ""); err == nil {
		t.Error("empty expected state accepted")
	}
}

func TestRequestIDRoundTrip(t *testing.T) {
	if RequestID(context.Background()) != "" || RequestID(WithRequestID(context.Background(), "r")) != "r" {
		t.Fatal("request ID not carried")
	}
}

func TestPostTokenIsNeverRetried(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
	}))
	defer srv.Close()
	f := NewFetcher(nil)
	f.Backoff = 0
	tr, err := f.PostToken(context.Background(), srv.URL, url.Values{}, nil)
	if err != nil || tr.OK() || tr.Status != 503 || n.Load() != 1 {
		t.Fatalf("tr %+v err %v calls %d", tr, err, n.Load())
	}
}

func TestGetJSONStopsOnCancelDuringBackoff(t *testing.T) {
	var n atomic.Int32
	f := NewFetcher(nil)
	f.Backoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	f.Client.Transport = cancelAfter{cancel: cancel, n: &n}
	var v any
	if err := f.GetJSON(ctx, "https://idp.example/keys", &v); !errors.Is(err, context.Canceled) || n.Load() != 1 {
		t.Fatalf("err = %v, attempts = %d", err, n.Load())
	}
}

// cancelAfter answers 500 and cancels the context, so GetJSON is waiting in backoff when it notices.
type cancelAfter struct {
	cancel context.CancelFunc
	n      *atomic.Int32
}

func (c cancelAfter) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	c.cancel()
	return &http.Response{StatusCode: 500, Body: http.NoBody, Request: r}, nil
}

func TestKeySetLookupUsesOnlySigningKeys(t *testing.T) {
	sig := func(kid string) map[string]any {
		k := map[string]any{}
		raw, _ := json.Marshal(jose.JSONWebKey{Key: &fakeidp.NewCertificate(t).Key.PublicKey, KeyID: kid, Use: "sig"})
		_ = json.Unmarshal(raw, &k)
		return k
	}
	withUse := func(k map[string]any, use string) map[string]any {
		if use == "" {
			delete(k, "use")
		} else {
			k["use"] = use
		}
		return k
	}
	for name, tc := range map[string]struct {
		keys  []map[string]any
		kid   string
		found bool
	}{
		"one sig key, no kid":       {keys: []map[string]any{sig("a")}, found: true},
		"two sig keys, no kid":      {keys: []map[string]any{sig("a"), sig("b")}},
		"one enc key, no kid":       {keys: []map[string]any{withUse(sig("a"), "enc")}},
		"enc key with matching kid": {keys: []map[string]any{withUse(sig("a"), "enc")}, kid: "a"},
		"key without use":           {keys: []map[string]any{withUse(sig("a"), "")}, kid: "a", found: true},
		"enc and sig, no kid":       {keys: []map[string]any{withUse(sig("a"), "enc"), sig("b")}, found: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": tc.keys})
			}))
			defer srv.Close()
			_, err := NewKeySet(NewFetcher(nil), srv.URL, func() time.Time { return fixedNow }).Key(context.Background(), tc.kid)
			if (err == nil) != tc.found {
				t.Fatalf("err = %v, want found %v", err, tc.found)
			}
		})
	}
}
