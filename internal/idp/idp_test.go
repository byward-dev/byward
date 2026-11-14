package idp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
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

// A client key may be an EC P-256 key, or an RSA key of MinRSABits or more with either RSA
// algorithm; another curve, another key type or a shorter RSA key is refused, saying why.
func TestOnlyAP256OrMinRSABitsRSAKeyIsAClientKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey := func(bits int) crypto.Signer {
		t.Helper()
		k, err := rsa.GenerateKey(rand.Reader, bits) //nolint:gosec // deliberately weak keys for the test
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rsa2048 := rsaKey(2048)
	for name, tc := range map[string]struct {
		key     crypto.Signer
		alg     string
		wantErr string // "" accepts
	}{
		"EC P-256":                {key: p256},
		"EC P-384":                {key: p384, wantErr: "idp: EC client keys must use P-256"},
		"Ed25519":                 {key: ed, wantErr: "idp: unsupported client key type ed25519.PublicKey"},
		"RSA 2048, PS256":         {key: rsa2048, alg: "PS256"},
		"RSA 2048, RS256":         {key: rsa2048, alg: "RS256"},
		"RSA 2047, default PS256": {key: rsaKey(2047), wantErr: "idp: a 2047-bit RSA key: use at least 2048 bits"},
		"RSA 1024, RS256":         {key: rsaKey(1024), alg: "RS256", wantErr: "idp: a 1024-bit RSA key: use at least 2048 bits"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := PrivateKeyJWTWithAlg(tc.key, nil, "", tc.alg)
			if got := fmt.Sprint(err); (tc.wantErr == "" && err != nil) || (tc.wantErr != "" && got != tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// The client assertion is signed with the chosen algorithm, or the key type's default when none is
// chosen (PS256 for RSA, ES256 for EC P-256, as before #306); an algorithm the key cannot sign with
// is refused.
func TestPrivateKeyJWTSignsWithTheChosenAlgorithm(t *testing.T) {
	rsaKey := fakeidp.NewCertificate(t).Key
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, tc := range []struct {
		name, alg string
		want      string // the algorithm signed with; "" means refused with ErrClientKeyAlg, as wantErr
		wantErr   string
		key       crypto.Signer
	}{
		{name: "an RSA key by default", key: rsaKey, want: "PS256"},
		{name: "an RSA key with PS256", key: rsaKey, alg: "PS256", want: "PS256"},
		{name: "an RSA key with RS256", key: rsaKey, alg: "RS256", want: "RS256"},
		{name: "an EC key by default", key: ecKey, want: "ES256"},
		{name: "an EC key with ES256", key: ecKey, alg: "ES256", want: "ES256"},
		{name: "an RSA key with ES256", key: rsaKey, alg: "ES256", wantErr: `an RSA client key signs with PS256 or RS256, not "ES256"`},
		{name: "an RSA key with RS384", key: rsaKey, alg: "RS384", wantErr: `an RSA client key signs with PS256 or RS256, not "RS384"`},
		{name: "an EC key with RS256", key: ecKey, alg: "RS256", wantErr: `an EC P-256 client key signs with ES256, not "RS256"`},
		{name: "an EC key with PS256", key: ecKey, alg: "PS256", wantErr: `an EC P-256 client key signs with ES256, not "PS256"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := PrivateKeyJWTWithAlg(tc.key, nil, "kid-1", tc.alg)
			if tc.want == "" {
				if !errors.Is(err, ErrClientKeyAlg) || err.Error() != ErrClientKeyAlg.Error()+": "+tc.wantErr {
					t.Fatalf("err = %v, want ErrClientKeyAlg: %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, ok := ca.(AssertionInfo)
			if !ok {
				t.Fatalf("%T is not an AssertionInfo", ca)
			}
			if info.SigningAlgorithm() != tc.want || info.KeyID() != "kid-1" {
				t.Fatalf("SigningAlgorithm %q, KeyID %q; want %s, kid-1", info.SigningAlgorithm(), info.KeyID(), tc.want)
			}
			form := url.Values{}
			if err := ca.Apply(form, "cid", "https://idp.example/token", time.Unix(1_800_000_000, 0)); err != nil {
				t.Fatal(err)
			}
			tok, err := jwt.ParseSigned(form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.SignatureAlgorithm(tc.want)})
			if err != nil {
				t.Fatalf("the assertion is not signed with %s: %v", tc.want, err)
			}
			var c jwt.Claims
			if err := tok.Claims(tc.key.Public(), &c); err != nil {
				t.Fatalf("the assertion does not verify with the key: %v", err)
			}
		})
	}
}

// Every algorithm ClientKeyTypes lists for a key type signs with that key type, so advice built from
// it names only algorithms PrivateKeyJWTWithAlg accepts (#306).
func TestEveryListedClientKeyAlgorithmSigns(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := map[string]crypto.Signer{"RSA": fakeidp.NewCertificate(t).Key, "EC P-256": ecKey}
	types := ClientKeyTypes()
	if len(types) != len(keys) {
		t.Fatalf("ClientKeyTypes %+v, want one per key type the test knows: %d", types, len(keys))
	}
	for _, kt := range types {
		key, ok := keys[kt.Name]
		if !ok {
			t.Fatalf("no test key for %q", kt.Name)
		}
		for _, alg := range append([]string{""}, kt.Algs...) {
			want := alg
			if alg == "" {
				want = kt.Algs[0] // the default
			}
			ca, err := PrivateKeyJWTWithAlg(key, nil, "", alg)
			if err != nil {
				t.Fatalf("%s with %q: %v", kt.Name, alg, err)
			}
			if info, ok := ca.(AssertionInfo); !ok || info.SigningAlgorithm() != want {
				t.Fatalf("%s with %q: %T signs with %v, want %s", kt.Name, alg, ca, info, want)
			}
		}
	}
	// a copy: changing it changes neither the table nor what the signer accepts
	types[0].Name, types[0].Algs[0] = "changed", "XX"
	if again := ClientKeyTypes(); again[0].Name != "RSA" || again[0].Algs[0] != "PS256" {
		t.Fatalf("ClientKeyTypes shares its table: %+v", again)
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
		"408 then 200":    {statuses: []int{408, 200}, calls: 2},
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
	// A success without tokens is a protocol violation, not an outage: Fatal, so the broker fails the
	// request and keeps the grant instead of answering "try again".
	_, err := f.PostToken(context.Background(), srv.URL+"/ok", url.Values{}, nil)
	if ie := (*Error)(nil); !errors.As(err, &ie) || ie.Class != Fatal || ie.Alert != AlertProtocol {
		t.Errorf("a success without tokens: %#v, want Fatal with an operator alert", err)
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

func TestTokenCheckErrorDropsTheHintOnlyWhenKeysAreUnavailable(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		class    Class
		keepHint bool
	}{
		"keys unavailable":        {ErrKeysUnavailable, Unavailable, false},
		"wrapped twice":           {fmt.Errorf("a: %w", fmt.Errorf("b: %w", ErrKeysUnavailable)), Unavailable, false},
		"deadline with sentinel":  {fmt.Errorf("%w: %w", ErrKeysUnavailable, context.DeadlineExceeded), Unavailable, false},
		"bad signature":           {errors.New("idp: JWT signature: crypto"), Fatal, true},
		"cancel without sentinel": {context.Canceled, Fatal, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := TokenCheckError(tc.err, "fix it")
			if e.Class != tc.class || (e.OperatorHint == "fix it") != tc.keepHint || !errors.Is(e, tc.err) {
				t.Fatalf("got %+v", e)
			}
		})
	}
}

func TestFetcherBudgetCoversItsRetries(t *testing.T) {
	f := NewFetcher(&http.Client{Timeout: 2 * time.Second})
	f.Retries, f.Backoff = 3, time.Second
	// Worst case: 4 attempts, and before retry a a sleep under Backoff*a + Backoff (a = 1..3).
	if b, worst := f.budget(), 4*2*time.Second+(2+3+4)*f.Backoff; b < worst {
		t.Fatalf("budget %v is shorter than the worst case %v", b, worst)
	}
	if b := NewFetcher(&http.Client{}).budget(); b < 3*DefaultTimeout {
		t.Fatalf("no client timeout: budget %v", b)
	}
}

// #204: every alert reason names a fix, distinct per reason, so an alert line never has an empty
// reason, even for a reason added later without a hint of its own.
func TestEveryAlertReasonNamesAFix(t *testing.T) {
	seen := map[string]Alert{}
	for _, a := range append(Alerts, Alert("added_later")) {
		h := a.Hint()
		if h == "" {
			t.Errorf("%q has no fix", a)
		}
		if other, dup := seen[h]; dup {
			t.Errorf("%q and %q share the fix %q", a, other, h)
		}
		seen[h] = a
	}
	if h := Alert("").Hint(); h != "" {
		t.Errorf("no alert names the fix %q", h)
	}
}

// #204: an alert names the IdP's own fix when it has one, else its reason's default.
func TestTheFixIsTheIdPsOwnElseTheAlertsDefault(t *testing.T) {
	for _, c := range []struct {
		name string
		err  Error
		want string
	}{
		{"the IdP's own", Error{Alert: AlertCredentialRejected, OperatorHint: "AADSTS7000222: renew the secret"}, "AADSTS7000222: renew the secret"},
		{"the alert's default", Error{Alert: AlertCredentialRejected}, AlertCredentialRejected.Hint()},
		{"neither", Error{}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.err.Fix(); got != c.want {
				t.Errorf("Fix() = %q, want %q", got, c.want)
			}
		})
	}
}

// #204: an alert, wrapped or not, is counted once and logged on the line operators alert on, with
// its fix and the request's ID.
func TestReportAlertCountsAndLogsAnAlert(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		alert  Alert
		reason string // the fix on the line: the IdP's own hint, else the alert's
	}{
		{"wrapped, with the alert's own fix", fmt.Errorf("wrap: %w", &Error{Alert: AlertProtocol}), AlertProtocol,
			"the IdP answered against the protocol: check the IdP's endpoints and status"},
		{"bare, with the IdP's hint", &Error{Alert: AlertCredentialRejected, OperatorHint: "rotate the secret"}, AlertCredentialRejected, "rotate the secret"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var logs bytes.Buffer
			var counted []string
			ctx := logging.WithRequestID(context.Background(), "req-1")
			ReportAlert(ctx, logging.New(&logs, "json"), "entra", "refresh", c.err, func(op, reason string) { counted = append(counted, op+" "+reason) })
			if !slices.Equal(counted, []string{"refresh " + string(c.alert)}) {
				t.Errorf("counted %v, want refresh %s once", counted, c.alert)
			}
			var line map[string]any
			if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
				t.Fatalf("not one JSON line (%v): %q", err, logs.String())
			}
			want := map[string]any{"msg": "IdP alert: the operator must act", "level": "ERROR", "idp": "entra", "operation": "refresh",
				"alert": string(c.alert), "reason": c.reason, "request_id": "req-1"}
			for k, v := range want {
				if line[k] != v {
					t.Errorf("%s = %v, want %v (line %v)", k, line[k], v, line)
				}
			}
		})
	}
}

// Anything that is not an IdP alert is neither counted nor logged.
func TestReportAlertIgnoresWhatIsNoAlert(t *testing.T) {
	for name, err := range map[string]error{
		"an IdP error without an alert": &Error{Class: Unavailable},
		"not an IdP error":              errors.New("x"),
		"nil":                           nil,
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			counted := 0
			ReportAlert(context.Background(), logging.New(&logs, "json"), "entra", "refresh", err, func(string, string) { counted++ })
			if counted != 0 || logs.Len() != 0 {
				t.Fatalf("counted %d and logged %q, want neither", counted, logs.String())
			}
		})
	}
}

// A GUID is the 36-character form in either case and nothing else: not a tenant name, a GUID one
// character short or long, one with a dash missing or moved, or one with a non-hex digit.
func TestOnlyThe36CharacterFormIsAGUID(t *testing.T) {
	g := fakeidp.NewGUID()
	for s, want := range map[string]bool{
		g:                                      true,
		strings.ToUpper(g):                     true,
		"D4991BF4-0BFE-4828-9C3A-ABCDEF012345": true, // upper case, whatever g is
		g[:35]:                                 false,
		g + "0":                                false,
		g[:8] + "0" + g[9:]:                    false, // dash missing
		g[:7] + "-" + g[7:8] + g[9:]:           false, // dash moved one place left
		"organizations":                        false,
		"":                                     false,
		"00000000-0000-0000-0000-00000000000g": false,
	} {
		if got := IsGUID(s); got != want {
			t.Errorf("IsGUID(%q) = %v, want %v", s, got, want)
		}
	}
}
