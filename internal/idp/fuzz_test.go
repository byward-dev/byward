package idp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// memory serves a fixed status and body without a socket, so fuzz inputs stay cheap.
type memory struct {
	status int
	body   []byte
}

func (m memory) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: m.status, Body: io.NopCloser(bytes.NewReader(m.body)), Header: http.Header{}, Request: r}, nil
}

func memoryFetcher(status int, body string) *Fetcher {
	f := NewFetcher(&http.Client{Transport: memory{status, []byte(body)}})
	f.Retries = 0
	return f
}

func FuzzVerifyJWT(f *testing.F) {
	fake := fakeidp.New(f, fakeidp.Generic)
	now := time.Unix(1_800_000_000, 0)
	f.Add(fake.Mint(map[string]any{"iss": "i", "aud": "c", "sub": "s", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}))
	f.Add("a.b.c")
	f.Add("")
	ks := NewKeySet(NewFetcher(nil), fake.JWKSURL(""), func() time.Time { return now })
	rules := TokenRules{Issuer: func(string, map[string]any) error { return nil }, ClientID: "c",
		Algs: []jose.SignatureAlgorithm{jose.RS256, jose.HS256}, Now: func() time.Time { return now }}
	f.Fuzz(func(t *testing.T, raw string) {
		claims, err := VerifyJWT(context.Background(), raw, ks, rules)
		if err != nil {
			return
		}
		if _, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256}); err != nil {
			t.Fatalf("accepted a token that is not RS256: %v", err)
		}
		if aud, _ := claims["aud"].(string); aud != "c" && !equalAud(claims["aud"]) {
			t.Fatalf("accepted aud %v", claims["aud"])
		}
		if s, _ := claims["sub"].(string); s == "" {
			t.Fatal("accepted a token without sub")
		}
	})
}

func equalAud(v any) bool {
	a, ok := v.([]any)
	return ok && len(a) == 1 && a[0] == "c"
}

func FuzzKeySetJWKS(f *testing.F) {
	f.Add(`{"keys":[]}`, "")
	f.Add(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"k","use":"enc"}]}`, "k")
	f.Add(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"k","use":"sig"}]}`, "k")
	f.Add(`{"keys":[{"kty":"AKP","kid":"x"},{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"k"}]}`, "k")
	f.Add(`{"keys":[{"kty":"EC","crv":"P-256"}]}`, "")
	f.Fuzz(func(t *testing.T, body, kid string) {
		key, err := NewKeySet(memoryFetcher(200, body), "https://idp.example/keys", time.Now).Key(context.Background(), kid)
		if err == nil && (!key.IsPublic() || (key.Use != "" && key.Use != "sig")) {
			t.Fatalf("returned a non-signing key: %+v", key)
		}
	})
}

func TestKeySetSkipsUnsupportedKeyTypes(t *testing.T) {
	body := `{"keys":[{"kty":"AKP","kid":"x"},{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"k","use":"sig"}]}`
	if _, err := NewKeySet(memoryFetcher(200, body), "https://idp.example/keys", time.Now).Key(context.Background(), "k"); err != nil {
		t.Fatalf("one unknown key type failed the whole set: %v", err)
	}
}

func FuzzTokenResponse(f *testing.F) {
	f.Add(200, `{"access_token":"a","expires_in":3600}`)
	f.Add(400, `{"error":"invalid_grant","error_codes":[70000],"trace_id":"t"}`)
	f.Add(502, `<html>`)
	f.Fuzz(func(t *testing.T, status int, body string) {
		if status < 200 || status > 599 {
			return
		}
		tr, err := memoryFetcher(status, body).PostToken(context.Background(), "https://idp.example/token", url.Values{}, nil)
		if err == nil && tr.OK() && tr.AccessToken == "" && tr.IDToken == "" {
			t.Fatal("success without tokens")
		}
	})
}

func FuzzReadCallback(f *testing.F) {
	f.Add("state=s&code=c", "s", "")
	f.Add("state=s&error=x&iss=i", "s", "i")
	f.Fuzz(func(t *testing.T, query, state, iss string) {
		q, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		r, err := ReadCallback(q, Login{State: state}, iss)
		if err == nil && (state == "" || q.Get("state") != state || (iss != "" && q.Get("iss") != iss) || (r.Code == "" && r.Error == "")) {
			t.Fatalf("accepted %q with state %q iss %q", query, state, iss)
		}
	})
}
