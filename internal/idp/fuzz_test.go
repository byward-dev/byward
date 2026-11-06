package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
)

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
		if err == nil && claims["aud"] == nil {
			t.Fatal("accepted a token without aud")
		}
	})
}

func FuzzKeySetJWKS(f *testing.F) {
	f.Add(`{"keys":[]}`, "")
	f.Add(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"k","use":"enc"}]}`, "k")
	f.Add(`{"keys":[{"kty":"EC","crv":"P-256"}]}`, "")
	f.Fuzz(func(t *testing.T, body, kid string) {
		if len(body) > MaxBodyBytes {
			return
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		defer srv.Close()
		fe := NewFetcher(nil)
		fe.Retries = 0
		key, err := NewKeySet(fe, srv.URL, time.Now).Key(context.Background(), kid)
		if err == nil && (!key.IsPublic() || (key.Use != "" && key.Use != "sig")) {
			t.Fatalf("returned a non-signing key: %+v", key)
		}
	})
}

func FuzzTokenResponse(f *testing.F) {
	f.Add(200, `{"access_token":"a","expires_in":3600}`)
	f.Add(400, `{"error":"invalid_grant","error_codes":[70000],"trace_id":"t"}`)
	f.Add(502, `<html>`)
	f.Fuzz(func(t *testing.T, status int, body string) {
		if status < 200 || status > 599 {
			return
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		tr, err := NewFetcher(nil).PostToken(context.Background(), srv.URL, url.Values{}, nil)
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
