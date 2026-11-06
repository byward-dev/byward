package idp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

func TestVerifyJWT(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	now := time.Unix(1_800_000_000, 0)
	ks := NewKeySet(NewFetcher(nil), f.JWKSURL(""), func() time.Time { return now })
	base := func() map[string]any {
		return map[string]any{"iss": "https://issuer.example", "aud": "cid", "sub": "u1", "nonce": "n1",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	}
	rules := TokenRules{
		Issuer: func(iss string, _ map[string]any) error {
			if iss != "https://issuer.example" {
				return errors.New("bad iss")
			}
			return nil
		},
		ClientID: "cid", Nonce: "n1", Algs: []jose.SignatureAlgorithm{jose.RS256}, Now: func() time.Time { return now },
	}
	for name, tc := range map[string]struct {
		edit  func(map[string]any)
		rules func(*TokenRules)
		ok    bool
	}{
		"valid":                   {ok: true},
		"aud array of one":        {edit: func(c map[string]any) { c["aud"] = []any{"cid"} }, ok: true},
		"aud with extra audience": {edit: func(c map[string]any) { c["aud"] = []any{"cid", "other"} }},
		"aud other":               {edit: func(c map[string]any) { c["aud"] = "other" }},
		"no aud":                  {edit: func(c map[string]any) { delete(c, "aud") }},
		"azp other":               {edit: func(c map[string]any) { c["azp"] = "other" }},
		"azp ours":                {edit: func(c map[string]any) { c["azp"] = "cid" }, ok: true},
		"wrong issuer":            {edit: func(c map[string]any) { c["iss"] = "https://evil.example" }},
		"expired beyond leeway":   {edit: func(c map[string]any) { c["exp"] = now.Add(-Leeway).Unix() }},
		"expired within leeway":   {edit: func(c map[string]any) { c["exp"] = now.Add(-Leeway + time.Second).Unix() }, ok: true},
		"iat in the future":       {edit: func(c map[string]any) { c["iat"] = now.Add(Leeway + time.Second).Unix() }},
		"iat within leeway":       {edit: func(c map[string]any) { c["iat"] = now.Add(Leeway).Unix() }, ok: true},
		"no iat":                  {edit: func(c map[string]any) { delete(c, "iat") }},
		"nbf in the future":       {edit: func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }},
		"nonce mismatch":          {edit: func(c map[string]any) { c["nonce"] = "n2" }},
		"nonce missing":           {edit: func(c map[string]any) { delete(c, "nonce") }},
		"no nonce expected":       {edit: func(c map[string]any) { delete(c, "nonce") }, rules: func(r *TokenRules) { r.Nonce = "" }, ok: true},
		"no sub":                  {edit: func(c map[string]any) { delete(c, "sub") }},
		"RS256 not in allowlist":  {rules: func(r *TokenRules) { r.Algs = []jose.SignatureAlgorithm{jose.ES256} }},
		"wrong client in rules":   {rules: func(r *TokenRules) { r.ClientID = "x" }},
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			if tc.edit != nil {
				tc.edit(c)
			}
			r := rules
			if tc.rules != nil {
				tc.rules(&r)
			}
			_, err := VerifyJWT(context.Background(), f.Mint(c), ks, r)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
		})
	}

	t.Run("tampered signature", func(t *testing.T) {
		parts := strings.Split(f.Mint(base()), ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sig[0] ^= 0xFF
		forged := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
		if _, err := VerifyJWT(context.Background(), forged, ks, rules); err == nil {
			t.Fatal("tampered token accepted")
		}
	})
	t.Run("HS256 token signed with the public modulus", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"` + jwksKid(t, f) + `"}`))
		payload := strings.Split(f.Mint(base()), ".")[1]
		mac := hmac.New(sha256.New, []byte("public"))
		mac.Write([]byte(header + "." + payload))
		tok := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		r := rules
		r.Algs = append(append([]jose.SignatureAlgorithm{}, rules.Algs...), jose.HS256)
		if _, err := VerifyJWT(context.Background(), tok, ks, r); err == nil {
			t.Fatal("HS256 accepted with a mixed allowlist")
		}
		r.Algs = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512}
		if _, err := VerifyJWT(context.Background(), tok, ks, r); err == nil || !strings.Contains(err.Error(), "no signature algorithm allowed") {
			t.Fatalf("HS* allowlist: err = %v", err)
		}
	})
	t.Run("alg none", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		tok := header + "." + strings.Split(f.Mint(base()), ".")[1] + "."
		if _, err := VerifyJWT(context.Background(), tok, ks, rules); err == nil {
			t.Fatal("alg none accepted")
		}
	})
}

func TestCodeChallengeIsRFC7636S256(t *testing.T) {
	// RFC 7636 Appendix B.
	if got := CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge = %s", got)
	}
}

func TestStringsClaim(t *testing.T) {
	c := map[string]any{"r": []any{"a", 1, "b"}, "s": "x"}
	if got := StringsClaim(c, "r"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("StringsClaim = %v", got)
	}
	if StringsClaim(c, "s") != nil || StringsClaim(c, "missing") != nil {
		t.Error("non-array claim returned values")
	}
}

type unavailableKeys struct{}

func (unavailableKeys) Key(context.Context, string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("down: %w", ErrKeysUnavailable)
}

func TestVerifyJWTPassesKeyOutagesThrough(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	raw := f.Mint(map[string]any{"iss": "i", "aud": "c", "sub": "s"})
	_, err := VerifyJWT(context.Background(), raw, unavailableKeys{}, TokenRules{
		Issuer: func(string, map[string]any) error { return nil }, ClientID: "c",
		Algs: []jose.SignatureAlgorithm{jose.RS256}, Now: func() time.Time { return fixedNow }})
	if !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("err = %v", err)
	}
}
