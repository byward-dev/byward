package assertion_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
)

// Contract test (ADR-0016 §8, ADR-0024): an upstream on go-sdk's stock bearer middleware, with the
// verifier docs/reference/identity-assertion.md shows, accepts the proxy's assertion and refuses
// one for another audience, an expired one and one signed with another key.

// verifier is the docs' example: the proxy's JWKS, ES256 only, typ at+jwt, aud this upstream's URL
// exactly as the proxy's BYWARD_UPSTREAM_URL says, 30 s leeway.
func verifier(keys jose.JSONWebKeySet, audience string) auth.TokenVerifier {
	return func(_ context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
		tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil || len(tok.Headers) != 1 || tok.Headers[0].ExtraHeaders["typ"] != "at+jwt" {
			return nil, auth.ErrInvalidToken
		}
		k := keys.Key(tok.Headers[0].KeyID)
		if len(k) != 1 {
			return nil, auth.ErrInvalidToken
		}
		var c jwt.Claims
		var extra struct {
			ClientID string   `json:"client_id"`
			Roles    []string `json:"roles"`
		}
		if err := tok.Claims(k[0].Key, &c, &extra); err != nil {
			return nil, auth.ErrInvalidToken
		}
		if err := c.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{audience}, Time: time.Now()}, 30*time.Second); err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
		}
		return &auth.TokenInfo{UserID: c.Subject, Expiration: c.Expiry.Time(),
			Extra: map[string]any{"client_id": extra.ClientID, "roles": extra.Roles}}, nil
	}
}

func TestGoSDKBearerMiddlewareAcceptsTheAssertion(t *testing.T) {
	const upstream = "http://mcp-upstream.internal:3001/mcp"
	dir := t.TempDir()
	assertionkey.Write(t, dir, "k1", false)
	keys, err := assertion.LoadKeys(dir, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// The JWKS as the upstream fetches it from the proxy.
	rec := httptest.NewRecorder()
	keys.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	var seen *auth.TokenInfo
	h := auth.RequireBearerToken(verifier(set, upstream), nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = auth.TokenInfoFromContext(r.Context())
	}))
	call := func(raw string) int {
		r := httptest.NewRequest(http.MethodPost, upstream, nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	id := resource.Identity{Subject: "tid:oid", ClientID: "claude-code", PrincipalType: resource.PrincipalUser, Roles: []string{"byward.user"}}
	mint := func(audience string, now time.Time, k *assertion.Keys) string {
		t.Helper()
		m, err := assertion.NewMinter(k, "https://mcp.example.com", audience, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		raw, err := m.Mint(id)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if code := call(mint(upstream, time.Now(), keys)); code != http.StatusOK || seen == nil || seen.UserID != "tid:oid" || seen.Extra["client_id"] != "claude-code" {
		t.Fatalf("a valid assertion: %d, %+v", code, seen)
	}
	otherDir := t.TempDir()
	assertionkey.Write(t, otherDir, "k1", false)
	other, err := assertion.LoadKeys(otherDir, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"another audience":     mint("http://other.internal/mcp", time.Now(), keys),
		"expired":              mint(upstream, time.Now().Add(-assertion.Lifetime-time.Minute), keys),
		"another key, same ID": mint(upstream, time.Now(), other),
	} {
		if code := call(raw); code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, code)
		}
	}
}
