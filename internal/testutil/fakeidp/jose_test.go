package fakeidp

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestIsGUID(t *testing.T) {
	g := NewGUID()
	for s, want := range map[string]bool{
		g:                                      true,
		strings.ToUpper(g):                     true,
		g[:35]:                                 false,
		g + "0":                                false,
		g[:8] + "0" + g[9:]:                    false, // dash missing
		"g" + g[1:]:                            false,
		"organizations":                        false,
		"":                                     false,
		"00000000-0000-0000-0000-00000000000g": false,
	} {
		if got := isGUID(s); got != want {
			t.Errorf("isGUID(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestAudContainsOnlyStringsAndJSONArrays(t *testing.T) {
	for name, tc := range map[string]struct {
		aud  any
		want bool
	}{
		"string hit":        {"a", true},
		"string miss":       {"b", false},
		"array hit":         {[]any{"x", "a"}, true},
		"array miss":        {[]any{"x"}, false},
		"array non-strings": {[]any{1, nil}, false},
		"nil":               {nil, false},
		"[]string":          {[]string{"a"}, false},
	} {
		if got := audContains(tc.aud, "a"); got != tc.want {
			t.Errorf("%s: audContains = %v, want %v", name, got, tc.want)
		}
	}
}

// WithUnusableJWK serves, beside the signing key, an X448 key that a strict decode refuses and an RSA
// key for encryption, the two kinds a JWKS reader must skip (RFC 7517 §5).
func TestUnusableJWKsAreServedBesideTheSigningKey(t *testing.T) {
	f := newFixture(t, Entra, WithUnusableJWK(true))
	var uses []string
	for _, k := range f.jwks(t) {
		use, _ := k["use"].(string)
		uses = append(uses, k["kty"].(string)+":"+use)
	}
	if got := strings.Join(uses, " "); got != "RSA:sig OKP: RSA:enc" {
		t.Fatalf("keys %s, want the signing key, then an OKP key and an RSA encryption key", got)
	}
	resp, err := http.Get(f.idp.JWKSURL(f.tenant))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var strict jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&strict); err == nil {
		t.Fatal("a strict decode accepted the set: it holds no key go-jose cannot parse")
	}
}
