package token

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestRefreshTokensAreRandomAndOnlyTheirHashIsKept(t *testing.T) {
	a, ha := NewRefreshToken()
	b, hb := NewRefreshToken()
	if a == b || ha == hb {
		t.Fatal("two refresh tokens are equal")
	}
	if !strings.HasPrefix(a, RefreshPrefix) {
		t.Fatalf("token %q lacks the refresh prefix", a)
	}
	if ha != sha256.Sum256([]byte(a)) {
		t.Fatal("hash is not SHA-256 of the token")
	}
	if got, ok := HashRefreshToken(a); !ok || got != ha {
		t.Fatal("presented token does not hash to the stored value")
	}
}

func TestHashRefreshTokenRejectsWhatCannotBeOurs(t *testing.T) {
	tok, _ := NewRefreshToken()
	body := strings.TrimPrefix(tok, RefreshPrefix)
	cases := map[string]string{
		"empty":         "",
		"no prefix":     body,
		"access prefix": AccessPrefix + body,
		"too short":     tok[:len(tok)-1],
		"too long":      tok + "A",
		"not base64url": RefreshPrefix + strings.Repeat("+", len(body)),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := HashRefreshToken(in); ok {
				t.Fatal("accepted")
			}
		})
	}
}
