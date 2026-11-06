package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// refreshBytes is the entropy of a refresh token.
const refreshBytes = 32

// NewRefreshToken returns a random refresh token and the SHA-256 hash to store in its place; the
// token itself is never stored (ADR-0006 §4).
func NewRefreshToken() (tok string, hash [sha256.Size]byte) {
	b := make([]byte, refreshBytes)
	_, _ = rand.Read(b) // never fails (crypto/rand, Go 1.24+)
	tok = RefreshPrefix + base64.RawURLEncoding.EncodeToString(b)
	return tok, sha256.Sum256([]byte(tok))
}

// HashRefreshToken returns the stored hash for a presented refresh token, or false when the
// string cannot be one of ours, so the store is not queried for garbage.
func HashRefreshToken(tok string) ([sha256.Size]byte, bool) {
	body, ok := strings.CutPrefix(tok, RefreshPrefix)
	if !ok || len(body) != base64.RawURLEncoding.EncodedLen(refreshBytes) {
		return [sha256.Size]byte{}, false
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(body); err != nil {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(tok)), true
}
