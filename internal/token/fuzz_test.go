package token

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"strings"
	"testing"
)

// FuzzOpen feeds arbitrary strings to the sealed-token parser: it must never panic, and anything
// it accepts must be a complete, sealed access token.
func FuzzOpen(f *testing.F) {
	s := newSealer(f)
	long := claims()
	long.GrantID, long.Subject = "grant-with-a-longer-id", "tid-00000000:oid-11111111"
	for _, c := range []Claims{claims(), long} {
		if tok, err := s.Seal(Access, c); err == nil {
			f.Add(tok)
		}
		if tok, err := s.Seal(Code, c); err == nil {
			f.Add(tok)
		}
	}
	refresh, _ := NewRefreshToken()
	for _, seed := range []string{"", AccessPrefix, AccessPrefix + "AQ", AccessPrefix + "AQJrMQ", refresh, "eyJhbGciOiJub25lIn0.e30."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := s.Open(Access, tok)
		if err != nil {
			return
		}
		again, err := s.Seal(Access, c)
		if err != nil {
			t.Fatalf("accepted claims that cannot be sealed again: %+v: %v", c, err)
		}
		if c2, err := s.Open(Access, again); err != nil || c2 != c {
			t.Fatalf("claims do not round-trip: %+v → %+v, %v", c, c2, err)
		}
		if _, err := s.Open(Code, tok); err == nil {
			t.Fatal("one token opened as two types")
		}
	})
}

// FuzzDecodeKey feeds arbitrary key-file contents to the key parser: it must never panic, and
// anything it accepts must be a usable AES-256 key.
func FuzzDecodeKey(f *testing.F) {
	for _, seed := range []string{"", "\n", "not base64", "AAAA", "dGhpcyBpcyBub3QgMzIgYnl0ZXM=",
		"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\n", "  MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=  "} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := decodeKey(raw)
		if err != nil {
			return
		}
		if len(k) != KeySize || bytes.Count(k, k[:1]) == KeySize {
			t.Fatalf("accepted a %d-byte or uniform key", len(k))
		}
		if _, err := aes.NewCipher(k); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzHashRefreshToken: never panics; accepts only prefixed, well-formed tokens.
func FuzzHashRefreshToken(f *testing.F) {
	tok, _ := NewRefreshToken()
	f.Add(tok)
	f.Add(RefreshPrefix)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		h, ok := HashRefreshToken(s)
		if !ok {
			return
		}
		if len(s) != len(tok) || !strings.HasPrefix(s, RefreshPrefix) || h != sha256.Sum256([]byte(s)) {
			t.Fatalf("accepted %q", s)
		}
	})
}
