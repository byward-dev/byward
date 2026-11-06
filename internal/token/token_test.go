package token

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

const resourceA = "https://mcp.example.com/mcp"

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func claims() Claims {
	return Claims{GrantID: "g-1", Subject: "tid-1:oid-1", IssuedAt: t0, ExpiresAt: t0.Add(time.Hour)}
}

func sealerFor(t testing.TB, r *KeyRing, resource string) *Sealer {
	t.Helper()
	s, err := NewSealer(r, resource)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newSealer(t testing.TB) *Sealer {
	t.Helper()
	return sealerFor(t, mustRing(t, keyDir(t, map[string]string{"k1": randomKey(t)})), resourceA)
}

func mustSeal(t *testing.T, s *Sealer, typ Type, c Claims) string {
	t.Helper()
	tok, err := s.Seal(typ, c)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return tok
}

func TestOpenReturnsWhatWasSealed(t *testing.T) {
	s := newSealer(t)
	prop := func(grant, subject string, iat uint32, life uint16) bool {
		if grant == "" || subject == "" {
			return true
		}
		c := Claims{GrantID: grant, Subject: subject, IssuedAt: time.Unix(int64(iat)+1, 0), ExpiresAt: time.Unix(int64(iat)+1+int64(life)+1, 0)}
		for _, typ := range []Type{Access, Code} {
			tok, err := s.Seal(typ, c)
			if err != nil {
				return len(tok) > MaxLen // only an oversized claim may fail
			}
			got, err := s.Open(typ, tok)
			if err != nil || got.GrantID != c.GrantID || got.Subject != c.Subject || !got.IssuedAt.Equal(c.IssuedAt) || !got.ExpiresAt.Equal(c.ExpiresAt) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestTokensHaveTheirTypePrefixAndAreUnique(t *testing.T) {
	s := newSealer(t)
	a1, a2 := mustSeal(t, s, Access, claims()), mustSeal(t, s, Access, claims())
	if !strings.HasPrefix(a1, AccessPrefix) || !strings.HasPrefix(mustSeal(t, s, Code, claims()), CodePrefix) {
		t.Fatal("missing type prefix")
	}
	if a1 == a2 {
		t.Fatal("two seals of the same claims are identical: the nonce is not random")
	}
}

func TestAnyTamperedByteIsRejected(t *testing.T) {
	s := newSealer(t)
	tok := mustSeal(t, s, Access, claims())
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, AccessPrefix))
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for _, mask := range []byte{0x01, 0x80, 0xff} {
			b := append([]byte(nil), raw...)
			b[i] ^= mask
			if _, err := s.Open(Access, AccessPrefix+base64.RawURLEncoding.EncodeToString(b)); err == nil {
				t.Fatalf("byte %d ^ %#x accepted", i, mask)
			}
		}
	}
	for _, cut := range []int{1, 16, len(raw) - 1} {
		if _, err := s.Open(Access, AccessPrefix+base64.RawURLEncoding.EncodeToString(raw[:len(raw)-cut])); err == nil {
			t.Fatalf("token cut by %d bytes accepted", cut)
		}
	}
}

func TestTokenForOneResourceNeverOpensForAnother(t *testing.T) {
	r := mustRing(t, keyDir(t, map[string]string{"k1": randomKey(t)}))
	a := sealerFor(t, r, resourceA)
	for _, other := range []string{"https://mcp.example.com/mcp/", "https://other.example.com/mcp", "https://mcp.example.com/mcp2"} {
		if _, err := sealerFor(t, r, other).Open(Access, mustSeal(t, a, Access, claims())); !errors.Is(err, errOpen) {
			t.Errorf("token for %s opened for %s: %v", resourceA, other, err)
		}
	}
}

func TestTypesNeverCross(t *testing.T) {
	s := newSealer(t)
	code := mustSeal(t, s, Code, claims())
	if _, err := s.Open(Access, code); !errors.Is(err, errWrongType) {
		t.Fatalf("code opened as access: %v", err)
	}
	// Relabelled with the access prefix, it still fails: the type is sealed, not just a prefix.
	relabelled := AccessPrefix + strings.TrimPrefix(code, CodePrefix)
	if _, err := s.Open(Access, relabelled); !errors.Is(err, errOpen) {
		t.Fatalf("relabelled code opened as access: %v", err)
	}
	if _, err := s.Open(Code, mustSeal(t, s, Access, claims())); !errors.Is(err, errWrongType) {
		t.Fatalf("access opened as code: %v", err)
	}
	if _, err := s.Open(Type(9), code); !errors.Is(err, errWrongType) {
		t.Fatalf("unknown type: %v", err)
	}
	if _, err := s.Seal(Type(9), claims()); !errors.Is(err, errWrongType) {
		t.Fatalf("Seal of unknown type: %v", err)
	}
}

func TestHeaderFieldsAreBoundToTheSeal(t *testing.T) {
	r := mustRing(t, keyDir(t, map[string]string{"k1": randomKey(t), "k2": randomKey(t)}))
	s := sealerFor(t, r, resourceA)
	tok := mustSeal(t, s, Access, claims()) // sealed with k2
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, AccessPrefix))
	reencode := func(b []byte) string { return AccessPrefix + base64.RawURLEncoding.EncodeToString(b) }

	swapped := append([]byte(nil), raw...)
	swapped[3] = '1' // header: version, len 2, "k2" → "k1"
	if _, err := s.Open(Access, reencode(swapped)); !errors.Is(err, errOpen) {
		t.Fatalf("key ID swapped to another loaded key: %v", err)
	}
	unknown := append([]byte(nil), raw...)
	unknown[3] = '9'
	if _, err := s.Open(Access, reencode(unknown)); !errors.Is(err, errUnknownKey) {
		t.Fatalf("unknown key ID: %v", err)
	}
	version := append([]byte(nil), raw...)
	version[0] = formatVersion + 1
	if _, err := s.Open(Access, reencode(version)); !errors.Is(err, errVersion) {
		t.Fatalf("other format version: %v", err)
	}
}

func TestMalformedTokensAreRejectedBeforeDecryption(t *testing.T) {
	s := newSealer(t)
	cases := map[string]string{
		"empty":           "",
		"prefix only":     AccessPrefix,
		"no prefix":       strings.TrimPrefix(mustSeal(t, s, Access, claims()), AccessPrefix),
		"JWT":             "eyJhbGciOiJIUzI1NiJ9.e30.sig",
		"padded base64":   AccessPrefix + "AQ==",
		"bad base64":      AccessPrefix + "!!!!",
		"one byte":        AccessPrefix + "AQ",
		"zero key ID":     AccessPrefix + base64.RawURLEncoding.EncodeToString([]byte{formatVersion, 0}),
		"key ID too long": AccessPrefix + base64.RawURLEncoding.EncodeToString([]byte{formatVersion, 40, 'k'}),
		"over MaxLen":     AccessPrefix + strings.Repeat("A", MaxLen),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Open(Access, tok); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRotationKeepsOldTokensUntilTheirKeyIsRemoved(t *testing.T) {
	k1, k2 := randomKey(t), randomKey(t)
	before := sealerFor(t, mustRing(t, keyDir(t, map[string]string{"2026-01": k1})), resourceA)
	old := mustSeal(t, before, Access, claims())

	during := sealerFor(t, mustRing(t, keyDir(t, map[string]string{"2026-01": k1, "2026-06": k2})), resourceA)
	if _, err := during.Open(Access, old); err != nil {
		t.Fatalf("token from the old key rejected during the overlap: %v", err)
	}
	fresh := mustSeal(t, during, Access, claims())
	if _, err := before.Open(Access, fresh); !errors.Is(err, errUnknownKey) {
		t.Fatalf("new token opened by a ring without the new key: %v", err)
	}

	after := sealerFor(t, mustRing(t, keyDir(t, map[string]string{"2026-06": k2})), resourceA)
	if _, err := after.Open(Access, fresh); err != nil {
		t.Fatalf("new token rejected after the old key is removed: %v", err)
	}
	if _, err := after.Open(Access, old); !errors.Is(err, errUnknownKey) {
		t.Fatalf("token of a removed key still opens: %v", err)
	}
}

func TestSealRejectsIncompleteClaims(t *testing.T) {
	s := newSealer(t)
	cases := map[string]func(*Claims){
		"no grant":          func(c *Claims) { c.GrantID = "" },
		"no subject":        func(c *Claims) { c.Subject = "" },
		"no iat":            func(c *Claims) { c.IssuedAt = time.Time{} },
		"exp not after iat": func(c *Claims) { c.ExpiresAt = c.IssuedAt },
		"exp before iat":    func(c *Claims) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			c := claims()
			edit(&c)
			if _, err := s.Seal(Access, c); !errors.Is(err, errClaims) {
				t.Fatalf("Seal = %v, want errClaims", err)
			}
		})
	}
}

func TestNewSealerNeedsARingAndAResource(t *testing.T) {
	r := mustRing(t, keyDir(t, map[string]string{"k1": randomKey(t)}))
	for name, tc := range map[string]struct {
		ring     *KeyRing
		resource string
	}{
		"no ring":       {nil, resourceA},
		"no resource":   {r, ""},
		"huge resource": {r, "https://x/" + strings.Repeat("a", maxResource)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSealer(tc.ring, tc.resource); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
