package token

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

const resourceA = "https://mcp.example.com/mcp"

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func claims() Claims {
	return Claims{GrantID: "g-1", Subject: "tid-1:oid-1", IssuedAt: t0, ExpiresAt: t0.Add(time.Hour), ClientID: "client-1"}
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
		c := Claims{GrantID: grant, Subject: subject, IssuedAt: time.Unix(int64(iat)+1, 0), ExpiresAt: time.Unix(int64(iat)+1+int64(life)+1, 0), ClientID: "c"}
		for _, typ := range []Type{Access, Code} {
			tok, err := s.Seal(typ, c)
			if err != nil {
				return false
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

// The prefixes are public: secret scanners match them (ADR-0006 §8, ADR-0028). Literals, not the
// constants, so a change to the wire format fails here.
func TestIssuedTokensCarryTheBywPrefixesScannersMatch(t *testing.T) {
	s := newSealer(t)
	refresh, _ := NewRefreshToken()
	for want, tok := range map[string]string{
		"byw_at_": mustSeal(t, s, Access, claims()),
		"byw_ac_": mustSeal(t, s, Code, claims()),
		"byw_rt_": refresh,
	} {
		if !strings.HasPrefix(tok, want) {
			t.Errorf("token %.12q... does not start with %q", tok, want)
		}
	}
}

// The domain-separation labels are part of every sealed value: changing one makes every token,
// sealed store row and login cookie issued before unreadable. They change only with a format
// version bump.
func TestDomainSeparationLabelsAreStable(t *testing.T) {
	if adLabel != "byward token\x00" || boxLabel != "byward box\x00" {
		t.Fatalf("adLabel %q, boxLabel %q changed: bump the token format version instead", adLabel, boxLabel)
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
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, AccessPrefix))
	if err != nil {
		t.Fatal(err)
	}
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
	header := func(b ...byte) string { return AccessPrefix + base64.RawURLEncoding.EncodeToString(b) }
	cases := []struct {
		name, tok string
		want      error
	}{
		{"empty", "", errWrongType},
		{"prefix only", AccessPrefix, errMalformed},
		{"no prefix", strings.TrimPrefix(mustSeal(t, s, Access, claims()), AccessPrefix), errWrongType},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.e30.sig", errWrongType},
		{"padded base64", AccessPrefix + "AQ==", errMalformed},
		{"bad base64", AccessPrefix + "!!!!", errMalformed},
		{"one byte", header(formatVersion), errMalformed},
		{"zero-length key ID", header(formatVersion, 0), errMalformed},
		{"key ID longer than the token", header(formatVersion, 40, 'k'), errMalformed},
		{"over MaxLen, otherwise well formed", header(append([]byte{formatVersion, 2, 'k', '1'}, make([]byte, MaxLen)...)...), errMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Open(Access, tc.tok); !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, want %v", err, tc.want)
			}
		})
	}
}

// Claims that only our own key could seal: the checks after decryption still hold.
func TestSealedButInvalidClaimsAreRejected(t *testing.T) {
	s := newSealer(t)
	k := s.ring.signing
	seal := func(plain string) string {
		b := k.aead.Seal(append([]byte{formatVersion, byte(len(k.id))}, k.id...), nil, []byte(plain), s.ad(Access, k.id)) //nolint:gosec // G407: random-nonce AEAD; nil is required
		return AccessPrefix + base64.RawURLEncoding.EncodeToString(b)
	}
	valid := `{"gid":"g","sub":"u","iat":100,"exp":200,"cid":"c"}`
	if _, err := s.Open(Access, seal(valid)); err != nil {
		t.Fatalf("hand-sealed valid claims rejected: %v", err)
	}
	for name, plain := range map[string]string{
		"not JSON":        "not json",
		"missing fields":  `{"gid":"g"}`,
		"unknown field":   `{"gid":"g","sub":"u","iat":100,"exp":200,"cid":"c","x":1}`,
		"no client ID":    `{"gid":"g","sub":"u","iat":100,"exp":200}`,
		"trailing object": valid + `{}`,
		"zero iat":        `{"gid":"g","sub":"u","iat":0,"exp":200,"cid":"c"}`,
		"exp before iat":  `{"gid":"g","sub":"u","iat":200,"exp":100,"cid":"c"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Open(Access, seal(plain)); !errors.Is(err, errClaims) {
				t.Fatalf("Open = %v, want errClaims", err)
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
		"no grant":              func(c *Claims) { c.GrantID = "" },
		"no subject":            func(c *Claims) { c.Subject = "" },
		"no iat":                func(c *Claims) { c.IssuedAt = time.Time{} },
		"iat at the Unix epoch": func(c *Claims) { c.IssuedAt = time.Unix(0, 0) },
		"iat before 1970":       func(c *Claims) { c.IssuedAt, c.ExpiresAt = time.Unix(-100, 0), time.Unix(100, 0) },
		"exp not after iat":     func(c *Claims) { c.ExpiresAt = c.IssuedAt },
		"exp before iat":        func(c *Claims) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) },
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

// Regressions from the runtime sweep: Seal must never return a token that Open rejects.
func TestSealRefusesWhatOpenWouldReject(t *testing.T) {
	s := newSealer(t)
	huge := claims()
	huge.Subject = strings.Repeat("s", MaxLen)
	if _, err := s.Seal(Access, huge); !errors.Is(err, errTooLong) {
		t.Fatalf("oversized claims: Seal = %v, want errTooLong", err)
	}
	sameSecond := claims()
	sameSecond.IssuedAt, sameSecond.ExpiresAt = time.Unix(100, 1e8), time.Unix(100, 9e8)
	if _, err := s.Seal(Access, sameSecond); !errors.Is(err, errClaims) {
		t.Fatalf("iat and exp in the same second: Seal = %v, want errClaims", err)
	}
	subSecond := claims()
	subSecond.IssuedAt, subSecond.ExpiresAt = time.Unix(100, 9e8), time.Unix(101, 1e8)
	got, err := s.Open(Access, mustSeal(t, s, Access, subSecond))
	if err != nil || !got.IssuedAt.Equal(time.Unix(100, 0)) || !got.ExpiresAt.Equal(time.Unix(101, 0)) {
		t.Fatalf("sub-second times: %+v, %v; want whole seconds", got, err)
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

// Version 2 seals the client ID and the asserted claims; a version 1 token is refused, so a client
// refreshes once after an upgrade (ADR-0016 §1).
func TestAccessTokensRoundTripTheAssertedClaims(t *testing.T) {
	s := newSealer(t)
	c := claims()
	c.Roles, c.Groups, c.Email, c.Name = []string{"byward.user"}, []string{"g1", "g2"}, "a@contoso.example", "Alex"
	got, err := s.Open(Access, mustSeal(t, s, Access, c))
	if err != nil || !got.IssuedAt.Equal(c.IssuedAt) || !got.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatalf("round trip: %+v, %v; want %+v", got, err, c)
	}
	got.IssuedAt, got.ExpiresAt = c.IssuedAt, c.ExpiresAt
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip: %+v; want %+v", got, c)
	}
}

// Tokens sealed before format 2 carry no client or claims: they are refused, and the client
// refreshes once (ADR-0016 §1).
func TestAVersion1AccessTokenIsRefused(t *testing.T) {
	s := newSealer(t)
	k := s.ring.signing
	v1 := []byte{1, byte(len(k.id))}                                                                                    //nolint:gosec // G115: key IDs are at most 64 bytes (keyIDPattern)
	v1 = k.aead.Seal(append(v1, k.id...), nil, []byte(`{"gid":"g","sub":"u","iat":100,"exp":200}`), s.ad(Access, k.id)) //nolint:gosec // G407: random-nonce AEAD; nil is required
	if _, err := s.Open(Access, AccessPrefix+base64.RawURLEncoding.EncodeToString(v1)); !errors.Is(err, errVersion) {
		t.Fatalf("a version 1 token: %v, want errVersion", err)
	}
}

// The upstream's assertion needs the client, so an access token is never sealed without one (the
// "no client ID" case of TestSealedButInvalidClaimsAreRejected is the same rule on Open).
func TestAnAccessTokenWithoutAClientIsNotSealed(t *testing.T) {
	s := newSealer(t)
	c := claims()
	c.ClientID = ""
	if _, err := s.Seal(Access, c); !errors.Is(err, errClaims) {
		t.Fatalf("an access token without a client ID: %v, want errClaims", err)
	}
}

// Sizes the operator sees: with roles only a token stays well under any header limit (8 KiB is
// the smallest common one); with 200 groups opted in (Entra's overage limit) it still fits MaxLen.
func TestAccessTokensFit200GroupsAndRefuse400(t *testing.T) {
	s := newSealer(t)
	c := claims()
	c.Subject = "00000000-0000-0000-0000-000000000000:11111111-1111-1111-1111-111111111111"
	c.ClientID = "https://claude.ai/oauth/claude-code-client-metadata"
	for i := range 20 {
		c.Roles = append(c.Roles, fmt.Sprintf("byward.role-%02d", i))
	}
	rolesOnly := mustSeal(t, s, Access, c)
	if len(rolesOnly) > 1<<10 {
		t.Fatalf("with 20 roles a token is %d bytes, want at most 1 KiB", len(rolesOnly))
	}
	for range 200 {
		c.Groups = append(c.Groups, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	}
	withGroups, err := s.Seal(Access, c)
	if err != nil {
		t.Fatalf("200 groups do not fit: %v", err)
	}
	t.Logf("access token: %d bytes with 20 roles, %d bytes with 200 groups as well", len(rolesOnly), len(withGroups))
	c.Groups = append(c.Groups, c.Groups...)
	if _, err := s.Seal(Access, c); !errors.Is(err, ErrTooLong) {
		t.Fatalf("400 groups: %v, want ErrTooLong", err)
	}
}
