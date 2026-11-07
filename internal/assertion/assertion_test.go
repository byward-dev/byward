package assertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
)

const (
	issuer   = "https://mcp.example.com"
	audience = "http://upstream.internal:3001/mcp"
)

var t0 = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

func noCheck(string) error { return nil }

func writeKey(t *testing.T, dir, id string, sec1 bool) { assertionkey.Write(t, dir, id, sec1) }

func keys(t *testing.T) (*Keys, string) {
	t.Helper()
	dir := t.TempDir()
	writeKey(t, dir, "2026-01-01", true)
	writeKey(t, dir, "2026-11-01", false)
	k, err := LoadKeys(dir, noCheck)
	if err != nil {
		t.Fatal(err)
	}
	return k, dir
}

func TestTheKeyWhoseIDSortsLastSignsAndAllArePublished(t *testing.T) {
	k, _ := keys(t)
	if k.SigningKeyID() != "2026-11-01" || strings.Join(k.KeyIDs(), ",") != "2026-01-01,2026-11-01" {
		t.Fatalf("signing %s, keys %v", k.SigningKeyID(), k.KeyIDs())
	}
	set := k.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys", len(set.Keys))
	}
	for _, j := range set.Keys {
		if !j.IsPublic() || j.Algorithm != "ES256" || j.Use != "sig" {
			t.Fatalf("JWKS key %s: public %v alg %s use %s", j.KeyID, j.IsPublic(), j.Algorithm, j.Use)
		}
	}
}

func TestLoadKeysRefusesWhatCannotSign(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKCS8PrivateKey(p384)
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		check func(string) error
		inErr string
	}{
		{"no directory", func(t *testing.T, dir string) { _ = os.Remove(dir) }, noCheck, "assertion key directory"},
		{"no key files", func(*testing.T, string) {}, noCheck, "has no key files"},
		{"not PEM", func(t *testing.T, dir string) { write(t, dir, "k1", []byte("not a key")) }, noCheck, "k1: not PEM; create one with: openssl ecparam"},
		{"an RSA key", func(t *testing.T, dir string) {
			write(t, dir, "k1", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))
		}, noCheck, "k1: want an ECDSA P-256 private key"},
		{"a P-384 key", func(t *testing.T, dir string) {
			write(t, dir, "k1", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER}))
		}, noCheck, "k1: want an ECDSA P-256 private key"},
		{"a public key", func(t *testing.T, dir string) {
			write(t, dir, "k1", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}))
		}, noCheck, `PEM block "PUBLIC KEY"`},
		{"a name that is no key ID", func(t *testing.T, dir string) { writeKey(t, dir, "key one", false) }, noCheck, "the name is the key ID"},
		{"a file the permission check refuses", func(t *testing.T, dir string) { writeKey(t, dir, "k1", false) },
			func(p string) error { return errors.New("secret file " + p + " has mode 0644") }, "assertion key file: secret file"},
		{"a file too large", func(t *testing.T, dir string) { write(t, dir, "k1", make([]byte, maxKeyFile+1)) }, noCheck, "larger than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			if _, err := LoadKeys(dir, tc.check); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}

// A key file's content never appears in an error: it is a private key.
func TestLoadKeysErrorsNeverQuoteTheKey(t *testing.T) {
	dir := t.TempDir()
	secret := "MHcCAQEEIBsecretsecretsecretsecretsecretsecretsecretsecretoAoGCCqGSM49"
	write(t, dir, "k1", []byte("-----BEGIN EC PRIVATE KEY-----\n"+secret+"\n-----END EC PRIVATE KEY-----\n"))
	if _, err := LoadKeys(dir, noCheck); err == nil || strings.Contains(err.Error(), "secretsecret") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadKeysSkipsDotfilesAndDirectories(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "k1", false)
	write(t, dir, ".hidden", []byte("not a key"))
	if err := os.Mkdir(filepath.Join(dir, "..data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadKeys(dir, noCheck); err != nil || strings.Join(k.KeyIDs(), ",") != "k1" {
		t.Fatalf("keys %v, err %v", k, err)
	}
}

func write(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// verify checks an assertion against the published JWKS, as an upstream does.
func verify(t *testing.T, k *Keys, raw string) (header jose.Header, c map[string]any) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	set := k.JWKS()
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q not in the JWKS", tok.Headers[0].KeyID)
	}
	if err := tok.Claims(keys[0].Key, &c); err != nil {
		t.Fatalf("signature: %v", err)
	}
	return tok.Headers[0], c
}

func TestAnAssertionVerifiesWithThePublishedJWKS(t *testing.T) {
	k, _ := keys(t)
	m, err := NewMinter(k, issuer, audience, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Mint(resource.Identity{Subject: "tid:oid", ClientID: "claude-code", Roles: []string{"byward.user"}})
	if err != nil {
		t.Fatal(err)
	}
	h, c := verify(t, k, raw)
	if h.ExtraHeaders["typ"] != Type || h.KeyID != "2026-11-01" || h.Algorithm != "ES256" {
		t.Fatalf("header %+v", h)
	}
	if c["aud"] != audience || c["iss"] != issuer || c["exp"].(float64)-c["iat"].(float64) != Lifetime.Seconds() {
		t.Fatalf("claims %v", c)
	}
	for _, absent := range []string{"groups", "email", "name"} {
		if _, ok := c[absent]; ok {
			t.Errorf("claim %s is set though the identity has none", absent)
		}
	}
	other, _ := m.Mint(resource.Identity{Subject: "tid:oid", ClientID: "claude-code"})
	if _, c2 := verify(t, k, other); c2["jti"] == c["jti"] {
		t.Fatal("two assertions share a jti")
	}
}

func TestMintRefusesAnIdentityWithoutSubjectOrClient(t *testing.T) {
	k, _ := keys(t)
	m, err := NewMinter(k, issuer, audience, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Mint(resource.Identity{Subject: "s", ClientID: "c"}); err != nil {
		t.Fatalf("the same minter refuses a full identity: %v", err)
	}
	for _, id := range []resource.Identity{{ClientID: "c"}, {Subject: "s"}} {
		if _, err := m.Mint(id); err == nil {
			t.Errorf("minted for %+v", id)
		}
	}
	if _, err := NewMinter(k, issuer, "", nil); err == nil {
		t.Error("a minter without an audience")
	}
}

// The claims contract is public interface (ADR-0016 Consequences): RFC 9068 claims are fixed and
// ours are only ever added. The golden file pins the decoded header and claims; jti is random.
func TestAnAssertionCarriesExactlyTheDocumentedHeaderAndClaims(t *testing.T) {
	k, _ := keys(t)
	m, _ := NewMinter(k, issuer, audience, func() time.Time { return t0 })
	raw, err := m.Mint(resource.Identity{Subject: "00000000-0000-0000-0000-000000000001:11111111-1111-1111-1111-111111111111",
		ClientID: "https://claude.ai/oauth/claude-code-client-metadata", Roles: []string{"byward.user"},
		Groups: []string{"22222222-2222-2222-2222-222222222222"}, Email: "alex@contoso.example", EmailVerified: true, Name: "Alex"})
	if err != nil {
		t.Fatal(err)
	}
	h, c := verify(t, k, raw)
	if jti, _ := c["jti"].(string); len(jti) != 22 {
		t.Fatalf("jti %q, want 128 random bits", jti)
	}
	c["jti"] = "<random>"
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"header": map[string]any{"alg": h.Algorithm, "kid": h.KeyID, "typ": h.ExtraHeaders["typ"]}, "claims": c}); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSuffix(buf.String(), "\n")
	golden := filepath.Join("testdata", "assertion.golden.json")
	if os.Getenv("BYWARD_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(got+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // G304: the test's own golden file
	if err != nil || string(want) != string(got)+"\n" {
		t.Fatalf("%s is stale (BYWARD_UPDATE_GOLDEN=1 regenerates it):\ngot\n%s", golden, got)
	}
}

// email_verified comes with email and only with it, so the upstream sees whether the IdP vouched
// for the address.
func TestAnAssertionSaysWhetherItsEmailIsVerified(t *testing.T) {
	k, _ := keys(t)
	m, _ := NewMinter(k, issuer, audience, func() time.Time { return t0 })
	for _, tc := range []struct {
		name string
		id   resource.Identity
		want any // nil: no email_verified claim
	}{
		{"verified", resource.Identity{Email: "alex@contoso.example", EmailVerified: true}, true},
		{"unverified", resource.Identity{Email: "alex@contoso.example"}, false},
		{"no email", resource.Identity{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.id.Subject, tc.id.ClientID = "user", "app"
			raw, err := m.Mint(tc.id)
			if err != nil {
				t.Fatal(err)
			}
			if _, c := verify(t, k, raw); c["email_verified"] != tc.want {
				t.Fatalf("email_verified %v, want %v", c["email_verified"], tc.want)
			}
		})
	}
}

func TestTheJWKSIsServedCacheable(t *testing.T) {
	k, _ := keys(t)
	rec := httptest.NewRecorder()
	k.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set jose.JSONWebKeySet
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "public, max-age=300" || rec.Header().Get("Content-Type") != "application/json" ||
		json.Unmarshal(rec.Body.Bytes(), &set) != nil || len(set.Keys) != 2 {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"d"`) {
		t.Fatal("the JWKS carries a private key")
	}
}

// BenchmarkMint is the cost every MCP request to an HTTP upstream pays (ADR-0024 §10; the budget is
// 2 ms p99 added latency per request).
func BenchmarkMint(b *testing.B) {
	dir := b.TempDir()
	assertionkey.Write(b, dir, "k1", false)
	k, err := LoadKeys(dir, noCheck)
	if err != nil {
		b.Fatal(err)
	}
	m, _ := NewMinter(k, issuer, audience, nil)
	id := resource.Identity{Subject: "00000000-0000-0000-0000-000000000001:11111111-1111-1111-1111-111111111111",
		ClientID: "https://claude.ai/oauth/claude-code-client-metadata", Roles: []string{"byward.user"}}
	for b.Loop() {
		if _, err := m.Mint(id); err != nil {
			b.Fatal(err)
		}
	}
}
