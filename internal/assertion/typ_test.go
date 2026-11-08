package assertion

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/resource"
)

// The assertion is typ at+jwt (RFC 9068 §2.1) in every header it carries.
func TestTheAssertionIsTypAtJWT(t *testing.T) {
	if Type != "at+jwt" {
		t.Fatalf("Type = %q, want at+jwt", Type)
	}
	k, _ := keys(t)
	m, _ := NewMinter(k, issuer, audience, func() time.Time { return t0 })
	raw, err := m.Mint(resource.Identity{Subject: "s", ClientID: "c", PrincipalType: resource.PrincipalUser})
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := verify(t, k, raw); h.ExtraHeaders["typ"] != "at+jwt" {
		t.Fatalf("typ %v, want at+jwt", h.ExtraHeaders["typ"])
	}
}

// Every JWT byward signs has a typ of its own (ADR-0016 amendment, #207): the metadata's jwks_uri
// advertises the assertion keys, so no other kind of byward-signed JWT may reuse at+jwt and pass
// as an assertion. A new signer must be added here, with a typ nothing else uses.
func TestEveryJWTByWardSignsHasATypOfItsOwn(t *testing.T) {
	signers := map[string]string{ // file → its typ
		"assertion/mint.go": "Type",  // at+jwt, the identity assertion, aud = the upstream
		"idp/clientauth.go": `"JWT"`, // the client assertion to the IdP, aud = its token endpoint
	}
	withType := regexp.MustCompile(`WithType\(([^)]*)\)`)
	found := map[string]string{}
	root := ".."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, "testutil") {
			return err
		}
		src, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own sources
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !strings.Contains(string(src), "jose.NewSigner(") {
			return nil
		}
		m := withType.FindSubmatch(src)
		if m == nil {
			t.Errorf("%s signs a JWT without a typ", rel)
			return nil
		}
		found[rel] = string(m[1])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, typ := range found {
		if want, ok := signers[file]; !ok || typ != want {
			t.Errorf("%s signs JWTs with typ %s; add it to this test with a typ no other signer uses", file, typ)
		}
	}
	for file := range signers {
		if _, ok := found[file]; !ok {
			t.Errorf("%s no longer signs a JWT; update this test", file)
		}
	}
}
