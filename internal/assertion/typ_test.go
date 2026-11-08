package assertion

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	k, _ := keys(t) // keys fails the test itself on an error
	m, err := NewMinter(k, issuer, audience, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
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
	signers := map[string][]string{ // file → the typ of each signer in it, in order
		"internal/assertion/mint.go": {"Type"},  // at+jwt, the identity assertion, aud = the upstream
		"internal/idp/clientauth.go": {`"JWT"`}, // the client assertion to the IdP, aud = its token endpoint
	}
	withType := regexp.MustCompile(`WithType\(([^)]*)\)`)
	found := map[string][]string{}
	root := filepath.Join("..", "..") // the repository: internal/ and cmd/
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "build" || d.Name() == "node_modules" || d.Name() == "testutil") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own sources
		if err != nil {
			return err
		}
		n := strings.Count(string(src), "jose.NewSigner(")
		if n == 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		var typs []string
		for _, m := range withType.FindAllSubmatch(src, -1) {
			typs = append(typs, string(m[1]))
		}
		if len(typs) != n {
			t.Errorf("%s has %d JWT signers and %d typ options: every signer needs a typ of its own", rel, n, len(typs))
		}
		found[rel] = typs
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, typs := range found {
		if want, ok := signers[file]; !ok || !slices.Equal(typs, want) {
			t.Errorf("%s signs JWTs with typ %v; add it to this test with a typ no other signer uses", file, typs)
		}
	}
	for file := range signers {
		if _, ok := found[file]; !ok {
			t.Errorf("%s no longer signs a JWT; update this test", file)
		}
	}
}
