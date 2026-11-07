// Command assertionfixture writes what the identity assertion contract lane (scripts/assertion)
// verifies with the TypeScript SDK and FastMCP: a JWKS as the proxy serves it, and assertions minted
// by the proxy's code that a verifier must accept or refuse.
//
//	go run ./internal/testutil/assertionfixture <dir>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/resource"
)

const (
	issuer   = "https://mcp.example.com"
	audience = "http://mcp-upstream.internal:3001/mcp"
	subject  = "00000000-0000-0000-0000-000000000001:11111111-1111-1111-1111-111111111111"
	clientID = "claude-code"
)

// fixture is tokens.json: every case a verifier must accept (valid) or refuse (the others).
type fixture struct {
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	Subject       string `json:"subject"`
	ClientID      string `json:"client_id"`
	Valid         string `json:"valid"`
	WrongAudience string `json:"wrong_audience"`
	Expired       string `json:"expired"`
	OtherKey      string `json:"other_key"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: assertionfixture <dir>")
		os.Exit(2)
	}
	if err := write(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "assertionfixture:", err)
		os.Exit(1)
	}
}

func write(dir string) error {
	keys, err := newKeys(filepath.Join(dir, "keys"))
	if err != nil {
		return err
	}
	other, err := newKeys(filepath.Join(dir, "other-keys"))
	if err != nil {
		return err
	}
	id := resource.Identity{Subject: subject, ClientID: clientID, PrincipalType: resource.PrincipalUser, Roles: []string{"byward.user"}}
	mint := func(k *assertion.Keys, aud string, now time.Time) (string, error) {
		m, err := assertion.NewMinter(k, issuer, aud, func() time.Time { return now })
		if err != nil {
			return "", err
		}
		return m.Mint(id)
	}
	f := fixture{Issuer: issuer, Audience: audience, Subject: subject, ClientID: clientID}
	now := time.Now()
	for _, c := range []struct {
		dst *string
		k   *assertion.Keys
		aud string
		at  time.Time
	}{
		{&f.Valid, keys, audience, now},
		{&f.WrongAudience, keys, "http://other-upstream.internal/mcp", now},
		{&f.Expired, keys, audience, now.Add(-assertion.Lifetime - 2*time.Minute)},
		{&f.OtherKey, other, audience, now},
	} {
		if *c.dst, err = mint(c.k, c.aud, c.at); err != nil {
			return err
		}
	}
	jwks, err := json.Marshal(keys.JWKS())
	if err != nil {
		return err
	}
	tokens, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "jwks.json"), jwks, 0o644); err != nil { //nolint:gosec // G306: a public key set for the verifier containers
		return err
	}
	return os.WriteFile(filepath.Join(dir, "tokens.json"), tokens, 0o644) //nolint:gosec // G306: test assertions for the verifier containers
}

// newKeys writes one P-256 key, "k1", into dir and loads it; both key sets use the same ID, so only
// the signature tells them apart.
func newKeys(dir string) (*assertion.Keys, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: the lane's own build directory, from the command line
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "k1"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil { //nolint:gosec // G703: as above
		return nil, err
	}
	return assertion.LoadKeys(dir, func(string) error { return nil })
}
