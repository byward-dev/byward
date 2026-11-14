package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// An IdP with a certificate from a private CA is reached when SSL_CERT_FILE names that CA, and not
// without it (#308, docs/how-to/private-ca.md): doctor's discovery through the production IdP
// client, with an https issuer outside development mode. Go loads the roots once per process, so
// each setting runs in a child process.
func TestAnIdPOnAPrivateCAIsTrustedThroughSSLCertFile(t *testing.T) {
	if rerun.Child() {
		env := append(oidcEnv(t, "oidc", os.Getenv("PRIVATE_CA_TEST_ISSUER"), os.Getenv("PRIVATE_CA_TEST_CLIENT"), "s3cret"),
			"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
		cfg, _, err := config.Load(nil, env, os.ReadFile)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := Doctor(context.Background(), cfg, DoctorOptions{Proxy: &http.Client{Transport: refuse{}},
			Resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, nil }})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Checks {
			if r.Name == "discovery" || r.Name == "trust store" {
				fmt.Printf("%s: %s: %s\n", r.Name, r.Status, r.Message)
			}
		}
		return
	}
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}}
	idp := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app), fakeidp.WithTLS())
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() // a directory of the CA alone, which leaves out the public roots
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// On macOS either setting replaces the system's verifier, which the trust store line warns of.
	platformVerifier := runtime.GOOS == "darwin"
	trusted := "trust store: pass: roots from SSL_CERT_FILE " + ca + " (1 certificate(s)): " // and how many in all
	dropped := "trust store: warn: SSL_CERT_FILE names " + ca + " and SSL_CERT_DIR " + dir + " lists neither /etc/ssl/certs nor /etc/pki/tls/certs"
	defaults := "trust store: pass: roots from the system's default locations"
	if platformVerifier {
		only := "trust store: warn: SSL_CERT_FILE or SSL_CERT_DIR replaces the system's verifier here, so Go trusts only SSL_CERT_FILE " + ca + " (1 certificate(s))"
		trusted, dropped, defaults = only, only+" and SSL_CERT_DIR "+dir, "trust store: pass: roots from the system's verifier"
	}
	for _, tc := range []struct {
		name, certFile, certDir string
		discovery               string // the discovery line's start
		trustStore              string // a part of the trust store line
	}{
		{"with SSL_CERT_FILE naming the CA", ca, "", "discovery: pass:", trusted},
		{"without it", "", "", "discovery: fail: ", defaults},
		{"with the CA file and a directory that leaves out the public roots", ca, dir, "discovery: pass:", dropped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := rerun.Run(t, "TestAnIdPOnAPrivateCAIsTrustedThroughSSLCertFile", append(rerun.ProxyEnv(""),
				"SSL_CERT_FILE="+tc.certFile, "SSL_CERT_DIR="+tc.certDir, "PRIVATE_CA_TEST_ISSUER="+idp.Issuer(), "PRIVATE_CA_TEST_CLIENT="+app.ID)...)
			if !strings.Contains(out, tc.discovery) || !strings.Contains(out, tc.trustStore) {
				t.Fatalf("child output %q; want %q and %q", out, tc.discovery, tc.trustStore)
			}
			if tc.certFile == "" && !strings.Contains(out, "tls: failed to verify certificate") {
				t.Fatalf("child output %q; want discovery to fail on the IdP's certificate", out)
			}
		})
	}
}
