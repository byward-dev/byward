package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// certificateFile writes the proxy's certificate credential, the key and a certificate valid for
// validFor, in a 0600 file, as byward init entra does; it returns the path and the pair for the
// fake IdP's app registration.
func certificateFile(t *testing.T, validFor time.Duration) (string, *fakeidp.Certificate) {
	t.Helper()
	cert := fakeidp.NewCertificateUntil(t, time.Now().Add(validFor))
	file := filepath.Join(t.TempDir(), "entra-client-certificate.pem")
	if err := os.WriteFile(file, cert.PEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return file, cert
}

// certificateEnv is authEnv with the certificate file in place of the client secret.
func certificateEnv(t *testing.T, file string, extra ...string) []string {
	t.Helper()
	env := slices.DeleteFunc(authEnv(t), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE=") })
	return append(append(env, "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+file, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), extra...)
}

func loadCertificateConfig(t *testing.T, file string, extra ...string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load(nil, certificateEnv(t, file, extra...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// With BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE the Entra adapter signs in with the certificate
// (private_key_jwt, which the fake checks by x5t#S256 and PS256, as Entra does), and doctor's probe
// passes with it and reports the certificate's end date (ADR-0012 §5).
func TestTheWiredEntraIdPSignsInWithACertificate(t *testing.T) {
	file, cert := certificateFile(t, 365*24*time.Hour)
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Certificates: []*fakeidp.Certificate{cert}, RedirectURIs: []string{"https://mcp.example.com/callback/entra"}}))
	ip, err := newIdentityProvider(loadCertificateConfig(t, file), fake.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	q := fake.Authorize(t, mustAuthCodeURL(t, ip))
	if _, _, err := ip.adapter.Callback(context.Background(), q, testLogin); err != nil {
		t.Fatalf("sign-in with the certificate: %v", err)
	}
	results := map[string]doctor.Result{}
	for _, r := range ip.diagnose(context.Background(), time.Now()) {
		results[r.Name] = r
	}
	if r := results["entra app and credential"]; r.Status != doctor.Pass {
		t.Fatalf("doctor's probe: %+v", r)
	}
	if r := results["client certificate expiry"]; r.Status != doctor.Pass || !strings.Contains(r.Message, cert.X509.NotAfter.Format(time.DateOnly)) {
		t.Fatalf("certificate expiry: %+v", r)
	}
	if _, ok := results["client secret expiry"]; ok {
		t.Fatal("doctor checks a secret's expiry with a certificate")
	}
}

func mustAuthCodeURL(t *testing.T, ip *identityProvider) string {
	t.Helper()
	u, err := ip.adapter.AuthCodeURL(context.Background(), testLogin)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// A certificate that expires within 30 days is warned of at startup and in check, naming the file's
// setting and how to replace it; one with a year left is not (the boundaries are
// doctor.CertificateExpiry's, tested there).
func TestACertificateCloseToItsEndDateIsWarnedOf(t *testing.T) {
	for name, tc := range map[string]struct {
		validFor time.Duration
		warned   bool
	}{"in 10 days": {10 * 24 * time.Hour, true}, "in a year": {365 * 24 * time.Hour, false}} {
		t.Run(name, func(t *testing.T) {
			file, _ := certificateFile(t, tc.validFor)
			warnings, err := CheckOffline(loadCertificateConfig(t, file))
			if err != nil {
				t.Fatal(err)
			}
			warned := slices.ContainsFunc(warnings, func(w Warning) bool {
				return w.Setting == "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE" && strings.Contains(w.Message, "the client certificate expires on") &&
					strings.Contains(w.Fix, "docs/how-to/entra-certificate.md")
			})
			if warned != tc.warned || (!tc.warned && slices.ContainsFunc(warnings, func(w Warning) bool { return strings.Contains(w.Message, "certificate") })) {
				t.Fatalf("warned %v, want %v: %+v", warned, tc.warned, warnings)
			}
		})
	}
}

// An expired certificate stops the proxy from starting and fails check, but doctor still runs and
// reports it, and revoke-user, which needs no credential, still works: when it has expired is when
// an operator may need them most.
func TestAnExpiredCertificateRefusesToServeButDoctorAndRevokeUserStillWork(t *testing.T) {
	file, _ := certificateFile(t, -time.Hour)
	cfg := loadCertificateConfig(t, file)
	const want = "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the certificate expired on"
	if _, err := CheckOffline(cfg); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("check: %v, want %q", err, want)
	}
	if _, err := New(cfg, discard); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("New: %v, want %q", err, want)
	}
	ip, err := newIdentityProvider(cfg, nil)
	if err != nil {
		t.Fatalf("the identity provider for doctor: %v", err)
	}
	var expiry doctor.Result
	for _, r := range ip.diagnose(context.Background(), time.Now()) {
		if r.Name == "client certificate expiry" {
			expiry = r
		}
	}
	if expiry.Status != doctor.Fail {
		t.Fatalf("doctor's expiry check: %+v", expiry)
	}
	if user, err := RevokeUser(context.Background(), cfg, discard, fixtureTenant+":11111111-1111-1111-1111-11111111111a"); err != nil || user == "" {
		t.Fatalf("revoke-user with an expired certificate: %q, %v", user, err)
	}
}

// A certificate file byward cannot use is refused at startup and by check, naming the setting:
// unreadable by others only, and holding a usable key and certificate.
func TestAnUnusableCertificateFileRefusesToStartNamingTheSetting(t *testing.T) {
	for name, tc := range map[string]struct {
		file func(t *testing.T) string
		want string
	}{
		"readable by other users": {func(t *testing.T) string {
			f, _ := certificateFile(t, 365*24*time.Hour)
			if err := os.Chmod(f, 0o644); err != nil { //nolint:gosec // G302: the loose mode is what the test is about
				t.Fatal(err)
			}
			return f
		}, "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: secret file"},
		"a key without its certificate": {func(t *testing.T) string {
			f, cert := certificateFile(t, 365*24*time.Hour)
			if err := os.WriteFile(f, fakeidp.PrivateKeyPEM(t, cert.Key), 0o600); err != nil { //nolint:gosec // G703: the test's own temp file
				t.Fatal(err)
			}
			return f
		}, "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: no PEM certificate"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := loadCertificateConfig(t, tc.file(t))
			if _, err := CheckOffline(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check: %v, want %q", err, tc.want)
			}
			if _, err := New(cfg, discard); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New: %v, want %q", err, tc.want)
			}
		})
	}
}
