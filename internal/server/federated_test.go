package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// githubSubject is a GitHub Actions `sub` in the immutable, ID-based form a job in the real-entra
// environment gets.
const githubSubject = "repo:byward-dev@1000001/byward@2000002:environment:real-entra"

// federated is a run of the lane in miniature: a "GitHub" token in a file, and the fake Entra with
// a federated identity credential for it on the proxy's app.
type federated struct {
	cfg    *config.Config
	fake   *fakeidp.IdP
	github *fakeidp.Certificate // "GitHub's" signing key
	token  string               // the token file's path
}

// writeGitHubToken writes a GitHub Actions OIDC token for githubSubject, issued age ago, to path.
func writeGitHubToken(t *testing.T, github *fakeidp.Certificate, path string, age time.Duration) {
	t.Helper()
	iat := time.Now().Add(-age)
	tok, err := github.SignJWT("RS256", nil, map[string]any{"iss": "https://token.actions.githubusercontent.com", "sub": githubSubject,
		"aud": "api://AzureADTokenExchange", "iat": iat.Unix(), "exp": iat.Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newFederated(t *testing.T, credSubject string) federated {
	t.Helper()
	github := fakeidp.NewCertificate(t)
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant), fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID,
		Federated: []fakeidp.FederatedCredential{{Issuer: "https://token.actions.githubusercontent.com", Subject: credSubject,
			Audience: "api://AzureADTokenExchange", Signer: github}}}))
	path := filepath.Join(t.TempDir(), "federated-token")
	writeGitHubToken(t, github, path, 0)
	var env []string
	for _, kv := range authEnv(t) {
		if !strings.HasPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE=") {
			env = append(env, kv)
		}
	}
	env = append(env, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_ENTRA_FEDERATED_TOKEN_FILE="+path)
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return federated{cfg: cfg, fake: fake, github: github, token: path}
}

// checks runs doctor and returns its checks by name.
func (f federated) checks(t *testing.T) map[string]doctor.Result {
	t.Helper()
	rep, err := Doctor(context.Background(), f.cfg, DoctorOptions{IdP: f.fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]doctor.Result{}
	for _, c := range rep.Checks {
		out[c.Name] = c
	}
	return out
}

func (f federated) credentialCheck(t *testing.T) doctor.Result {
	t.Helper()
	c, ok := f.checks(t)["entra app and credential"]
	if !ok {
		t.Fatal("doctor ran no credential check")
	}
	return c
}

// With a federated token in place of a client secret, Entra accepts the proxy's app when a
// federated identity credential matches the token exactly (ADR-0012 §5), as the real-Entra lane
// relies on; with no secret, there is no secret expiry to report.
func TestDoctorSignsInToEntraWithAFederatedToken(t *testing.T) {
	got := newFederated(t, githubSubject).checks(t)
	// The checks scripts/real-entra/run.sh requires to pass.
	for _, name := range []string{"entra tenant", "entra signing keys", "entra app and credential", "entra access token", "entra idtyp claim"} {
		if c := got[name]; c.Status != doctor.Pass {
			t.Errorf("%s: %s %s", name, c.Status, c.Message)
		}
	}
	if c, ok := got["client secret expiry"]; ok {
		t.Errorf("a secret expiry check without a secret: %+v", c)
	}
}

// A federated credential for another subject is no credential: doctor fails and says what must
// match, naming the setting, never a client secret.
func TestDoctorSaysWhatMustMatchWhenNoFederatedCredentialDoes(t *testing.T) {
	c := newFederated(t, "repo:byward-dev/byward:ref:refs/heads/main").credentialCheck(t)
	// The fix's wording is the Entra doctor's tests'; here, that it names this setting, and that the
	// fake refused for the credential (not, say, a bad signature: AADSTS700027).
	if c.Status != doctor.Fail || !strings.Contains(c.Fix, "BYWARD_ENTRA_FEDERATED_TOKEN_FILE must match") || strings.Contains(c.Message, "AADSTS700027") ||
		strings.Contains(c.Fix, "secret") {
		t.Fatalf("%s: %s; fix %q", c.Status, c.Message, c.Fix)
	}
}

// A renewed token is used without a restart (the GitHub token outlives no run), and an emptied
// file fails closed, with no other credential to fall back on.
func TestARenewedFederatedTokenIsUsedAndAnEmptiedOneFailsClosed(t *testing.T) {
	f := newFederated(t, githubSubject)
	writeGitHubToken(t, f.github, f.token, 6*time.Minute) // expired
	if c := f.credentialCheck(t); c.Status != doctor.Fail {
		t.Fatalf("expired token: %s %s", c.Status, c.Message)
	}
	writeGitHubToken(t, f.github, f.token, 0) // renewed in place
	if c := f.credentialCheck(t); c.Status != doctor.Pass {
		t.Fatalf("renewed token: %s %s", c.Status, c.Message)
	}
	if err := os.WriteFile(f.token, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if c := f.credentialCheck(t); c.Status != doctor.Fail || !strings.Contains(c.Message, "client assertion file is empty") ||
		!strings.Contains(c.Fix, "BYWARD_ENTRA_FEDERATED_TOKEN_FILE must exist") {
		t.Fatalf("empty token file: %s %s", c.Status, c.Message)
	}
}

// The token file is a credential: one other users can read refuses startup (except with --dev, as
// every secret file), and a missing one refuses it even with --dev.
func TestALooseFederatedTokenFileRefusesToStartOutsideDevAndAMissingOneAlways(t *testing.T) {
	loosen := func(t *testing.T, path string) {
		if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: the mode under test
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		dev     bool
		prepare func(t *testing.T, path string)
		inErr   string // "" when the proxy starts
	}{
		{"readable by others", false, loosen, "has mode 0644, so other users can read it"},
		{"readable by others, --dev", true, loosen, ""},
		{"missing", false, removeFile, "no such file or directory"},
		{"missing, --dev", true, removeFile, "no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFederated(t, githubSubject)
			f.cfg.Dev = tc.dev
			tc.prepare(t, f.token)
			s, err := New(f.cfg, discard)
			if tc.inErr == "" {
				if err != nil {
					t.Fatalf("New = %v, want it to start", err)
				}
				_ = s.closeStore()
				return
			}
			if err == nil || !strings.Contains(err.Error(), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE") || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("New = %v, want the token file refused with %q", err, tc.inErr)
			}
		})
	}
}

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
