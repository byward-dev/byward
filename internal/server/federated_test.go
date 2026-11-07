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
	cfg   *config.Config
	fake  *fakeidp.IdP
	token string // the token file's path
}

func newFederated(t *testing.T, credSubject string) federated {
	t.Helper()
	github := fakeidp.NewCertificate(t)
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant), fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID,
		Federated: []fakeidp.FederatedCredential{{Issuer: "https://token.actions.githubusercontent.com", Subject: credSubject,
			Audience: "api://AzureADTokenExchange", Signer: github}}}))
	now := time.Now()
	tok, err := github.SignJWT("RS256", nil, map[string]any{"iss": "https://token.actions.githubusercontent.com", "sub": githubSubject,
		"aud": "api://AzureADTokenExchange", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "federated-token")
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	return federated{cfg: cfg, fake: fake, token: path}
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
	for _, name := range []string{"entra app and credential", "entra access token"} {
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
	if c.Status != doctor.Fail || !strings.Contains(c.Fix, "BYWARD_ENTRA_FEDERATED_TOKEN_FILE must match one of the app's federated identity credentials exactly: issuer, subject and audience") ||
		strings.Contains(c.Fix, "secret") {
		t.Fatalf("%s: %s; fix %q", c.Status, c.Message, c.Fix)
	}
}

// The file is read for every token request, so a renewed token is used without a restart; an
// emptied one fails closed, with no other credential to fall back on.
func TestTheFederatedTokenFileIsReadForEveryRequestAndFailsClosedWhenEmpty(t *testing.T) {
	f := newFederated(t, githubSubject)
	if c := f.credentialCheck(t); c.Status != doctor.Pass {
		t.Fatalf("first token: %s %s", c.Status, c.Message)
	}
	if err := os.WriteFile(f.token, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if c := f.credentialCheck(t); c.Status != doctor.Fail || !strings.Contains(c.Message, "client assertion file is empty") {
		t.Fatalf("empty token file: %s %s", c.Status, c.Message)
	}
}

// The token file is a credential: one other users can read, or one that is missing, refuses
// startup.
func TestALooseOrMissingFederatedTokenFileRefusesToStart(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, path string){
		"readable by others": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: the mode under test
				t.Fatal(err)
			}
		},
		"missing": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFederated(t, githubSubject)
			prepare(t, f.token)
			if _, err := New(f.cfg, discard); err == nil || !strings.Contains(err.Error(), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE") {
				t.Fatalf("New = %v, want the token file refused", err)
			}
		})
	}
}
