package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/token"
)

// upstreamCredential is a raw API key: with a "Bearer " prefix the logger would redact it anyway,
// and a leak would not show.
const upstreamCredential = "op-key-7f3a"

// credentialFile writes the operator's upstream credential, as the operator would: mode 0600.
func credentialFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "upstream-credential")
	if err := os.WriteFile(p, []byte(upstreamCredential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // the mode exactly, whatever the umask
		t.Fatal(err)
	}
	return p
}

// The upstream gets the operator's credential and the identity assertion, each in its own header,
// and a client can supply neither, in any spelling (ADR-0016 §4, §7).
func TestTheUpstreamGetsTheOperatorCredentialBesideTheAssertion(t *testing.T) {
	for _, tc := range []struct {
		name, credHeader, assertionHeader string
		env                               []string
		forged                            http.Header // besides the proxy token in Authorization
		forgedSpelling                    string      // the copy only the strip removes
	}{
		{"credential in Authorization", "Authorization", "X-Byward-Identity", []string{"BYWARD_ASSERTION_HEADER=X-Byward-Identity"},
			http.Header{"X_byward_identity": {"forged"}}, "X_byward_identity"},
		{"credential in its own header", "X-Api-Key", "Authorization", []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			http.Header{"X-Api-Key": {"forged"}, "X_api_key": {"forged"}}, "X_api_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAsserting(t, append(tc.env, "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credentialFile(t, 0o600))...)
			got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "claude-code"}, tc.forged)
			if v := got.Header.Values(tc.credHeader); len(v) != 1 || v[0] != upstreamCredential {
				t.Fatalf("%s at the upstream: %q, want only the operator's credential", tc.credHeader, v)
			}
			if _, ok := got.Header[tc.forgedSpelling]; ok {
				t.Fatalf("the client's %s reached the upstream", tc.forgedSpelling)
			}
			raw, ok := strings.CutPrefix(got.Header.Get(tc.assertionHeader), "Bearer ")
			if !ok {
				t.Fatalf("%s at the upstream: %q, want the assertion", tc.assertionHeader, got.Header.Get(tc.assertionHeader))
			}
			if c := verified(t, jwks(t, a.public, "mcp.example.com"), raw, a.cfg.UpstreamURL.String()); c["sub"] != "tid:oid" {
				t.Fatalf("assertion claims %v", c)
			}
			if strings.Contains(a.logs.String(), "op-key-7f3a") {
				t.Fatalf("the credential is in the log:\n%s", a.logs)
			}
		})
	}
}

// Without authentication there is no assertion, and the credential may use Authorization; the
// client's token still never reaches the upstream.
func TestWithoutAuthenticationTheUpstreamGetsOnlyTheOperatorCredential(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600)}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s, err := New(cfg, logging.New(&logs, "text"))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer the-clients-token")
	s.Public.Handler.ServeHTTP(httptest.NewRecorder(), r)
	got, ok := up.Last()
	if !ok {
		t.Fatal("the upstream got no request")
	}
	if v := got.Header.Values("Authorization"); len(v) != 1 || v[0] != upstreamCredential {
		t.Fatalf("Authorization at the upstream: %q, want only the operator's credential", v)
	}
	if strings.Contains(logs.String(), "op-key-7f3a") {
		t.Fatalf("the credential is in the log:\n%s", logs.String())
	}
}

// The credential file is a secret file: one others can read refuses startup, with authentication
// and without (ADR-0020 §4).
func TestALooseUpstreamCredentialFileRefusesToStart(t *testing.T) {
	file := "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o644)
	for name, env := range map[string][]string{
		"authenticated": append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", file),
		"without authentication": {"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_INSECURE_NO_AUTH=true", file},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := config.Load(nil, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(cfg, slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_CREDENTIAL_FILE: secret file") || !strings.Contains(err.Error(), "so other users can read it") {
				t.Fatalf("New = %v, want the loose credential file refused", err)
			}
		})
	}
}

// doctor says a credential is set and where it goes, never what it is.
func TestDoctorReportsTheUpstreamCredentialWithoutItsValue(t *testing.T) {
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600)}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Doctor(context.Background(), cfg, DoctorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var msg string
	for _, c := range report.Checks {
		if c.Name == "upstream" {
			msg = c.Message
		}
	}
	if !strings.Contains(msg, "the operator's upstream credential is set and sent in X-Api-Key") || strings.Contains(msg, "op-key-7f3a") {
		t.Fatalf("upstream check: %q", msg)
	}
}
