package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/tracing"
)

// Through the wired proxy, a header the operator lists never reaches the upstream while the
// operator credential the proxy sets still does, even when the list names it too.
func TestAListedHeaderNeverReachesTheUpstreamButTheProxysCredentialStillDoes(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600),
		"BYWARD_UPSTREAM_STRIP_HEADERS=x-argocd-base-url,authorization,x_api_key"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header["X_Argocd_Base_Url"] = []string{"https://evil.example"}
	s.Public.Handler.ServeHTTP(httptest.NewRecorder(), r)
	got, ok := up.Last()
	if !ok {
		t.Fatal("the upstream got no request")
	}
	for k := range got.Header {
		if strings.EqualFold(strings.ReplaceAll(k, "_", "-"), "X-Argocd-Base-Url") {
			t.Fatalf("%s reached the upstream", k)
		}
	}
	if got.Header.Get("X-Api-Key") != upstreamCredential {
		t.Fatalf("credential %q: the list must not strip what the proxy sets", got.Header.Get("X-Api-Key"))
	}
}

// The startup log names each entry the relay strips anyway, as a warning with the setting, with and
// without authentication; an entry only the list strips is not named.
func TestTheStartupLogNamesARedundantStripEntry(t *testing.T) {
	strip := "BYWARD_UPSTREAM_STRIP_HEADERS=x-argocd-base-url,authorization,x_api_key"
	for _, tc := range []struct {
		name      string
		env       func(*testing.T) []string
		redundant []string
	}{
		{"without authentication", func(t *testing.T) []string {
			return []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://10.0.0.7/mcp", "BYWARD_INSECURE_NO_AUTH=true",
				"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600), strip}
		}, []string{"Authorization", "X-Api-Key"}},
		{"with authentication", func(t *testing.T) []string {
			return append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://10.0.0.7/mcp", strip)
		}, []string{"Authorization"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := config.Load(nil, tc.env(t), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			s, err := New(cfg, logging.New(&logs, "text"))
			if err != nil {
				t.Fatal(err)
			}
			if s.closeStore != nil {
				t.Cleanup(func() { _ = s.closeStore() })
			}
			for _, n := range tc.redundant {
				if !strings.Contains(logs.String(), `level=WARN msg="`+n+` is stripped from every upstream request already; the entry changes nothing" setting=BYWARD_UPSTREAM_STRIP_HEADERS`) {
					t.Fatalf("the startup log does not warn that %s is already stripped: %s", n, logs.String())
				}
			}
			if strings.Contains(logs.String(), "X-Argocd-Base-Url is stripped") {
				t.Fatal("a header only the list strips is called redundant")
			}
		})
	}
}

// No header the tracing propagator sets can be listed: Inject sets it after the strip, from the
// inbound trace context, so the entry would remove nothing.
func TestNoHeaderTracingSetsCanBeListed(t *testing.T) {
	if len(tracing.Fields()) == 0 {
		t.Fatal("the propagator sets no header, so this test proves nothing")
	}
	for _, f := range tracing.Fields() {
		_, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://10.0.0.7/mcp",
			"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_STRIP_HEADERS=" + f}, os.ReadFile)
		if err == nil || !strings.Contains(err.Error(), "cannot be stripped") {
			t.Errorf("listing %s: %v, want it refused", f, err)
		}
	}
}

// doctor and check --offline name a redundant entry as a warning, with and without authentication.
func TestDoctorAndCheckNameARedundantStripEntry(t *testing.T) {
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}}))
	strip := "BYWARD_UPSTREAM_STRIP_HEADERS=X-Argocd-Base-Url,authorization"
	noAuth, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://10.0.0.7/mcp", "BYWARD_INSECURE_NO_AUTH=true", strip}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	withAuth, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://10.0.0.7/mcp", strip), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*config.Config{"without authentication": noAuth, "with authentication": withAuth} {
		t.Run(name, func(t *testing.T) {
			rep, err := Doctor(context.Background(), cfg, DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}}})
			if err != nil {
				t.Fatal(err)
			}
			var named []string
			for _, c := range rep.Checks {
				if c.Name == "configuration" && strings.Contains(c.Message, "is stripped from every upstream request already") {
					named = append(named, c.Message)
					if c.Status != doctor.Warn || c.Fix != "BYWARD_UPSTREAM_STRIP_HEADERS: remove Authorization from the list" {
						t.Fatalf("%+v, want a warning naming the setting", c)
					}
				}
			}
			if len(named) != 1 || !strings.HasPrefix(named[0], "Authorization ") {
				t.Fatalf("redundant entries named %q, want Authorization alone", named)
			}
			warnings, err := CheckOffline(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var offline []string
			for _, w := range warnings {
				if w.Setting == "BYWARD_UPSTREAM_STRIP_HEADERS" {
					offline = append(offline, w.Message)
				}
			}
			if len(offline) != 1 || !strings.HasPrefix(offline[0], "Authorization ") {
				t.Fatalf("check --offline names %q, want Authorization alone", offline)
			}
		})
	}
}

// Every kind of header the relay strips anyway is named as redundant: built in, hop-by-hop, an
// identity header, the assertion's, the On-Behalf-Of token's and the credential's; one only the
// list strips is not.
func TestEveryHeaderTheRelayStripsAnywayIsNamedAsRedundant(t *testing.T) {
	cfg := &config.Config{AssertionHeader: "X-Assert", OBOHeader: "X-Byward-Downstream-Token", UpstreamCredential: "k-123",
		UpstreamCredentialHeader: "X-Api-Key", UpstreamStripHeaders: []string{"Dpop", "Keep-Alive", "X-Byward-Subject", "X-Assert",
			"X-Byward-Downstream-Token", "X-Api-Key", "X-Argocd-Base-Url"}}
	var named []string
	for _, w := range redundantStrips(cfg) {
		named = append(named, strings.Fields(w.Message)[0])
		if w.Setting != "BYWARD_UPSTREAM_STRIP_HEADERS" || w.Fix != "remove "+strings.Fields(w.Message)[0]+" from the list" {
			t.Fatalf("%+v, want the setting and the fix naming the entry", w)
		}
	}
	if want := cfg.UpstreamStripHeaders[:6]; !slices.Equal(named, want) {
		t.Fatalf("named %q, want %q", named, want)
	}
}
