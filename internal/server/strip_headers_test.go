package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

// Through the wired proxy, a header the operator lists never reaches the upstream; an entry the
// relay strips anyway is accepted, and the startup log and check --offline say it changes nothing.
func TestTheOperatorsStripListIsAppliedAndARedundantEntryIsNamed(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600),
		"BYWARD_UPSTREAM_STRIP_HEADERS=x-argocd-base-url,authorization,x_api_key"}, os.ReadFile)
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
	warned := func(text string, n string) bool {
		return strings.Contains(text, n+" is stripped from every upstream request already")
	}
	for _, n := range []string{"Authorization", "X-Api-Key"} {
		if !warned(logs.String(), n) || !strings.Contains(logs.String(), "setting=BYWARD_UPSTREAM_STRIP_HEADERS") {
			t.Fatalf("the startup log does not name %s as already stripped: %s", n, logs.String())
		}
	}
	if warned(logs.String(), "X-Argocd-Base-Url") {
		t.Fatal("a header only the list strips is called redundant")
	}
	warnings, err := CheckOffline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var offline []string
	for _, w := range warnings {
		offline = append(offline, w.String())
	}
	if text := strings.Join(offline, "\n"); !warned(text, "Authorization") || !warned(text, "X-Api-Key") {
		t.Fatalf("check --offline warnings %q do not name the redundant entries", offline)
	}
}

// doctor names a redundant entry as a configuration warning, with and without authentication.
func TestDoctorNamesARedundantStripEntry(t *testing.T) {
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: "00000000-0000-0000-0000-000000000002", Secrets: []string{"s3cret-entra"}}))
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
					if c.Status != doctor.Warn || !strings.HasPrefix(c.Fix, "BYWARD_UPSTREAM_STRIP_HEADERS: ") {
						t.Fatalf("%+v, want a warning naming the setting", c)
					}
				}
			}
			if len(named) != 1 || !strings.HasPrefix(named[0], "Authorization ") {
				t.Fatalf("redundant entries named %q, want Authorization alone", named)
			}
		})
	}
}
