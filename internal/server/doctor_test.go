package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const fixtureClientID = "00000000-0000-0000-0000-000000000002"

func TestCheckOfflineAcceptsAWorkingConfigurationAndWritesNothing(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp")
	warnings, err := CheckOffline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.StoreDir); !os.IsNotExist(err) {
		t.Fatalf("check --offline created the state directory (%v)", err)
	}
	var texts []string
	for _, w := range warnings {
		texts = append(texts, w.String())
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{"access gate is empty", "consent page uses generic wording (BYWARD_SCOPE_DESCRIPTION: set it"} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings %q lack %q", all, want)
		}
	}
}

func TestCheckOfflineFindsWhatStartupWould(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, env []string) []string
		inErr string
	}{
		{"no keys directory", func(t *testing.T, env []string) []string {
			return append(env, "BYWARD_KEYS_DIR="+filepath.Join(t.TempDir(), "missing"))
		}, "BYWARD_KEYS_DIR"},
		{"clients file missing", func(t *testing.T, env []string) []string {
			return append(env, "BYWARD_STATIC_CLIENTS_FILE="+filepath.Join(t.TempDir(), "none.json"))
		}, "BYWARD_STATIC_CLIENTS_FILE"},
		{"a Google-only gate list with Entra", func(_ *testing.T, env []string) []string {
			return append(env, "BYWARD_GATE_HOSTED_DOMAINS=example.com")
		}, "BYWARD_GATE_HOSTED_DOMAINS"},
		{"client denylist entry that is neither a URL nor a host", func(_ *testing.T, env []string) []string {
			return append(env, "BYWARD_CLIENT_DENYLIST=not a host")
		}, "BYWARD_CLIENT_DENYLIST: \"not a host\" is neither"},
		{"secret file readable by other users", func(t *testing.T, env []string) []string {
			for _, kv := range env {
				if f, ok := strings.CutPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE="); ok {
					if err := os.Chmod(f, 0o640); err != nil { //nolint:gosec // G302: the loose mode is what the test is about
						t.Fatal(err)
					}
				}
			}
			return env
		}, "BYWARD_ENTRA_CLIENT_SECRET_FILE: secret file"},
		{"an app-only caller allowlist entry that is not a GUID", func(_ *testing.T, env []string) []string {
			return append(env, "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=byward.app", "BYWARD_APP_CLIENT_IDS=my-app")
		}, `BYWARD_APP_CLIENT_IDS: "my-app" is not a GUID`},
		{"counter file in a directory that does not exist", func(t *testing.T, env []string) []string {
			return append(env, "BYWARD_STORE_COUNTER_FILE="+filepath.Join(t.TempDir(), "missing", "store-writes"))
		}, "BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the counter file's directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.setup(t, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"))
			cfg, _, err := config.Load(nil, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CheckOffline(cfg); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}

func TestCheckOfflineWarnsOfAnExpiringSecret(t *testing.T) {
	soon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.DateOnly)
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT="+soon)
	warnings, err := CheckOffline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if w.Setting == "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT" && strings.Contains(w.Message, "expires on "+soon) {
			return
		}
	}
	t.Fatalf("no expiry warning in %v", warnings)
}

func TestCheckOfflineWithoutAuthSaysOnlyTheSettingsWereChecked(t *testing.T) {
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_INSECURE_NO_AUTH=true"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := CheckOffline(cfg); err != nil || len(w) != 1 || !strings.Contains(w[0].Message, "authentication is off") {
		t.Fatalf("warnings %v, err %v", w, err)
	}
}

// running is the real proxy on a test listener, configured for its own URL, with Entra a fake.
type running struct {
	cfg  *config.Config
	fake *fakeidp.IdP
}

func runProxy(t *testing.T, extra ...string) running {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + srv.Listener.Addr().String() + "/mcp"
	cfg := loadConfig(t, publicURL, append([]string{"BYWARD_DEV=true"}, extra...)...)
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.closeStore() })
	srv.Config.Handler = s.Public.Handler
	srv.Start()
	t.Cleanup(srv.Close)
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}}))
	return running{cfg: cfg, fake: fake}
}

func (r running) doctor(t *testing.T) map[string]doctor.Result {
	t.Helper()
	rep, err := Doctor(context.Background(), r.cfg, DoctorOptions{IdP: r.fake.HTTPClient()})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]doctor.Result{}
	for _, c := range rep.Checks {
		out[c.Name] = c
	}
	return out
}

// With app-only tokens on, doctor's hand check of the app roles names the app gate's roles too.
func TestDoctorNamesTheAppRolesWhenAppOnlyTokensAreOn(t *testing.T) {
	r := runProxy(t, "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=byward.app")
	if got := r.doctor(t)["entra app roles"]; !strings.Contains(got.Fix, "with Application among their members: byward.app") {
		t.Fatalf("entra app roles: %+v", got)
	}
}

// The self-probe and the proxy agree: every proxy check passes against the real handler.
func TestDoctorOfAHealthyDeploymentPasses(t *testing.T) {
	r := runProxy(t, "BYWARD_SCOPE_DESCRIPTION=Read your dashboards.")
	rep, err := Doctor(context.Background(), r.cfg, DoctorOptions{IdP: r.fake.HTTPClient()})
	if err != nil {
		t.Fatal(err)
	}
	if code := rep.ExitCode(); code != 0 {
		var b strings.Builder
		rep.WriteText(&b)
		t.Fatalf("exit code %d:\n%s", code, b.String())
	}
	got := r.doctor(t)
	for _, name := range []string{"protected resource metadata (path-inserted)", "protected resource metadata (root)",
		"authorization server metadata (RFC 8414)", "authorization server metadata (OpenID)", "unauthenticated MCP request", "Host header",
		"entra tenant", "entra signing keys", "entra app and credential", "entra access token", "identity assertion keys (discovery)"} {
		if got[name].Status != doctor.Pass {
			t.Errorf("%s: %+v", name, got[name])
		}
	}
	if got["client secret expiry"].Status != doctor.Skip {
		t.Errorf("secret expiry without the setting: %+v", got["client secret expiry"])
	}
	if got["configuration"].Status != doctor.Warn || !strings.Contains(got["configuration"].Message, "access gate is empty") {
		t.Errorf("empty gate: %+v, want a warning", got["configuration"])
	}
}

func TestDoctorExitsWithTheIdPBitWhenEntraRejectsTheSecret(t *testing.T) {
	r := runProxy(t)
	r.fake.Set(fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.InvalidClientSecret))
	rep, err := Doctor(context.Background(), r.cfg, DoctorOptions{IdP: r.fake.HTTPClient()})
	if err != nil {
		t.Fatal(err)
	}
	if code := rep.ExitCode(); code != doctor.ExitIdP {
		t.Fatalf("exit code %d, want %d", code, doctor.ExitIdP)
	}
}

type refuse struct{}

func (refuse) RoundTrip(*http.Request) (*http.Response, error) { return nil, http.ErrServerClosed }

func TestDoctorReportsTheSecretExpiry(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour).UTC().Format(time.DateOnly)
	r := runProxy(t, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT="+past)
	got := r.doctor(t)
	if c := got["client secret expiry"]; c.Status != doctor.Fail || !strings.Contains(c.Fix, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT") {
		t.Fatalf("%+v", c)
	}
	if c := got["configuration"]; strings.Contains(c.Message, "expired") {
		t.Fatalf("the expiry is reported twice: %+v", c)
	}
}

func TestDoctorNamesTheSettingsInFixes(t *testing.T) {
	r := runProxy(t)
	r.fake.Set(fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.UnknownClient))
	if c := r.doctor(t)["entra app and credential"]; !strings.Contains(c.Fix, "set BYWARD_ENTRA_CLIENT_ID") {
		t.Fatalf("%+v", c)
	}
	r.fake.Set(fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.InvalidClientSecret))
	if c := r.doctor(t)["entra app and credential"]; !strings.Contains(c.Fix, "BYWARD_ENTRA_CLIENT_SECRET_FILE") {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorWithoutAuthChecksOnlyTheUpstreamAndTheTrustStoreAndWarns(t *testing.T) {
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_INSECURE_NO_AUTH=true"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Doctor(context.Background(), cfg, DoctorOptions{Proxy: &http.Client{Transport: refuse{}}})
	if err != nil || len(rep.Checks) != 3 || rep.Checks[0].Name != "upstream" || rep.Checks[1].Name != "trust store" || rep.Checks[2].Name != "authentication" || rep.Checks[2].Status != doctor.Warn ||
		!strings.Contains(rep.Checks[2].Message, "authentication is off") || rep.ExitCode() != 0 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
}

func TestStartupLogsAnExpiredSecret(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=2020-01-01")
	var logs strings.Builder
	s, err := New(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.closeStore() })
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec struct{ Level, Msg, Setting string }
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Level == "WARN" && rec.Setting == "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT" && strings.Contains(rec.Msg, "expired on 2020-01-01") {
			return
		}
	}
	t.Fatalf("no expiry warning in the startup log:\n%s", logs.String())
}

// Doctor checks the store paths as check --offline does, and stops before probing anything.
func TestDoctorStopsAtAStorePathErrorBeforeAnyCheck(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_STORE_COUNTER_FILE="+filepath.Join(t.TempDir(), "missing", "store-writes"))
	rep, err := Doctor(context.Background(), cfg, DoctorOptions{IdP: &http.Client{Transport: refuse{}}, Proxy: &http.Client{Transport: refuse{}}})
	if err == nil || !strings.Contains(err.Error(), "BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE") || len(rep.Checks) != 0 {
		t.Fatalf("err %v, checks %v", err, rep.Checks)
	}
}

// stdioEnv configures a stdio upstream whose command, if it ever ran, would leave a marker file.
func stdioEnv(t *testing.T, base []string) (env []string, marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "ran")
	script := filepath.Join(dir, "mcp-server")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test command
		t.Fatal(err)
	}
	return append(base, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", `BYWARD_UPSTREAM_COMMAND=["`+script+`","--flag"]`), marker
}

func TestCheckOfflineAndDoctorCheckAStdioUpstreamWithoutStartingIt(t *testing.T) {
	env, marker := stdioEnv(t, authEnv(t))
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckOffline(cfg); err != nil {
		t.Fatalf("check --offline: %v", err)
	}
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}}))
	rep, err := Doctor(context.Background(), cfg, DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}}})
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Checks[0]; c.Name != "upstream" || c.Status != doctor.Pass || !strings.Contains(c.Message, "stdio upstream mcp-server: the command was found; doctor does not start it") {
		t.Fatalf("first check %+v", c)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("check --offline or doctor started the stdio upstream")
	}
}

func TestCheckOfflineFindsStdioUpstreamMistakes(t *testing.T) {
	cases := []struct {
		name  string
		env   func(t *testing.T) []string
		inErr string
	}{
		{"command that does not exist", func(t *testing.T) []string {
			return append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", `BYWARD_UPSTREAM_COMMAND=["/nonexistent/mcp-server"]`)
		}, "stdio upstream (BYWARD_UPSTREAM_COMMAND, BYWARD_UPSTREAM_ENV_FILE)"},
		{"env file other users can read, without authentication", func(t *testing.T) []string {
			env, _ := stdioEnv(t, []string{"BYWARD_INSECURE_NO_AUTH=true"})
			envFile := filepath.Join(t.TempDir(), "upstream.env")
			if err := os.WriteFile(envFile, []byte("TOKEN=x\n"), 0o644); err != nil { //nolint:gosec // G306: the loose mode is what the test is about
				t.Fatal(err)
			}
			for i, kv := range env {
				if strings.HasPrefix(kv, "BYWARD_PUBLIC_URL=") {
					env[i] = "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp"
				}
			}
			return append(env, "BYWARD_UPSTREAM_ENV_FILE="+envFile)
		}, "BYWARD_UPSTREAM_ENV_FILE: secret file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := config.Load(nil, tc.env(t), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CheckOffline(cfg); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("check --offline: err = %v, want %q", err, tc.inErr)
			}
			if _, err := Doctor(context.Background(), cfg, DoctorOptions{IdP: &http.Client{Transport: refuse{}}, Proxy: &http.Client{Transport: refuse{}}}); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("doctor: err = %v, want %q", err, tc.inErr)
			}
		})
	}
}

// GODEBUG's x509sslcertoverrideplatform is read as Go reads it: the last entry wins, and only "0"
// keeps the platform verifier.
func TestGODEBUGIsReadAsGoReadsIt(t *testing.T) {
	for _, tc := range []struct{ godebug, want string }{
		{"", ""},
		{"x509sslcertoverrideplatform=0", "0"},
		{"http2client=0,x509sslcertoverrideplatform=0", "0"},
		{"x509sslcertoverrideplatform=0,x509sslcertoverrideplatform=1", "1"},
		{"x509sslcertoverrideplatform=00", "00"},
		{"xx509sslcertoverrideplatform=0", ""},
		{"x509sslcertoverrideplatform=0,x509sslcertoverrideplatform", "0"},
		{" x509sslcertoverrideplatform=0", ""},
		{"x509sslcertoverrideplatform=0#pattern", "0"},
		{"x509sslcertoverrideplatform= 0", " 0"},
	} {
		if got := godebugValue(tc.godebug, "x509sslcertoverrideplatform"); got != tc.want {
			t.Errorf("godebugValue(%q) = %q, want %q", tc.godebug, got, tc.want)
		}
	}
}

// With GODEBUG x509sslcertoverrideplatform=0, Go keeps a platform verifier and ignores SSL_CERT_FILE
// and SSL_CERT_DIR; on Linux there is no platform verifier either way.
func TestTrustSettingsFollowGODEBUGOnAPlatformVerifier(t *testing.T) {
	platform := runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "ios"
	t.Setenv("SSL_CERT_FILE", "/nonexistent")
	for _, tc := range []struct {
		godebug           string
		verifier, ignored bool
	}{
		{"", platform, false},
		{"x509sslcertoverrideplatform=0", false, platform},
		{"x509sslcertoverrideplatform=0,x509sslcertoverrideplatform=1", platform, false},
	} {
		t.Setenv("GODEBUG", tc.godebug)
		if s := trustSettings(); s.PlatformVerifier != tc.verifier || s.SettingsIgnored != tc.ignored {
			t.Errorf("GODEBUG=%q on %s: %+v; want PlatformVerifier %v, SettingsIgnored %v", tc.godebug, runtime.GOOS, s, tc.verifier, tc.ignored)
		}
	}
}
