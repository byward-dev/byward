package main

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/server"
	"github.com/byward-dev/byward/internal/testutil/fakeaz"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const tenant = "11111111-2222-3333-4444-555555555555"

type refusing struct{}

func (refusing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrServerClosed
}

// TestMain points doctor at refusing transports, so a test that forgets useFakes fails instead of
// reaching Entra or anything else on the network.
func TestMain(m *testing.M) {
	doctorOptions = server.DoctorOptions{IdP: &http.Client{Transport: refusing{}}, Proxy: &http.Client{Transport: refusing{}}}
	os.Exit(m.Run())
}

// Usage mistakes are configuration errors (exit 2) that name the right call.
func TestOperateCommandMisuseExits2WithTheRightCallOnStderr(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		env      []string
		inStderr string
	}{
		{"check without --offline", []string{"check"}, nil, "usage: byward check --offline [-- stdio-upstream-command [args...]] (for the network checks, run byward doctor)"},
		{"check with another flag", []string{"check", "--online"}, nil, "usage: byward check --offline"},
		{"check with a stdio command but without --offline", []string{"check", "--", "/bin/sh"}, nil, "usage: byward check --offline"},
		{"doctor with another flag", []string{"doctor", "--yaml"}, nil, "usage: byward doctor [--json]"},
		{"init without an IdP", []string{"init"}, nil, "init prints the setup of an entra IdP"},
		{"init for another IdP", []string{"init", "okta", "--tenant", tenant, "--public-url", "https://m.example/mcp"}, nil, `init sets up only an entra IdP, not "okta"`},
		{"init entra without a tenant", []string{"init", "entra"}, nil, "usage: byward init entra --tenant"},
		{"init entra with an extra argument", []string{"init", "entra", "--tenant", tenant, "now"}, nil, "usage: byward init entra"},
		{"init entra with a domain as tenant", []string{"init", "entra", "--tenant", "contoso.com", "--public-url", "https://m.example/mcp"}, nil, "tenant must be the tenant ID"},
		{"init entra without a public URL", []string{"init", "entra", "--tenant", tenant}, nil, "BYWARD_PUBLIC_URL is required (give --public-url)"},
		{"init entra with an http public URL", []string{"init", "entra", "--tenant", tenant, "--public-url", "http://m.example/mcp"}, nil, "must use https"},
		{"init entra with a 3-year secret", []string{"init", "entra", "--tenant", tenant, "--public-url", "https://m.example/mcp", "--secret-years", "3"}, nil, "1 to 2 years"},
		{"check with a bad setting", []string{"check", "--offline"}, []string{"BYWARD_PUBLC_URL=x"}, "configuration error: unknown setting BYWARD_PUBLC_URL"},
		{"doctor with a bad setting", []string{"doctor"}, []string{"BYWARD_PUBLC_URL=x"}, "configuration error: unknown setting BYWARD_PUBLC_URL"},
		{"flags before the command", []string{"--dev", "check", "--offline"}, nil, "to run check, put it first: byward check"},
		{"init entra with a non-numeric secret lifetime", []string{"init", "entra", "--tenant", tenant, "--secret-years", "abc"}, nil, `invalid value "abc" for flag -secret-years`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith(tc.args, tc.env...)
			if code != exitConfig || stdout != "" || !strings.Contains(stderr, tc.inStderr) {
				t.Fatalf("code %d stdout %q stderr %q, want exit 2 and %q", code, stdout, stderr, tc.inStderr)
			}
		})
	}
}

func TestCheckOfflinePassesAWorkingSetupWithItsStartupWarnings(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	code, stdout, stderr := runWith([]string{"check", "--offline"}, env...)
	if code != exitOK || !strings.Contains(stdout, "configuration OK") || !strings.Contains(stdout, "warn  access gate is empty") || stderr != "" {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestCheckOfflineAndDoctorExit2OnAConfigurationErrorAndCheckNothing(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_KEYS_DIR=/nonexistent/keys")
	for _, args := range [][]string{{"check", "--offline"}, {"doctor"}, {"doctor", "--json"}} {
		code, stdout, stderr := runWith(args, env...)
		if code != exitConfig || stdout != "" || !strings.Contains(stderr, "configuration error: BYWARD_KEYS_DIR: /nonexistent/keys") {
			t.Fatalf("%v: code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

// useFakes points doctor at a fake Entra that knows authEnv's app, and at proxy for the self-probe.
func useFakes(t *testing.T, proxy http.RoundTripper) {
	t.Helper()
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID("00000000-0000-0000-0000-000000000001"),
		fakeidp.WithClient(fakeidp.Client{ID: "00000000-0000-0000-0000-000000000002", Secrets: []string{"s3cret-entra"}}))
	old := doctorOptions
	doctorOptions = server.DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: proxy}}
	t.Cleanup(func() { doctorOptions = old })
}

func TestDoctorExitsWithTheFailedClassAndPrintsJSON(t *testing.T) {
	useFakes(t, refusing{})
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	code, stdout, _ := runWith([]string{"doctor", "--json"}, env...)
	if code != 4 {
		t.Fatalf("exit code %d, want 4 (proxy unreachable, IdP fine); %s", code, stdout)
	}
	var rep struct {
		Checks []struct{ Class, Name, Status, Message, Fix string } `json:"checks"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, stdout)
	}
	byName := map[string]string{}
	for _, c := range rep.Checks {
		byName[c.Name] = c.Class + " " + c.Status
	}
	if byName["entra app and credential"] != "idp pass" || byName["unauthenticated MCP request"] != "proxy fail" {
		t.Fatalf("checks %v", byName)
	}
	code, stdout, _ = runWith([]string{"doctor"}, env...)
	if code != 4 || !strings.Contains(stdout, "fail  proxy  unauthenticated MCP request: cannot reach") || !strings.Contains(stdout, "fix: start the proxy") {
		t.Fatalf("text: code %d\n%s", code, stdout)
	}
}

// initEnv runs the script init entra printed against a stand-in az and returns byward.env's lines.
func initEnv(t *testing.T, args []string, env ...string) []string {
	t.Helper()
	code, stdout, stderr := runWith(args, env...)
	if code != exitOK || stderr != "" {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	r := fakeaz.Run(t, stdout, tenant)
	if r.Err != nil {
		t.Fatalf("the printed script failed: %v\n%s", r.Err, r.Stderr)
	}
	file, _ := r.File(t, "byward.env")
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(file), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines
}

// The env file the printed script writes configures the proxy: it loads, with the app it created.
func TestInitEntraScriptWritesAnEnvFileTheProxyLoads(t *testing.T) {
	lines := initEnv(t, []string{"init", "entra", "--tenant", strings.ToUpper(tenant), "--public-url", "https://flag.example/team/mcp",
		"--upstream-url", "http://127.0.0.1:3001/mcp", "--secret-years", "2"}, "BYWARD_PUBLIC_URL=https://env.example/mcp")
	cfg, _, err := config.Load(nil, append(lines, "BYWARD_DATA_DIR=/var/lib/byward"), os.ReadFile)
	if err != nil {
		t.Fatalf("byward.env does not load: %v\n%s", err, strings.Join(lines, "\n"))
	}
	if cfg.PublicURL.String() != "https://flag.example/team/mcp" || cfg.UpstreamURL.String() != "http://127.0.0.1:3001/mcp" ||
		cfg.EntraTenant != tenant || cfg.EntraClientID != fakeaz.AppID || cfg.EntraClientSecret != fakeaz.Secret ||
		cfg.EntraClientSecretExpiresAt.Before(time.Now().AddDate(2, 0, -2)) { // a date: up to a day early, and a run may cross midnight
		t.Fatalf("settings %+v", cfg)
	}
}

func TestInitEntraLeavesAnUnknownUpstreamURLEmpty(t *testing.T) {
	lines := initEnv(t, []string{"init", "entra", "--tenant", tenant}, "BYWARD_PUBLIC_URL=https://env.example/mcp")
	if !slices.Contains(lines, "BYWARD_UPSTREAM_URL=") || !slices.Contains(lines, "BYWARD_PUBLIC_URL=https://env.example/mcp") {
		t.Fatalf("env file %q", lines)
	}
}

func TestHelpListsCheckDoctorAndInit(t *testing.T) {
	code, stdout, _ := runWith([]string{"--help"})
	for _, want := range []string{"byward check --offline", "byward doctor [--json]", "byward init entra --tenant <tenant-id>", "4 (proxy), 8 (IdP), 12 (both)"} {
		if code != exitOK || !strings.Contains(stdout, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

// A stdio upstream given after "--", as the proxy takes it, reaches check and doctor's configuration.
func TestCheckOfflineAndDoctorTakeAStdioUpstreamAfterDashes(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/mcp-server"
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+dir+"/ran\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test command
		t.Fatal(err)
	}
	useFakes(t, refusing{})
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp")
	code, stdout, stderr := runWith([]string{"check", "--offline", "--", script, "--flag"}, env...)
	if code != exitOK || !strings.Contains(stdout, "configuration OK") {
		t.Fatalf("check: code %d stdout %q stderr %q", code, stdout, stderr)
	}
	code, stdout, _ = runWith([]string{"doctor", "--json", "--", script}, env...)
	if code != 4 || !strings.Contains(stdout, `"message": "stdio upstream mcp-server: the command was found`) {
		t.Fatalf("doctor: code %d\n%s", code, stdout)
	}
	if _, err := os.Stat(dir + "/ran"); err == nil {
		t.Fatal("check or doctor started the stdio upstream")
	}
}

func TestJWKSPrintsThePublicKeysOnly(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	code, stdout, stderr := runWith([]string{"jwks"}, env...)
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if code != exitOK || json.Unmarshal([]byte(stdout), &set) != nil || len(set.Keys) != 1 || set.Keys[0]["kid"] != "k1" || set.Keys[0]["alg"] != "ES256" {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
	if _, private := set.Keys[0]["d"]; private {
		t.Fatal("the JWKS carries the private key")
	}
}

// `byward jwks` with no key, or with an argument it does not take, prints nothing and exits 2.
func TestJWKSRefusesNoKeysOrAnExtraArgument(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	for _, tc := range []struct {
		name     string
		args     []string
		env      []string
		inStderr []string
	}{
		{"no keys", []string{"jwks"}, append(env, "BYWARD_ASSERTION_KEYS_DIR="+t.TempDir()), []string{"BYWARD_ASSERTION_KEYS_DIR", "has no key files"}},
		{"extra argument", []string{"jwks", "--out", "x"}, env, []string{"usage: byward jwks"}},
	} {
		code, stdout, stderr := runWith(tc.args, tc.env...)
		if code != exitConfig || stdout != "" {
			t.Errorf("%s: code %d stdout %q", tc.name, code, stdout)
		}
		for _, want := range tc.inStderr {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s: stderr %q lacks %q", tc.name, stderr, want)
			}
		}
	}
}
