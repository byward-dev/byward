package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/tracing"
	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/server"
	"github.com/byward-dev/byward/internal/testutil/fakeaz"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const tenant = "11111111-2222-3333-4444-555555555555"

type refusing struct{}

func (refusing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrServerClosed
}

// TestMain points doctor at refusing transports and a resolver that resolves nothing, so a test
// that forgets useFakes fails instead of reaching Entra or anything else on the network, and at no
// HTTP proxy, so the developer's HTTP_PROXY never changes the upstream line.
func TestMain(m *testing.M) {
	doctorOptions = server.DoctorOptions{IdP: &http.Client{Transport: refusing{}}, Proxy: &http.Client{Transport: refusing{}},
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("the tests resolve no names")
		},
		UpstreamProxy: func(*http.Request) (*url.URL, error) { return nil, nil }}
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
		{"init entra with an upstream URL the proxy refuses", []string{"init", "entra", "--tenant", tenant, "--public-url", "https://m.example/mcp", "--upstream-url", "ftp://up.example/mcp"}, nil, `BYWARD_UPSTREAM_URL: want an absolute http(s) URL`},
		{"init entra with an upstream URL from the environment the proxy refuses", []string{"init", "entra", "--tenant", tenant, "--public-url", "https://m.example/mcp"}, []string{"BYWARD_UPSTREAM_URL=up.example/mcp"}, `"up.example/mcp" (give --upstream-url)`},
		{"check with a bad setting", []string{"check", "--offline"}, []string{"BYWARD_PUBLC_URL=x"}, "byward: configuration error: unknown setting BYWARD_PUBLC_URL"},
		{"doctor with a bad setting", []string{"doctor"}, []string{"BYWARD_PUBLC_URL=x"}, "byward: configuration error: unknown setting BYWARD_PUBLC_URL"},
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

// L167, L176: init refuses a URL with a password in it, as the proxy does, naming the setting, the
// flag to give and, when the URL parses, its host; it prints the password nowhere: not in its error,
// and not in a script.
func TestInitRefusesAURLWithAPasswordWithoutShowingIt(t *testing.T) {
	const password = "s3cretPW"
	for name, tc := range map[string]struct {
		args     []string
		env      []string
		inStderr []string
	}{
		"public URL": {args: []string{"--public-url", "https://user:" + password + "@m.example/mcp"},
			inStderr: []string{"BYWARD_PUBLIC_URL: ", `"https://m.example/mcp"`, "(give --public-url)"}},
		"upstream URL": {args: []string{"--public-url", "https://m.example/mcp", "--upstream-url", "https://user:" + password + "@up.example/mcp"},
			inStderr: []string{"BYWARD_UPSTREAM_URL: ", `"https://up.example/mcp"`, "(give --upstream-url)"}},
		"upstream URL from the environment": {args: []string{"--public-url", "https://m.example/mcp"}, env: []string{"BYWARD_UPSTREAM_URL=https://user:" + password + "@up.example/mcp"},
			inStderr: []string{"BYWARD_UPSTREAM_URL: ", `"https://up.example/mcp"`, "(give --upstream-url)"}},
		"upstream URL that Go cannot parse": {args: []string{"--public-url", "https://m.example/mcp", "--upstream-url", "ftp://user:" + password + "@up stream/x"},
			inStderr: []string{"BYWARD_UPSTREAM_URL: ", logging.Hidden, "(give --upstream-url)"}},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runWith(append([]string{"init", "entra", "--tenant", tenant}, tc.args...), tc.env...)
			if code != exitConfig || stdout != "" || strings.Contains(stderr, password) {
				t.Fatalf("code %d stdout %q stderr %q, want exit 2, no script, and no password", code, stdout, stderr)
			}
			for _, want := range tc.inStderr {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr %q, want %q in it", stderr, want)
				}
			}
		})
	}
}

// L167: a URL setting or list entry with a credential in it stops startup, check --offline and doctor
// with exit 2, naming the setting and showing the URL's host when the URL parses (logging.Hidden when
// it does not), and the credential is nowhere on their output: load refuses the value before the
// startup log lists the settings.
func TestASettingWithACredentialStopsEveryCommandWithoutShowingIt(t *testing.T) {
	const secret = "s3cretPW"
	entraEnv := func(t *testing.T) []string { return authEnv(t) }
	// The OIDC issuer needs an oidc IdP.
	oidcEnv := func(t *testing.T) []string {
		return append(oidcAuthEnv(t), "BYWARD_IDP=oidc", "BYWARD_OIDC_CLIENT_ID=app", "BYWARD_GATE_ALLOW_EMPTY=true", "BYWARD_DEV=true")
	}
	for _, tc := range []struct {
		setting, shown string
		base           func(*testing.T) []string
	}{
		{"BYWARD_UPSTREAM_URL=https://user:" + secret + "@up.example/mcp", `"https://up.example/mcp"`, entraEnv},
		{"BYWARD_ALLOWED_ORIGINS=https://app.example?token=" + secret, `"https://app.example"`, entraEnv},
		{"BYWARD_CLIENT_DENYLIST=https://user:" + secret + "@app.example/c.json", `"https://app.example/c.json"`, entraEnv},
		{"BYWARD_RESOURCE_DOCUMENTATION=https://user:" + secret + "@docs.example/", `"https://docs.example/"`, entraEnv},
		{"BYWARD_OIDC_ISSUER=https://user:" + secret + "@idp.example", `"https://idp.example"`, oidcEnv},
		{"BYWARD_OIDC_ISSUER=https://user:" + secret + "@id p.example", logging.Hidden, oidcEnv},
	} {
		name, _, _ := strings.Cut(tc.setting, "=")
		for _, command := range [][]string{nil, {"check", "--offline"}, {"doctor"}} {
			// Should a value ever load, startup must still serve nothing: neither listener can open,
			// and it runs with its context already done, so it returns at once.
			env := append(tc.base(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
				"BYWARD_LISTEN=192.0.2.1:8080", "BYWARD_INTERNAL_LISTEN=", tc.setting)
			code, stdout, stderr := runDone(command, env...)
			if code != exitConfig || strings.Contains(stdout+stderr, secret) || !strings.Contains(stderr, name+": ") || !strings.Contains(stderr, tc.shown) {
				t.Errorf("%q with %s: code %d stdout %q stderr %q, want exit 2, %s and %s named, and no secret", command, tc.setting, code, stdout, stderr, name, tc.shown)
			}
		}
	}
}

func TestCheckOfflinePassesAWorkingSetupWithItsStartupWarnings(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	code, stdout, stderr := runWith([]string{"check", "--offline"}, env...)
	if code != exitOK || !strings.Contains(stdout, "configuration OK") || !strings.Contains(stdout, "warn  access gate is empty") || stderr != "" {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
}

// L157: check --offline builds the trace exporter as startup does, so an OTEL_* value startup
// refuses fails check with exit 2 and startup's message (ADR-0021 §9: failing closed; the refusal
// classes are internal/tracing's TestNewExporterRefusesWhatStartupRefuses). A value the exporter
// only ignores passes and is logged through the redacting logger: by its message, on check's
// standard error, its value (which can be a credential) nowhere.
func TestCheckOfflineBuildsTheTraceExporterAsStartupDoes(t *testing.T) {
	const secret = "s3cret-token"
	ignoredHeader := []string{"OTEL_TRACES_EXPORTER=otlp", "OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318",
		"OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer%zz" + secret}
	for _, tc := range []struct {
		name               string
		otel, byward       []string // the OTEL_* settings; more byward settings
		looseSecret        bool     // the client secret file is group-readable, which check also refuses
		code               int
		inStdout, inStderr string
	}{
		{"an exporter startup refuses", []string{"OTEL_TRACES_EXPORTER=jaeger"}, nil, false, exitConfig, "", "byward: configuration error: OTEL_* tracing settings: "},
		{"a protocol startup refuses", []string{"OTEL_TRACES_EXPORTER=otlp", "OTEL_EXPORTER_OTLP_PROTOCOL=udp"}, nil, false, exitConfig, "",
			"byward: configuration error: OTEL_* tracing settings: "},
		// Startup builds the exporter before it checks the rest, so check reports that refusal first.
		{"an exporter startup refuses, beside another mistake", []string{"OTEL_TRACES_EXPORTER=jaeger"}, nil, true, exitConfig, "", "OTEL_* tracing settings: "},
		// The message is otlptrace's wording; the line is in the proxy's log format.
		{"a header the exporter ignores", ignoredHeader, nil, false, exitOK, "configuration OK", `"msg":"tracing error","error":"escape header value"`},
		{"a header the exporter ignores, in the text log format", ignoredHeader, []string{"BYWARD_LOG_FORMAT=text"}, false, exitOK, "configuration OK",
			`msg="tracing error" error="escape header value"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blankOTELEnv(t)
			for _, kv := range tc.otel {
				k, v, _ := strings.Cut(kv, "=")
				t.Setenv(k, v)
			}
			t.Cleanup(func() { otel.SetLogger(logr.Discard()) }) // NewExporter's logger writes to this test's stderr
			env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			env = append(env, tc.byward...)
			if tc.looseSecret {
				for _, kv := range env {
					if f, ok := strings.CutPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE="); ok {
						if err := os.Chmod(f, 0o644); err != nil { //nolint:gosec // G302: a secret file check refuses
							t.Fatal(err)
						}
					}
				}
			}
			code, stdout, stderr := runWith([]string{"check", "--offline"}, append(env, tc.otel...)...)
			if code != tc.code || !strings.Contains(stdout, tc.inStdout) || !strings.Contains(stderr, tc.inStderr) {
				t.Fatalf("code %d (want %d)\nstdout %q (want %q)\nstderr %q (want %q)", code, tc.code, stdout, tc.inStdout, stderr, tc.inStderr)
			}
			if strings.Contains(stdout+stderr, secret) {
				t.Fatalf("a setting's value was printed:\nstdout %q\nstderr %q", stdout, stderr)
			}
			// A refusal gives the exporter's own reason after byward's prefix: the error
			// tracing.NewExporter returns for these settings, so no library wording is pinned here.
			if tc.code == exitConfig {
				_, want := tracing.NewExporter(context.Background(), os.Getenv, slog.New(slog.DiscardHandler))
				if want == nil {
					t.Fatal("tracing.NewExporter accepts these settings; the row expects exit 2")
				}
				if !strings.Contains(stderr, "OTEL_* tracing settings: "+want.Error()) {
					t.Fatalf("stderr %q; want %q after the prefix", stderr, want)
				}
			}
		})
	}
}

// check prints the warning the proxy logs at every start while the plain identity headers are on,
// as it prints every other startup warning.
func TestCheckOfflineWarnsThatPlainIdentityHeadersAreOn(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	for name, tc := range map[string]struct {
		env  []string
		want bool
	}{"off": {env, false}, "on": {append(slices.Clone(env), "BYWARD_IDENTITY_HEADERS=true"), true}} {
		const warning = "warn  plain identity headers are on (BYWARD_IDENTITY_HEADERS: the upstream gets the user in X-Byward-* headers as well as the assertion; that is safe only when it is reachable through this proxy alone (docs/how-to/plain-identity-headers.md))\n"
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runWith([]string{"check", "--offline"}, tc.env...)
			if code != exitOK || stderr != "" || strings.Contains(stdout, warning) != tc.want {
				t.Fatalf("code %d stdout %q stderr %q, want exit 0, no stderr, the warning with its setting and guide shown: %v", code, stdout, stderr, tc.want)
			}
		})
	}
}

// check names an oidc IdP's client credential (#306); Entra's has no such line.
func TestCheckOfflineNamesAnOIDCClientCredential(t *testing.T) {
	urls := []string{"BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}
	base := append(authEnv(t), urls...)
	oidcEnv := append(append(oidcAuthEnv(t), urls...),
		"BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_CLIENT_ID=byward", "BYWARD_GATE_ALLOW_EMPTY=true")
	for name, tc := range map[string]struct {
		env  []string
		line string // "" means no credential line
	}{
		"entra":    {base, ""},
		"keycloak": {oidcEnv, "info  client credential: a client secret\n"},
		"no auth":  {[]string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_INSECURE_NO_AUTH=true"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runWith([]string{"check", "--offline"}, tc.env...)
			hasLine := strings.Contains(stdout, "client credential")
			if code != exitOK || stderr != "" || (tc.line == "" && hasLine) || (tc.line != "" && !strings.Contains(stdout, tc.line)) {
				t.Fatalf("code %d stdout %q stderr %q; want the line %q", code, stdout, stderr, tc.line)
			}
		})
	}
}

func TestCheckOfflineAndDoctorExit2OnAConfigurationErrorAndCheckNothing(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_KEYS_DIR=/nonexistent/keys")
	for _, args := range [][]string{{"check", "--offline"}, {"doctor"}, {"doctor", "--json"}} {
		code, stdout, stderr := runWith(args, env...)
		if code != exitConfig || stdout != "" || !strings.HasPrefix(stderr, "byward: configuration error: BYWARD_KEYS_DIR: /nonexistent/keys") ||
			strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
			t.Fatalf("%v: code %d stdout %q stderr %q; want exit 2, no stdout, and the BYWARD_KEYS_DIR configuration error alone", args, code, stdout, stderr)
		}
	}
}

// useFakes points doctor at a fake Entra that knows authEnv's app, and at proxy for the self-probe.
func useFakes(t *testing.T, proxy http.RoundTripper) {
	t.Helper()
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID("00000000-0000-0000-0000-000000000001"),
		fakeidp.WithClient(fakeidp.Client{ID: "00000000-0000-0000-0000-000000000002", Secrets: []string{"s3cret-entra"}}))
	old := doctorOptions // keeps TestMain's resolver and upstream proxy, so no test reaches the network
	doctorOptions.IdP, doctorOptions.Proxy = fake.HTTPClient(), &http.Client{Transport: proxy}
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

// With --credential certificate the env file names the certificate the script made instead of a
// secret, and the proxy loads it as it is (ADR-0012 §5).
func TestInitEntraWithACertificateWritesAnEnvFileTheProxyLoads(t *testing.T) {
	if _, err := os.Stat("/usr/bin/openssl"); err != nil {
		t.Skip("the script runs the system openssl, and there is none at /usr/bin/openssl")
	}
	lines := initEnv(t, []string{"init", "entra", "--tenant", tenant, "--public-url", "https://flag.example/mcp", "--upstream-url", "http://127.0.0.1:3001/mcp",
		"--credential", "certificate"})
	cfg, _, err := config.Load(nil, append(lines, "BYWARD_DATA_DIR=/var/lib/byward"), os.ReadFile)
	if err != nil {
		t.Fatalf("byward.env does not load: %v\n%s", err, strings.Join(lines, "\n"))
	}
	if cfg.EntraClientSecret != "" || cfg.EntraClientCertificate == "" || !cfg.EntraClientSecretExpiresAt.IsZero() {
		t.Fatalf("env file %q", lines)
	}
	if _, err := entra.LoadCertificate([]byte(cfg.EntraClientCertificate)); err != nil {
		t.Fatalf("the certificate the script made does not load: %v", err)
	}
}

func TestInitEntraRefusesAnUnknownCredential(t *testing.T) {
	if code, _, stderr := runWith([]string{"init", "entra", "--tenant", tenant, "--public-url", "https://flag.example/mcp", "--credential", "password"}); code != exitConfig ||
		!strings.Contains(stderr, `the credential must be secret or certificate, not "password"`) {
		t.Fatalf("an unknown credential: %d %q", code, stderr)
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
	for _, want := range []string{"byward check --offline", "byward doctor [--json]", "byward init entra --tenant <tenant-id>", "exit 0, 2 (configuration), 4 (proxy), 8 (IdP) or 12 (both)"} {
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
	env := append(stdioAuthEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_DATA_DIR="+dir) // the test's own, so no default path reaches the host's
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

// `byward jwks` with no key, with an argument it does not take, without authentication or with a
// stdio upstream, prints nothing and exits 2.
func TestJWKSRefusesNoKeysAnExtraArgumentNoAuthenticationOrAStdioUpstream(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	// A stdio upstream with a key in its default key directory, which a jwks that read it would print
	// (#429), and one with no key directory, which a jwks that read it would name.
	withKey, noKeyDir := t.TempDir(), t.TempDir()
	assertionkey.Write(t, withKey+"/assertion-keys", "k1", false)
	stdio := append(stdioAuthEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", `BYWARD_UPSTREAM_COMMAND=["/bin/cat"]`)
	noAuth := []string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp"}
	const noAuthRefusal = "byward: configuration error: with BYWARD_INSECURE_NO_AUTH no identity assertion is sent, so there are no assertion keys to export\n"
	const stdioRefusal = "byward: configuration error: with a stdio upstream (BYWARD_UPSTREAM_COMMAND) no identity assertion is sent, so there are no assertion keys to export; only an HTTP upstream gets one\n"
	for _, tc := range []struct {
		name     string
		args     []string
		env      []string
		inStderr []string
	}{
		{"no keys", []string{"jwks"}, append(slices.Clone(env), "BYWARD_ASSERTION_KEYS_DIR="+assertionkey.EmptyDir(t)), []string{"BYWARD_ASSERTION_KEYS_DIR", "has no key files", "(see docs/how-to/identity-assertion.md)"}},
		{"extra argument", []string{"jwks", "--out", "x"}, env, []string{"usage: byward jwks"}},
		// Without authentication no identity assertion is sent: refused as such, not as a key
		// directory that cannot be read (L175).
		{"without authentication", []string{"jwks"}, append(slices.Clone(noAuth), "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp"), []string{noAuthRefusal}},
		// A stdio upstream gets no identity assertion (ADR-0016 §2): refused as such, before the
		// key directory is read, whether it holds a key or does not exist.
		{"stdio upstream, a key in the default directory", []string{"jwks"}, append(slices.Clone(stdio), "BYWARD_DATA_DIR="+withKey), []string{stdioRefusal}},
		{"stdio upstream, no key directory", []string{"jwks"}, append(slices.Clone(stdio), "BYWARD_DATA_DIR="+noKeyDir), []string{stdioRefusal}},
		// Both: refused as no authentication, as revoke-user, revoke-all and store new-epoch are.
		{"stdio upstream without authentication", []string{"jwks"}, append(slices.Clone(noAuth), `BYWARD_UPSTREAM_COMMAND=["/bin/cat"]`), []string{noAuthRefusal}},
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

// check --offline prints each relaxation in effect, as the startup log has them, before the
// startup warnings and "configuration OK", labelled neutrally: --insecure-no-auth's are not
// development mode (security invariant 12, #355).
func TestCheckOfflinePrintsEachRelaxationFirst(t *testing.T) {
	for _, tc := range []struct {
		name, warning string
		env           []string
		relaxations   []string
	}{
		{"--dev", "warn  access gate is empty", append(authEnv(t), "BYWARD_DEV=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"),
			[]string{"secret file permissions are not checked", "http public URL on loopback"}},
		{"--insecure-no-auth", "warn  authentication is off", []string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"},
			[]string{"http public URL on loopback", "AUTHENTICATION IS OFF: anyone who can reach http://127.0.0.1:8080/mcp can use the upstream, and the upstream receives no identity"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith([]string{"check", "--offline"}, tc.env...)
			if code != exitOK || stderr != "" || !strings.Contains(stdout, tc.warning) || !strings.Contains(stdout, "configuration OK") {
				t.Fatalf("code %d stdout %q stderr %q; want the warnings and configuration OK", code, stdout, stderr)
			}
			var want string
			for _, r := range tc.relaxations {
				want += "warn  relaxation: " + r + "\n"
			}
			if !strings.HasPrefix(stdout, want) || strings.Contains(stdout, "development mode") {
				t.Fatalf("stdout %q; want it to start with\n%s", stdout, want)
			}
		})
	}
}

// With no upstream, the refusal names a stdio upstream command after -- only for the proxy and the
// commands that take one; jwks refuses any argument, so it names BYWARD_UPSTREAM_COMMAND only (#499).
func TestTheNoUpstreamRefusalSuggestsACommandAfterDashesOnlyWhereOneIsTaken(t *testing.T) {
	const withDashes = "byward: configuration error: BYWARD_UPSTREAM_URL is required (or BYWARD_UPSTREAM_COMMAND, or a command after --)\n"
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"jwks", []string{"jwks"}, "byward: configuration error: BYWARD_UPSTREAM_URL is required (or BYWARD_UPSTREAM_COMMAND)\n"},
		{"the proxy", nil, withDashes},
		{"check --offline", []string{"check", "--offline"}, withDashes},
		{"doctor", []string{"doctor"}, withDashes},
		{"revoke-user", []string{"revoke-user", "u1"}, withDashes},
		{"revoke-all", []string{"revoke-all", "--yes"}, withDashes},
		{"store new-epoch", []string{"store", "new-epoch", "--yes"}, withDashes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith(tc.args, env...)
			if code != exitConfig || stdout != "" || stderr != tc.want {
				t.Errorf("code %d, stdout %q, stderr %q; want %d, nothing, %q", code, stdout, stderr, exitConfig, tc.want)
			}
		})
	}
}
