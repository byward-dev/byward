package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

var base = []string{
	"MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp",
	"MCP_AUTHPROXY_UPSTREAM_URL=http://upstream:9000/mcp",
	"MCP_AUTHPROXY_ENTRA_TENANT=00000000-0000-0000-0000-000000000001",
	"MCP_AUTHPROXY_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
	"MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra",
	"MCP_AUTHPROXY_KEYS_DIR=/var/lib/mcp-authproxy/keys",
	"MCP_AUTHPROXY_STATIC_CLIENTS_FILE=/etc/mcp-authproxy/clients.json",
}

// baseFiles serves the secret file named in base.
func baseFiles(p string) ([]byte, error) {
	if p == "/run/secrets/entra" {
		return []byte("s3cret-entra\n"), nil
	}
	return nil, os.ErrNotExist
}

func isConfigError(err error) bool {
	var ce *configError
	return errors.As(err, &ce)
}

func load(t *testing.T, args []string, env ...string) (*Config, error) {
	t.Helper()
	c, _, err := Load(args, append(append([]string{}, base...), env...), baseFiles)
	return c, err
}

func TestDefaults(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.LogFormat != "json" || c.Scope != "mcp" || c.Dev {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.Issuer() != "https://mcp.example.com" {
		t.Fatalf("issuer = %q", c.Issuer())
	}
}

func TestFlagBeatsEnvBeatsDefault(t *testing.T) {
	c, err := load(t, []string{"--listen", "0.0.0.0:9"}, "MCP_AUTHPROXY_LISTEN=127.0.0.1:7", "MCP_AUTHPROXY_LOG_FORMAT=text")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:9" || c.LogFormat != "text" {
		t.Fatalf("listen=%q log=%q", c.Listen, c.LogFormat)
	}
	src := map[string]Source{}
	for _, v := range c.Values.Effective() {
		src[v.Setting.Name] = v.Source
	}
	if src["listen"] != SourceFlag || src["log-format"] != SourceEnv || src["scope"] != SourceDefault || src["public-url"] != SourceEnv {
		t.Fatalf("sources: %v", src)
	}
}

func TestUnknownEnvSuggestsSetting(t *testing.T) {
	_, err := load(t, nil, "MCP_AUTHPROXY_PUBLC_URL=x")
	if !isConfigError(err) || !strings.Contains(err.Error(), "did you mean MCP_AUTHPROXY_PUBLIC_URL?") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownEnvFarFromAnySettingHasNoSuggestion(t *testing.T) {
	_, err := load(t, nil, "MCP_AUTHPROXY_ZZZZZZZZZZZZZZ=x")
	if !isConfigError(err) || strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidSettingsAreRejectedNamingTheSetting(t *testing.T) {
	cases := []struct {
		name, env, want string
	}{
		{"required", "MCP_AUTHPROXY_PUBLIC_URL=", "MCP_AUTHPROXY_PUBLIC_URL is required"},
		{"trailing slash", "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp/", "MCP_AUTHPROXY_PUBLIC_URL"},
		{"no path", "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com", "MCP_AUTHPROXY_PUBLIC_URL"},
		{"query", "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp?x=1", "must not have a query or fragment"},
		{"fragment", "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp#f", "must not have a query or fragment"},
		{"http public", "MCP_AUTHPROXY_PUBLIC_URL=http://mcp.example.com/mcp", "must use https"},
		{"http loopback without dev", "MCP_AUTHPROXY_PUBLIC_URL=http://127.0.0.1:8080/mcp", "needs --dev"},
		// Browsers and MCP clients send IDN hosts in ASCII (xn--) form, so a Unicode host never matches.
		{"unicode public host", "MCP_AUTHPROXY_PUBLIC_URL=https://bücher.example/mcp", `MCP_AUTHPROXY_PUBLIC_URL: the host "bücher.example" is not ASCII`},
		{"escaped unicode public host", "MCP_AUTHPROXY_PUBLIC_URL=https://b%C3%BCcher.example/mcp", `MCP_AUTHPROXY_PUBLIC_URL: the host "bücher.example" is not ASCII`},
		{"unicode allowed origin", "MCP_AUTHPROXY_ALLOWED_ORIGINS=https://bücher.example", `MCP_AUTHPROXY_ALLOWED_ORIGINS: the host "bücher.example" is not ASCII`},
		{"unicode allowed host", "MCP_AUTHPROXY_ALLOWED_HOSTS=bücher.example:8443", `MCP_AUTHPROXY_ALLOWED_HOSTS: the host "bücher.example:8443" is not ASCII`},
		{"credentials", "MCP_AUTHPROXY_UPSTREAM_URL=http://u:p@upstream/mcp", "MCP_AUTHPROXY_UPSTREAM_URL"},
		{"origin with path", "MCP_AUTHPROXY_ALLOWED_ORIGINS=https://a.example/path", "MCP_AUTHPROXY_ALLOWED_ORIGINS"},
		{"host with path", "MCP_AUTHPROXY_ALLOWED_HOSTS=a.example/x", "MCP_AUTHPROXY_ALLOWED_HOSTS"},
		{"host with space", "MCP_AUTHPROXY_ALLOWED_HOSTS=a b", "MCP_AUTHPROXY_ALLOWED_HOSTS"},
		{"listen without port", "MCP_AUTHPROXY_LISTEN=8080", "MCP_AUTHPROXY_LISTEN"},
		{"log format", "MCP_AUTHPROXY_LOG_FORMAT=xml", "MCP_AUTHPROXY_LOG_FORMAT"},
		{"two scopes", "MCP_AUTHPROXY_SCOPE=a b", "MCP_AUTHPROXY_SCOPE"},
		{"dev not a bool", "MCP_AUTHPROXY_DEV=maybe", "MCP_AUTHPROXY_DEV"},
		{"documentation not a URL", "MCP_AUTHPROXY_RESOURCE_DOCUMENTATION=javascript:x", "MCP_AUTHPROXY_RESOURCE_DOCUMENTATION"},
		{"gate allow-empty not a bool", "MCP_AUTHPROXY_GATE_ALLOW_EMPTY=yes", "MCP_AUTHPROXY_GATE_ALLOW_EMPTY: want true or false"},
		{"gate tenants blank", "MCP_AUTHPROXY_GATE_TENANTS=,", "MCP_AUTHPROXY_GATE_TENANTS is set but lists nothing"},
		{"gate roles blank", "MCP_AUTHPROXY_GATE_ROLES= ,,", "MCP_AUTHPROXY_GATE_ROLES is set but lists nothing"},
		{"gate groups blank", "MCP_AUTHPROXY_GATE_GROUPS= ", "MCP_AUTHPROXY_GATE_GROUPS is set but lists nothing"},
		{"gate email domains blank", "MCP_AUTHPROXY_GATE_EMAIL_DOMAINS=,", "MCP_AUTHPROXY_GATE_EMAIL_DOMAINS is set but lists nothing"},
		{"gate hosted domains blank", "MCP_AUTHPROXY_GATE_HOSTED_DOMAINS=,", "MCP_AUTHPROXY_GATE_HOSTED_DOMAINS is set but lists nothing"},
		{"operator name too long", "MCP_AUTHPROXY_OPERATOR_NAME=" + strings.Repeat("é", 81), "MCP_AUTHPROXY_OPERATOR_NAME: at most 80 characters, got 81"},
		{"operator name with a newline", "MCP_AUTHPROXY_OPERATOR_NAME=a\nb", "MCP_AUTHPROXY_OPERATOR_NAME: must not contain control or formatting characters"},
		{"operator name with a bidi override", "MCP_AUTHPROXY_OPERATOR_NAME=Evil \u202eTI", "MCP_AUTHPROXY_OPERATOR_NAME: must not contain control or formatting characters"},
		{"scope description with a bidi override", "MCP_AUTHPROXY_SCOPE_DESCRIPTION=Read \u202edashboards", "MCP_AUTHPROXY_SCOPE_DESCRIPTION: must not contain control or formatting characters"},
		{"scope description too long", "MCP_AUTHPROXY_SCOPE_DESCRIPTION=" + strings.Repeat("x", 201), "MCP_AUTHPROXY_SCOPE_DESCRIPTION: at most 200 characters"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, nil, c.env)
			if !isConfigError(err) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a config error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestConsentWordingLoadsUpToItsLimitCountedAsCharacters(t *testing.T) {
	c, err := load(t, nil, "MCP_AUTHPROXY_OPERATOR_NAME="+strings.Repeat("é", 80), "MCP_AUTHPROXY_SCOPE_DESCRIPTION="+strings.Repeat("é", 200))
	if err != nil {
		t.Fatal(err)
	}
	if c.OperatorName != strings.Repeat("é", 80) || c.ScopeDescription != strings.Repeat("é", 200) {
		t.Fatalf("operator %q, scope description %q", c.OperatorName, c.ScopeDescription)
	}
}

func TestBaseSettingsAreValid(t *testing.T) {
	if _, err := load(t, nil); err != nil {
		t.Fatalf("the base settings the rejection cases build on must load: %v", err)
	}
}

func TestDevAllowsLoopbackHTTPAndRecordsIt(t *testing.T) {
	c, err := load(t, []string{"--dev"}, "MCP_AUTHPROXY_PUBLIC_URL=http://localhost:8080/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Dev || len(c.Relaxations) != 1 || c.Relaxations[0] != "http public URL on loopback" {
		t.Fatalf("dev=%v relaxations=%v", c.Dev, c.Relaxations)
	}
}

func TestListsAreNormalized(t *testing.T) {
	c, err := load(t, nil, "MCP_AUTHPROXY_ALLOWED_ORIGINS= https://App.Example ,http://localhost:3000", "MCP_AUTHPROXY_ALLOWED_HOSTS=Internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.AllowedOrigins, ",") != "https://app.example,http://localhost:3000" || c.AllowedHosts[0] != "internal:8080" {
		t.Fatalf("origins=%v hosts=%v", c.AllowedOrigins, c.AllowedHosts)
	}
}

func TestHelpFlagAsksForUsageListingEnvNames(t *testing.T) {
	if _, _, err := Load([]string{"-h"}, base, baseFiles); !IsHelp(err) {
		t.Fatalf("want help, got %v", err)
	}
	if !strings.Contains(Usage(), "MCP_AUTHPROXY_PUBLIC_URL") {
		t.Fatal("usage lacks env names")
	}
}

func TestPositionalArgumentIsAConfigError(t *testing.T) {
	if _, _, err := Load([]string{"extra"}, base, baseFiles); !isConfigError(err) || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("want config error naming the argument, got %v", err)
	}
}

func TestVersionNeedsNoOtherSettings(t *testing.T) {
	_, act, err := Load([]string{"--version", "--json"}, nil, nil)
	if err != nil || !act.Version || !act.JSON {
		t.Fatalf("act=%+v err=%v", act, err)
	}
}

// Secrets are exercised with a test registry: slice 1.1 has no secret settings yet.
var secretReg = []Setting{{Name: "client-secret", Secret: true, Help: "secret"}}

func files(m map[string]string) readFileFunc {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
}

func TestSecretFromEnvFile(t *testing.T) {
	v, err := resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/run/secrets/x"}, files(map[string]string{"/run/secrets/x": "s3cret\n"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Effective()[0]
	if got.Raw != "s3cret" || got.Source != SourceFile || got.Display() != "<redacted>" {
		t.Fatalf("got %+v display=%q", got, got.Display())
	}
}

func TestSecretFromFlagFileBeatsEnvFile(t *testing.T) {
	v, err := resolve(secretReg, []string{"--client-secret-file", "/a"}, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/b"}, files(map[string]string{"/a": "A", "/b": "B"}), nil)
	if err != nil || v.get("client-secret") != "A" {
		t.Fatalf("got %q err=%v", v.get("client-secret"), err)
	}
}

func TestSecretFileMissingIsConfigError(t *testing.T) {
	_, err := resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/nope"}, files(nil), nil)
	if !isConfigError(err) || !strings.Contains(err.Error(), "MCP_AUTHPROXY_CLIENT_SECRET_FILE") {
		t.Fatalf("want a config error naming the setting, got %v", err)
	}
}

func TestInlineSecretIsReported(t *testing.T) {
	v, err := resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET=inline"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.inlineSecrets(); len(got) != 1 || got[0] != "MCP_AUTHPROXY_CLIENT_SECRET" {
		t.Fatalf("inline = %v", got)
	}
	if v.Effective()[0].Display() != "<redacted>" {
		t.Fatal("inline secret not redacted")
	}
}

func TestSecretHasNoInlineFlag(t *testing.T) {
	_, err := resolve(secretReg, []string{"--client-secret", "x"}, nil, nil, nil)
	if !isConfigError(err) {
		t.Fatalf("want config error, got %v", err)
	}
}

func TestInlineSecretRejectedOutsideDevMode(t *testing.T) {
	v, err := resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET=inline"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkInlineSecrets(v, false); !isConfigError(err) || !strings.Contains(err.Error(), "MCP_AUTHPROXY_CLIENT_SECRET_FILE") {
		t.Fatalf("without dev: want error pointing at the _FILE variable, got %v", err)
	}
	relaxed, err := checkInlineSecrets(v, true)
	if err != nil || !strings.Contains(relaxed, "MCP_AUTHPROXY_CLIENT_SECRET") {
		t.Fatalf("with dev: relaxation=%q err=%v", relaxed, err)
	}
}

func TestSecretFileNeedsAFileReader(t *testing.T) {
	_, err := resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/run/secrets/x"}, nil, nil)
	if !isConfigError(err) || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("got %v", err)
	}
}

func TestBrokerSettingsAreRequired(t *testing.T) {
	for _, name := range []string{"MCP_AUTHPROXY_ENTRA_TENANT", "MCP_AUTHPROXY_ENTRA_CLIENT_ID", "MCP_AUTHPROXY_KEYS_DIR", "MCP_AUTHPROXY_STATIC_CLIENTS_FILE"} {
		if _, err := load(t, nil, name+"="); !isConfigError(err) || !strings.Contains(err.Error(), name+" is required") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := load(t, nil, "MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE="); !isConfigError(err) || !strings.Contains(err.Error(), "MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE is required") {
		t.Errorf("secret: %v", err)
	}
	if _, err := load(t, nil, "MCP_AUTHPROXY_ENTRA_TENANT=contoso.onmicrosoft.com"); !isConfigError(err) || !strings.Contains(err.Error(), "want the tenant ID, a GUID") {
		t.Errorf("tenant: %v", err)
	}
	c, err := load(t, nil)
	if err != nil || c.EntraClientSecret != "s3cret-entra" || c.KeysDir == "" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
}

func TestInternalListenDefaultsToLoopbackAndMustDifferFromListen(t *testing.T) {
	base := []string{"MCP_AUTHPROXY_INSECURE_NO_AUTH=true", "MCP_AUTHPROXY_PUBLIC_URL=http://127.0.0.1:8080/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"}
	cfg, _, err := Load(nil, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InternalListen != "127.0.0.1:9090" {
		t.Fatalf("default internal listener = %q, want 127.0.0.1:9090", cfg.InternalListen)
	}
	cfg, _, err = Load(nil, append(base, "MCP_AUTHPROXY_INTERNAL_LISTEN="), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InternalListen != "" {
		t.Fatalf("MCP_AUTHPROXY_INTERNAL_LISTEN= must turn the internal listener off, got %q", cfg.InternalListen)
	}
	for _, bad := range []string{"9090", "127.0.0.1:8080"} {
		if _, _, err := Load(nil, append(base, "MCP_AUTHPROXY_INTERNAL_LISTEN="+bad), nil); err == nil || !strings.Contains(err.Error(), "MCP_AUTHPROXY_INTERNAL_LISTEN") {
			t.Errorf("MCP_AUTHPROXY_INTERNAL_LISTEN=%q: want an error naming the setting, got %v", bad, err)
		}
	}
}

func noAuthEnv(extra ...string) []string {
	return append([]string{"MCP_AUTHPROXY_INSECURE_NO_AUTH=true", "MCP_AUTHPROXY_PUBLIC_URL=http://127.0.0.1:8080/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"}, extra...)
}

func TestOAuthRateLimitsDefaultToADR0018AndCanBeRaisedWithinBounds(t *testing.T) {
	cfg, _, err := Load(nil, noAuthEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"authorize": 30, "consent": 60, "callback": 30, "token": 60, "revoke": 30, "register": 30}
	for ep, n := range want {
		if cfg.OAuthRateLimits[ep] != n {
			t.Errorf("default %s = %d/min, want %d", ep, cfg.OAuthRateLimits[ep], n)
		}
	}
	cfg, _, err = Load(nil, noAuthEnv("MCP_AUTHPROXY_OAUTH_RATE_LIMITS=authorize=120, token=600"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthRateLimits["authorize"] != 120 || cfg.OAuthRateLimits["token"] != 600 || cfg.OAuthRateLimits["callback"] != 30 {
		t.Errorf("overrides = %v, want authorize 120, token 600 and the other defaults", cfg.OAuthRateLimits)
	}
	for _, bad := range []string{"metadata=10", "authorize", "authorize=0", "authorize=10001", "authorize=fast", "authorize=-5"} {
		if _, _, err := Load(nil, noAuthEnv("MCP_AUTHPROXY_OAUTH_RATE_LIMITS="+bad), nil); err == nil || !strings.Contains(err.Error(), "MCP_AUTHPROXY_OAUTH_RATE_LIMITS") {
			t.Errorf("MCP_AUTHPROXY_OAUTH_RATE_LIMITS=%q: want an error naming the setting, got %v", bad, err)
		}
	}
}

func TestTrustedProxiesTakeCIDRsAndAddresses(t *testing.T) {
	cfg, _, err := Load(nil, noAuthEnv("MCP_AUTHPROXY_TRUSTED_PROXIES=10.0.0.0/8, 192.0.2.7, 2001:db8::/32, 10.1.2.3/8"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(cfg.TrustedProxies)
	if want := "[10.0.0.0/8 192.0.2.7/32 2001:db8::/32 10.0.0.0/8]"; got != want {
		t.Errorf("trusted proxies = %s, want %s (bare addresses as /32 or /128, prefixes masked)", got, want)
	}
	if cfg, _, err := Load(nil, noAuthEnv(), nil); err != nil || len(cfg.TrustedProxies) != 0 {
		t.Errorf("default trusted proxies = %v (err %v), want none", cfg.TrustedProxies, err)
	}
	if _, _, err := Load(nil, noAuthEnv("MCP_AUTHPROXY_TRUSTED_PROXIES=proxy.internal"), nil); err == nil || !strings.Contains(err.Error(), "MCP_AUTHPROXY_TRUSTED_PROXIES") {
		t.Errorf("a hostname must be rejected with the setting named, got %v", err)
	}
}
