package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

var base = []string{
	"MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp",
	"MCP_AUTHPROXY_UPSTREAM_URL=http://upstream:9000/mcp",
}

func load(t *testing.T, args []string, env ...string) (*Config, error) {
	t.Helper()
	c, _, err := Load(args, append(append([]string{}, base...), env...), nil)
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
	if !IsConfigError(err) || !strings.Contains(err.Error(), "did you mean MCP_AUTHPROXY_PUBLIC_URL?") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownEnvFarFromAnySettingHasNoSuggestion(t *testing.T) {
	_, err := load(t, nil, "MCP_AUTHPROXY_ZZZZZZZZZZZZZZ=x")
	if !IsConfigError(err) || strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string][]string{
		"required":       {"MCP_AUTHPROXY_PUBLIC_URL="},
		"trailing slash": {"MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp/"},
		"no path":        {"MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com"},
		"http public":    {"MCP_AUTHPROXY_PUBLIC_URL=http://mcp.example.com/mcp"},
		"http loopback":  {"MCP_AUTHPROXY_PUBLIC_URL=http://127.0.0.1:8080/mcp"},
		"credentials":    {"MCP_AUTHPROXY_UPSTREAM_URL=http://u:p@upstream/mcp"},
		"bad origin":     {"MCP_AUTHPROXY_ALLOWED_ORIGINS=https://a.example/path"},
		"bad listen":     {"MCP_AUTHPROXY_LISTEN=8080"},
		"bad log":        {"MCP_AUTHPROXY_LOG_FORMAT=xml"},
		"bad scope":      {"MCP_AUTHPROXY_SCOPE=a b"},
		"bad dev":        {"MCP_AUTHPROXY_DEV=maybe"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, nil, env...); !IsConfigError(err) {
				t.Fatalf("want config error, got %v", err)
			}
		})
	}
}

func TestDevAllowsLoopbackHTTPAndRecordsIt(t *testing.T) {
	c, err := load(t, []string{"--dev"}, "MCP_AUTHPROXY_PUBLIC_URL=http://localhost:8080/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Dev || len(c.Relaxations) != 1 {
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

func TestHelpAndUnexpectedArgs(t *testing.T) {
	if _, _, err := Load([]string{"-h"}, base, nil); !IsHelp(err) {
		t.Fatalf("want help, got %v", err)
	}
	if _, _, err := Load([]string{"extra"}, base, nil); !IsConfigError(err) {
		t.Fatalf("want config error, got %v", err)
	}
	if !strings.Contains(Usage(), "MCP_AUTHPROXY_PUBLIC_URL") {
		t.Fatal("usage lacks env names")
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

func files(m map[string]string) ReadFileFunc {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
}

func TestSecretFromEnvFile(t *testing.T) {
	v, err := Resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/run/secrets/x"}, files(map[string]string{"/run/secrets/x": "s3cret\n"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Effective()[0]
	if got.Raw != "s3cret" || got.Source != SourceFile || got.Display() != "<redacted>" {
		t.Fatalf("got %+v display=%q", got, got.Display())
	}
}

func TestSecretFromFlagFileBeatsEnvFile(t *testing.T) {
	v, err := Resolve(secretReg, []string{"--client-secret-file", "/a"}, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/b"}, files(map[string]string{"/a": "A", "/b": "B"}), nil)
	if err != nil || v.Get("client-secret") != "A" {
		t.Fatalf("got %q err=%v", v.Get("client-secret"), err)
	}
}

func TestSecretFileMissingIsConfigError(t *testing.T) {
	_, err := Resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET_FILE=/nope"}, files(nil), nil)
	if !IsConfigError(err) || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("err = %v", err)
	}
}

func TestInlineSecretIsReported(t *testing.T) {
	v, err := Resolve(secretReg, nil, []string{"MCP_AUTHPROXY_CLIENT_SECRET=inline"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.InlineSecrets(); len(got) != 1 || got[0] != "MCP_AUTHPROXY_CLIENT_SECRET" {
		t.Fatalf("inline = %v", got)
	}
	if v.Effective()[0].Display() != "<redacted>" {
		t.Fatal("inline secret not redacted")
	}
}

func TestSecretHasNoInlineFlag(t *testing.T) {
	_, err := Resolve(secretReg, []string{"--client-secret", "x"}, nil, nil, nil)
	if !IsConfigError(err) {
		t.Fatalf("want config error, got %v", err)
	}
}

func TestIsConfigErrorWrapped(t *testing.T) {
	if !IsConfigError(errors.Join(errors.New("x"), &Error{Msg: "y"})) {
		t.Fatal("wrapped config error not detected")
	}
}
