package config

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

var anon = []string{
	"MCP_AUTHPROXY_INSECURE_NO_AUTH=true",
	"MCP_AUTHPROXY_PUBLIC_URL=http://localhost:8080/mcp",
	"MCP_AUTHPROXY_UPSTREAM_URL=http://upstream:9000/mcp",
}

func loadAnon(t *testing.T, readFile readFileFunc, env ...string) (*Config, error) {
	t.Helper()
	c, _, err := Load(nil, append(append([]string{}, anon...), env...), readFile)
	return c, err
}

func TestNoAuthOnLoopbackStartsWithoutDevAndSaysAuthIsOff(t *testing.T) {
	c, err := loadAnon(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.NoAuth || c.Dev || !strings.Contains(strings.Join(c.Relaxations, "|"), "AUTHENTICATION IS OFF") {
		t.Fatalf("noauth=%v dev=%v relaxations=%v", c.NoAuth, c.Dev, c.Relaxations)
	}
}

func TestNoAuthIsRefusedOffLoopback(t *testing.T) {
	cases := []struct{ name, env, want string }{
		{"public URL", "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp", "MCP_AUTHPROXY_PUBLIC_URL must be a loopback URL"},
		{"listen outside a container", "MCP_AUTHPROXY_LISTEN=0.0.0.0:8080", "MCP_AUTHPROXY_LISTEN must be a loopback address"},
		{"extra host", "MCP_AUTHPROXY_ALLOWED_HOSTS=proxy.internal:8080", "MCP_AUTHPROXY_ALLOWED_HOSTS may only list loopback hosts"},
		{"extra origin", "MCP_AUTHPROXY_ALLOWED_ORIGINS=https://app.example", "MCP_AUTHPROXY_ALLOWED_ORIGINS may only list loopback origins"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := loadAnon(t, nil, c.env); !isConfigError(err) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want config error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestNoAuthAcceptsLoopbackHostsAndOrigins(t *testing.T) {
	c, err := loadAnon(t, nil, "MCP_AUTHPROXY_ALLOWED_HOSTS=127.0.0.1:8080,localhost", "MCP_AUTHPROXY_ALLOWED_ORIGINS=http://localhost:6274")
	if err != nil || len(c.AllowedOrigins) != 1 || len(c.AllowedHosts) != 2 {
		t.Fatalf("err=%v origins=%v hosts=%v", err, c.AllowedOrigins, c.AllowedHosts)
	}
}

func TestNoAuthInAContainerMayListenOnAllInterfacesWithAWarning(t *testing.T) {
	docker := func(p string) ([]byte, error) {
		if p == "/.dockerenv" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	c, err := loadAnon(t, docker, "MCP_AUTHPROXY_LISTEN=0.0.0.0:8080")
	if err != nil {
		t.Fatal(err)
	}
	if !c.InContainer || !strings.Contains(strings.Join(c.Relaxations, "|"), "docker run -p 127.0.0.1:8080:8080") {
		t.Fatalf("container=%v relaxations=%v", c.InContainer, c.Relaxations)
	}
	if _, err := loadAnon(t, docker, "MCP_AUTHPROXY_LISTEN=0.0.0.0:8080", "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp"); !isConfigError(err) {
		t.Fatalf("a container still needs a loopback public URL, got %v", err)
	}
}

func TestNoAuthCannotBeCombinedWithAuthSettings(t *testing.T) {
	reg := []Setting{{Name: "idp", Auth: true}, {Name: "listen", Default: "x"}}
	v, err := resolve(reg, nil, []string{"MCP_AUTHPROXY_IDP=entra"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{PublicURL: mustURL(t, "http://localhost:8080/mcp"), Listen: "127.0.0.1:8080"}
	if errs := checkNoAuth(c, v); len(errs) != 1 || !strings.Contains(errs[0].Error(), "cannot be combined with MCP_AUTHPROXY_IDP") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestNoAuthOffIsTheDefault(t *testing.T) {
	c, err := load(t, nil)
	if err != nil || c.NoAuth {
		t.Fatalf("noauth=%v err=%v", c != nil && c.NoAuth, err)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
