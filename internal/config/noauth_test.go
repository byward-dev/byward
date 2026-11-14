package config

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

var anon = []string{
	"BYWARD_INSECURE_NO_AUTH=true",
	"BYWARD_PUBLIC_URL=http://localhost:8080/mcp",
	"BYWARD_UPSTREAM_URL=http://upstream:9000/mcp",
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
		{"public URL", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_PUBLIC_URL must be a loopback URL"},
		{"listen outside a container", "BYWARD_LISTEN=0.0.0.0:8080", "BYWARD_LISTEN must be a loopback address"},
		{"listen on all interfaces by omission", "BYWARD_LISTEN=:8080", "BYWARD_LISTEN must be a loopback address"},
		{"listen without port", "BYWARD_LISTEN=0.0.0.0", "BYWARD_LISTEN"},
		{"listen on all IPv6 interfaces", "BYWARD_LISTEN=[::]:8080", "BYWARD_LISTEN must be a loopback address"},
		{"flag not a bool", "BYWARD_INSECURE_NO_AUTH=yes", "BYWARD_INSECURE_NO_AUTH: want true or false"},
		{"extra host", "BYWARD_ALLOWED_HOSTS=proxy.internal:8080", "BYWARD_ALLOWED_HOSTS may only list loopback hosts"},
		{"extra origin", "BYWARD_ALLOWED_ORIGINS=https://app.example", "BYWARD_ALLOWED_ORIGINS may only list loopback origins"},
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
	c, err := loadAnon(t, nil, "BYWARD_ALLOWED_HOSTS=127.0.0.1:8080,localhost,[::1],[::1]:8080,::1", "BYWARD_ALLOWED_ORIGINS=http://localhost:6274", "BYWARD_LISTEN=[::1]:8080", "BYWARD_PUBLIC_URL=http://[::1]:8080/mcp")
	if err != nil || len(c.AllowedOrigins) != 1 || len(c.AllowedHosts) != 5 {
		t.Fatalf("err=%v origins=%v hosts=%v", err, c.AllowedOrigins, c.AllowedHosts)
	}
}

// fakeHost answers readFile for the given marker file and network interface list; every ethN is a
// veth (iflink differs from ifindex) unless physical lists it.
func fakeHost(marker, netdev string, physical ...string) readFileFunc {
	return func(p string) ([]byte, error) {
		switch {
		case p == marker:
			return nil, nil
		case p == "/proc/self/net/dev" && netdev != "":
			return []byte(netdev), nil
		case strings.HasPrefix(p, "/sys/class/net/eth"):
			name := strings.Split(strings.TrimPrefix(p, "/sys/class/net/"), "/")[0]
			if strings.HasSuffix(p, "/ifindex") {
				return []byte("11\n"), nil
			}
			for _, ph := range physical {
				if ph == name {
					return []byte("11\n"), nil
				}
			}
			return []byte("25\n"), nil
		}
		return nil, os.ErrNotExist
	}
}

const netdevHeader = "Inter-|   Receive\n face |bytes\n"

// Measured on Docker 28.4 (2026-11-06).
const (
	bridgeNetdev = netdevHeader + "    lo: 0\n tunl0: 0\n  gre0: 0\ngretap0: 0\nerspan0: 0\nip_vti0: 0\nip6_vti0: 0\n  sit0: 0\nip6tnl0: 0\nip6gre0: 0\n  eth0: 0\n"
	hostNetdev   = netdevHeader + "    lo: 0\n bond0: 0\ndummy0: 0\n  eth0: 0\n teql0: 0\n tunl0: 0\nservices1: 0\ndocker0: 0\n"
)

func TestNoAuthInAContainerMayListenOnAllInterfacesWithAWarning(t *testing.T) {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		c, err := loadAnon(t, fakeHost(marker, bridgeNetdev), "BYWARD_LISTEN=0.0.0.0:8080", "BYWARD_PUBLIC_URL=http://localhost:18420/mcp")
		if err != nil {
			t.Fatalf("%s: %v", marker, err)
		}
		// Host port from the public URL, container port from the listen address.
		if !c.InContainer || !strings.Contains(strings.Join(c.Relaxations, "|"), "docker run -p 127.0.0.1:18420:8080") {
			t.Fatalf("%s: container=%v relaxations=%v", marker, c.InContainer, c.Relaxations)
		}
	}
	if _, err := loadAnon(t, fakeHost("/.dockerenv", bridgeNetdev), "BYWARD_LISTEN=0.0.0.0:8080", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp"); !isConfigError(err) {
		t.Fatalf("a container still needs a loopback public URL, got %v", err)
	}
}

func TestNoAuthInAContainerHintUsesTheSchemesDefaultPort(t *testing.T) {
	c, err := loadAnon(t, fakeHost("/.dockerenv", bridgeNetdev), "BYWARD_LISTEN=0.0.0.0:8443", "BYWARD_PUBLIC_URL=https://localhost/mcp")
	if err != nil || !strings.Contains(strings.Join(c.Relaxations, "|"), "docker run -p 127.0.0.1:443:8443") {
		t.Fatalf("err=%v relaxations=%v", err, c.Relaxations)
	}
}

func TestNoAuthWithHostNetworkingIsRefused(t *testing.T) {
	cases := map[string]string{
		"docker --network host":             hostNetdev,
		"interfaces cannot be read":         "",
		"an unknown interface (e.g. wlan0)": netdevHeader + "    lo: 0\n  eth0: 0\n wlan0: 0\n",
	}
	for name, netdev := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadAnon(t, fakeHost("/.dockerenv", netdev), "BYWARD_LISTEN=0.0.0.0:8080")
			if !isConfigError(err) || !strings.Contains(err.Error(), "not --network host") {
				t.Fatalf("want refusal, got %v", err)
			}
		})
	}
	// Podman --network host on a VM whose only NIC is a physical eth0 (iflink == ifindex).
	t.Run("physical eth0 only", func(t *testing.T) {
		_, err := loadAnon(t, fakeHost("/run/.containerenv", netdevHeader+"    lo: 0\n  eth0: 0\n", "eth0"), "BYWARD_LISTEN=0.0.0.0:8080")
		if !isConfigError(err) || !strings.Contains(err.Error(), "not --network host") {
			t.Fatalf("want refusal, got %v", err)
		}
	})
}

func TestOriginDropsTheDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"https://mcp.example.com:443/mcp":  "https://mcp.example.com",
		"https://MCP.example.com:8443/mcp": "https://mcp.example.com:8443",
		"http://localhost:80/mcp":          "http://localhost",
		"http://[::1]:8080/mcp":            "http://[::1]:8080",
	} {
		if got := (&Config{PublicURL: mustURL(t, raw)}).Origin(); got != want {
			t.Errorf("%s: got %s want %s", raw, got, want)
		}
	}
}

func TestNoAuthCannotBeCombinedWithAuthSettings(t *testing.T) {
	// A synthetic registry keeps this test independent of which settings carry Auth.
	reg := []Setting{{Name: "idp", Auth: true}, {Name: "listen", Default: "x"}}
	v, err := resolve(reg, nil, []string{"BYWARD_IDP=entra"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{PublicURL: mustURL(t, "http://localhost:8080/mcp"), Listen: "127.0.0.1:8080"}
	if errs := checkNoAuth(c, v); len(errs) != 1 || !strings.Contains(errs[0].Error(), "cannot be combined with BYWARD_IDP") {
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

func TestNoAuthRefusesRealAuthSettings(t *testing.T) {
	_, err := loadAnon(t, nil, "BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001")
	if !isConfigError(err) || !strings.Contains(err.Error(), "cannot be combined with BYWARD_ENTRA_TENANT") {
		t.Fatalf("got %v", err)
	}
}
