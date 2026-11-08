package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/logging"
)

// resolvesTo is a resolver that knows one host name.
func resolvesTo(host string, addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, h string) ([]netip.Addr, error) {
		if h != host {
			return nil, errors.New("no such host")
		}
		out := make([]netip.Addr, len(addrs))
		for i, a := range addrs {
			out[i] = netip.MustParseAddr(a)
		}
		return out, nil
	}
}

func hopConfig(t *testing.T, upstream string, edit func(*config.Config)) *config.Config {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{UpstreamURL: u}
	if edit != nil {
		edit(cfg)
	}
	return cfg
}

// A plain-http upstream at a public address is warned about, naming each secret that travels in
// clear; one the internet cannot reach directly, one reached over https, one that does not
// resolve and one that gets no secret are not.
func TestAPlainHTTPUpstreamAtAPublicAddressIsWarnedAbout(t *testing.T) {
	withCredential := func(c *config.Config) { c.UpstreamCredential = "s3cret-credential" }
	for _, tc := range []struct {
		name     string
		upstream string
		resolve  func(context.Context, string) ([]netip.Addr, error)
		edit     func(*config.Config)
		want     string // in the message; "" for no warning
	}{
		{"public by name", "http://mcp.example.com/mcp", resolvesTo("mcp.example.com", "203.0.113.7"), nil, "public address 203.0.113.7 (mcp.example.com), so these travel in clear: the identity assertion"},
		{"public among private", "http://mcp.example.com/mcp", resolvesTo("mcp.example.com", "10.0.0.7", "203.0.113.7"), nil, "203.0.113.7"},
		{"public as a mapped address", "http://mcp.example.com/mcp", resolvesTo("mcp.example.com", "::ffff:203.0.113.7"), nil, "public address 203.0.113.7 "},
		{"public literal", "http://203.0.113.7:8080/mcp", resolvesTo("none"), nil, "203.0.113.7"},
		{"public IPv6 literal", "http://[2001:db8::7]/mcp", resolvesTo("none"), nil, "2001:db8::7"},
		{"every secret", "http://203.0.113.7/mcp", nil, func(c *config.Config) { withCredential(c); c.OBOScopes = []string{"api://x/.default"} },
			"travel in clear: the identity assertion, the upstream credential, an On-Behalf-Of token for a downstream API"},
		{"only the credential", "http://203.0.113.7/mcp", nil, func(c *config.Config) { c.NoAuth = true; withCredential(c) }, "travel in clear: the upstream credential"},
		{"private", "http://mcp.internal/mcp", resolvesTo("mcp.internal", "10.0.0.7", "192.168.1.7"), nil, ""},
		{"loopback", "http://localhost:9000/mcp", resolvesTo("localhost", "127.0.0.1", "::1"), nil, ""},
		{"shared (CGNAT)", "http://100.64.0.7/mcp", nil, nil, ""},
		{"link-local", "http://[fe80::7]/mcp", nil, nil, ""},
		{"unresolvable", "http://mcp.example.com/mcp", resolvesTo("other.example.com", "203.0.113.7"), nil, ""},
		{"https", "https://mcp.example.com/mcp", resolvesTo("mcp.example.com", "203.0.113.7"), nil, ""},
		{"no secret", "http://203.0.113.7/mcp", nil, func(c *config.Config) { c.NoAuth = true }, ""},
		{"stdio", "http://203.0.113.7/mcp", nil, func(c *config.Config) { c.UpstreamCommand = []string{"server"} }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolve := tc.resolve
			if resolve == nil {
				resolve = func(context.Context, string) ([]netip.Addr, error) {
					t.Fatal("an address was resolved")
					return nil, nil
				}
			}
			w, ok := plainHTTPUpstream(context.Background(), hopConfig(t, tc.upstream, tc.edit), resolve)
			if tc.want == "" {
				if ok {
					t.Fatalf("warned %q, want no warning", w.Message)
				}
				return
			}
			if !ok || !strings.Contains(w.Message, tc.want) || w.Setting != "BYWARD_UPSTREAM_URL" || !strings.Contains(w.Fix, "aud") {
				t.Fatalf("warning %+v (%v), want %q, the setting and the aud note", w, ok, tc.want)
			}
			if strings.Contains(w.String(), "s3cret") {
				t.Fatalf("the warning names the credential's value: %s", w)
			}
		})
	}
}

// The proxy logs the warning at startup, from the configuration it starts with.
func TestThePlainHTTPWarningIsLoggedAtStartup(t *testing.T) {
	for _, tc := range []struct {
		upstream string
		warned   bool
	}{{"http://203.0.113.7:9/mcp", true}, {"http://10.0.0.7:9/mcp", false}} {
		t.Run(tc.upstream, func(t *testing.T) {
			cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + tc.upstream,
				"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600)}, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			if _, err := New(cfg, logging.New(&logs, "text")); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(logs.String(), "travel in clear"); got != tc.warned {
				t.Fatalf("warned %v, want %v; log %s", got, tc.warned, logs.String())
			}
			if strings.Contains(logs.String(), upstreamCredential) {
				t.Fatal("the log names the credential")
			}
		})
	}
}

// check --offline judges an upstream given as an address, and resolves no name.
func TestCheckOfflineWarnsOfAPlainHTTPUpstreamGivenAsAPublicAddress(t *testing.T) {
	for _, tc := range []struct {
		upstream string
		warned   bool
	}{{"http://203.0.113.7:9/mcp", true}, {"http://localhost:9/mcp", false}} {
		t.Run(tc.upstream, func(t *testing.T) {
			cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + tc.upstream,
				"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600)}, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			warnings, err := CheckOffline(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var got bool
			for _, w := range warnings {
				got = got || strings.Contains(w.Message, "travel in clear")
			}
			if got != tc.warned {
				t.Fatalf("warned %v, want %v: %v", got, tc.warned, warnings)
			}
		})
	}
}

// doctor reports the plain-http hop, and names the environment's HTTP proxy the upstream's
// requests go through, without its password.
func TestDoctorNamesThePlainHTTPHopAndTheEnvironmentsProxy(t *testing.T) {
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://mcp.example.com/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600)}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		proxy  func(*http.Request) (*url.URL, error)
		status doctor.Status
		want   string
	}{
		{"none", func(*http.Request) (*url.URL, error) { return nil, nil }, doctor.Pass, "doctor checks the proxy in front of it, not the upstream itself"},
		{"a proxy", func(*http.Request) (*url.URL, error) { return url.Parse("http://ops:pw-secret@egress.example:3128") },
			doctor.Pass, "go through the HTTP proxy http://ops:xxxxx@egress.example:3128 from the environment (list the upstream's host in NO_PROXY"},
		{"an invalid proxy", func(*http.Request) (*url.URL, error) { return nil, errors.New(`invalid proxy address "pw-secret"`) },
			doctor.Warn, "not a valid URL, so every request to the upstream fails"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Doctor(context.Background(), cfg, DoctorOptions{Resolve: resolvesTo("mcp.example.com", "203.0.113.7"), UpstreamProxy: tc.proxy})
			if err != nil {
				t.Fatal(err)
			}
			byName := map[string]doctor.Result{}
			for _, c := range rep.Checks {
				byName[c.Name] = c
			}
			up, hop := byName["upstream"], byName["upstream hop"]
			if up.Status != tc.status || !strings.Contains(up.Message, tc.want) || strings.Contains(up.Message+up.Fix, "pw-secret") {
				t.Fatalf("upstream %+v, want %s with %q and no password", up, tc.status, tc.want)
			}
			if hop.Status != doctor.Warn || !strings.Contains(hop.Message, "travel in clear: the upstream credential") || !strings.Contains(hop.Fix, "BYWARD_UPSTREAM_URL: ") {
				t.Fatalf("upstream hop %+v, want a warning naming the credential", hop)
			}
		})
	}
}
