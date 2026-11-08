package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"golang.org/x/net/http/httpproxy"
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

// withResolver makes the package's system resolver resolve for the test.
func withResolver(t *testing.T, resolve func(context.Context, string) ([]netip.Addr, error)) {
	prev := lookupNetIP
	lookupNetIP = resolve
	t.Cleanup(func() { lookupNetIP = prev })
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

// noAuthHopConfig is a configuration without authentication whose HTTP upstream gets the operator
// credential.
func noAuthHopConfig(t *testing.T, upstream string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + upstream,
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credentialFile(t, 0o600)}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// authHopConfig is a configuration with authentication: every request carries the assertion.
func authHopConfig(t *testing.T, upstream string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+upstream), os.ReadFile)
	if err != nil {
		t.Fatal(err)
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
		resolve  func(context.Context, string) ([]netip.Addr, error) // nil: must not be asked
		edit     func(*config.Config)
		want     string // in the message; "" for no warning
	}{
		{"public by name", "http://mcp.example.com/mcp", resolvesTo("mcp.example.com", "203.0.113.7"), nil, "public address 203.0.113.7 (mcp.example.com), so these travel in clear: the identity assertion"},
		{"public among private", "http://mcp.example.com/mcp", resolvesTo("mcp.example.com", "10.0.0.7", "203.0.113.7"), nil, "203.0.113.7"},
		{"public as a mapped address", "http://mcp.example.com/mcp", resolvesTo("mcp.example.com", "::ffff:203.0.113.7"), nil, "public address 203.0.113.7 "},
		{"public literal", "http://203.0.113.7:8080/mcp", nil, nil, "203.0.113.7"},
		{"public IPv6 literal", "http://[2001:db8::7]/mcp", nil, nil, "2001:db8::7"},
		{"every secret", "http://203.0.113.7/mcp", nil, func(c *config.Config) { withCredential(c); c.OBOScopes = []string{"api://x/.default"} },
			"travel in clear: the identity assertion, the upstream credential, an On-Behalf-Of token for a downstream API"},
		{"only the credential", "http://203.0.113.7/mcp", nil, func(c *config.Config) { c.NoAuth = true; withCredential(c) }, "travel in clear: the upstream credential"},
		{"private", "http://mcp.internal/mcp", resolvesTo("mcp.internal", "10.0.0.7", "192.168.1.7"), nil, ""},
		{"loopback", "http://localhost:9000/mcp", resolvesTo("localhost", "127.0.0.1", "::1"), nil, ""},
		{"shared (CGNAT)", "http://100.64.0.7/mcp", nil, nil, ""},
		{"link-local", "http://[fe80::7]/mcp", nil, nil, ""},
		{"unspecified IPv4", "http://0.0.0.0:8080/mcp", nil, nil, ""},
		{"unspecified IPv6", "http://[::]:8080/mcp", nil, nil, ""},
		{"unresolvable", "http://mcp.example.com/mcp", resolvesTo("other.example.com", "203.0.113.7"), nil, ""},
		{"https", "https://mcp.example.com/mcp", nil, nil, ""},
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
			cfg := hopConfig(t, tc.upstream, tc.edit)
			if !ok || !strings.Contains(w.Message, tc.want) || w.Setting != "BYWARD_UPSTREAM_URL" || strings.Contains(w.Fix, "aud") == cfg.NoAuth {
				t.Fatalf("warning %+v (%v), want %q, the setting, and the aud note exactly when an assertion is sent", w, ok, tc.want)
			}
			if strings.Contains(w.String(), "s3cret") {
				t.Fatalf("the warning names the credential's value: %s", w)
			}
		})
	}
}

// The warning's fix points at a guide section that exists.
func TestThePlainHTTPWarningPointsAtTheHardeningGuide(t *testing.T) {
	w, ok := plainHTTPUpstream(context.Background(), hopConfig(t, "http://203.0.113.7/mcp", nil), nil)
	m := regexp.MustCompile(`(docs/how-to/[a-z-]+\.md), "([^"]+)"`).FindStringSubmatch(w.Fix)
	if !ok || m == nil {
		t.Fatalf("fix %q names no guide section", w.Fix)
	}
	guide, err := os.ReadFile(filepath.Join("..", "..", m[1]))
	if err != nil || !regexp.MustCompile(`(?m)^## \d+\. `+regexp.QuoteMeta(m[2])+`$`).Match(guide) {
		t.Fatalf("%s has no section %q (%v)", m[1], m[2], err)
	}
}

// A lookup of the upstream's host that hangs is bounded: the resolver is given a deadline.
func TestALookupOfTheUpstreamsHostThatHangsIsBounded(t *testing.T) {
	var bounded bool
	plainHTTPUpstream(context.Background(), hopConfig(t, "http://mcp.example.com/mcp", nil), func(ctx context.Context, _ string) ([]netip.Addr, error) {
		_, bounded = ctx.Deadline()
		return nil, errors.New("timed out")
	})
	if !bounded {
		t.Fatal("the upstream's host was resolved without a deadline")
	}
}

// The proxy logs the warning at startup as a warning naming the setting, for an upstream given by
// name or as an address.
func TestThePlainHTTPWarningIsLoggedAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
		warned   bool
	}{
		{"a public name warns", "http://mcp.example.com:9/mcp", true},
		{"a public address warns", "http://203.0.113.7:9/mcp", true},
		{"a private address is silent", "http://10.0.0.7:9/mcp", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withResolver(t, resolvesTo("mcp.example.com", "203.0.113.7"))
			var logs bytes.Buffer
			if _, err := New(noAuthHopConfig(t, tc.upstream), logging.New(&logs, "text")); err != nil {
				t.Fatal(err)
			}
			line := regexp.MustCompile(`level=WARN msg="[^"]*travel in clear: the upstream credential" setting=BYWARD_UPSTREAM_URL reason=`)
			if got := line.MatchString(logs.String()); got != tc.warned {
				t.Fatalf("warned %v, want %v; log %s", got, tc.warned, logs.String())
			}
			if strings.Contains(logs.String(), upstreamCredential) {
				t.Fatal("the log names the credential")
			}
		})
	}
}

// check --offline judges only an upstream given as an address: a name, even one that resolves to a
// public address, is not looked up. With authentication it names the assertion.
func TestCheckOfflineWarnsOfAPlainHTTPUpstreamGivenAsAPublicAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(*testing.T, string) *config.Config
		up   string
		want string // "" for no warning
	}{
		{"a public address warns", noAuthHopConfig, "http://203.0.113.7:9/mcp", "travel in clear: the upstream credential"},
		{"with authentication, the assertion", authHopConfig, "http://203.0.113.7:9/mcp", "travel in clear: the identity assertion"},
		{"a name is not resolved", noAuthHopConfig, "http://mcp.example.com:9/mcp", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withResolver(t, resolvesTo("mcp.example.com", "203.0.113.7"))
			warnings, err := CheckOffline(tc.cfg(t, tc.up))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, w := range warnings {
				if strings.Contains(w.Message, "travel in clear") {
					got = append(got, w.Message)
				}
			}
			if (tc.want == "") != (len(got) == 0) || (tc.want != "" && !strings.Contains(strings.Join(got, "\n"), tc.want)) {
				t.Fatalf("hop warnings %q, want %q", got, tc.want)
			}
		})
	}
}

// doctor names the environment's HTTP proxy the upstream's requests go through, by scheme and host
// alone, from the setting as Go reads it; a setting whose credentials Go splits, and Go's refusal
// of HTTP_PROXY under CGI, warn without naming it.
func TestDoctorNamesTheEnvironmentsProxyWithoutItsCredentials(t *testing.T) {
	cfg := noAuthHopConfig(t, "http://10.0.0.7/mcp")
	for _, tc := range []struct {
		name     string
		proxy    httpproxy.Config
		status   doctor.Status
		want     string
		notWants []string
	}{
		{"no proxy is named when none applies", httpproxy.Config{}, doctor.Pass, "HTTP upstream http://10.0.0.7/mcp", []string{"HTTP proxy"}},
		{"a proxy is named without its password", httpproxy.Config{HTTPProxy: "http://ops:pw-secret@egress.example:3128"},
			doctor.Pass, "go through the HTTP proxy http://egress.example:3128 from the environment (list the upstream's host in NO_PROXY", []string{"ops", "pw-secret"}},
		{"a proxy without a scheme is named without its password", httpproxy.Config{HTTPProxy: "ops:pw-secret@egress.example:3128"},
			doctor.Pass, "go through the HTTP proxy http://egress.example:3128 ", []string{"ops", "pw-secret"}},
		{"a password with a slash is never shown", httpproxy.Config{HTTPProxy: "http://ops:pw/secret@egress.example:3128"},
			doctor.Warn, "has an unescaped /, ? or # before its host", []string{"ops", "pw", "secret"}},
		{"a numeric password with a slash is never shown", httpproxy.Config{HTTPProxy: "admin:1234/5678@egress.example:3128"},
			doctor.Warn, "has an unescaped /, ? or # before its host", []string{"admin", "1234", "5678"}},
		{"the refusal under CGI warns", httpproxy.Config{HTTPProxy: "http://ops:pw-secret@egress.example:3128", NoProxy: "10.0.0.7", CGI: true},
			doctor.Warn, "Go refuses HTTP_PROXY because REQUEST_METHOD is set", []string{"pw-secret", "list the upstream's host in NO_PROXY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pf := tc.proxy.ProxyFunc()
			rep, err := Doctor(context.Background(), cfg, DoctorOptions{UpstreamProxy: func(r *http.Request) (*url.URL, error) { return pf(r.URL) }})
			if err != nil {
				t.Fatal(err)
			}
			up := checkNamed(t, rep, "upstream")
			if up.Status != tc.status || !strings.Contains(up.Message, tc.want) {
				t.Fatalf("upstream %+v, want %s with %q", up, tc.status, tc.want)
			}
			for _, n := range tc.notWants {
				if strings.Contains(up.Message+up.Fix, n) {
					t.Fatalf("upstream %+v shows %q", up, n)
				}
			}
		})
	}
}

// doctor reports the plain-http hop with and without authentication, naming what travels in clear.
func TestDoctorWarnsOfThePlainHTTPHop(t *testing.T) {
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: "00000000-0000-0000-0000-000000000002", Secrets: []string{"s3cret-entra"}}))
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"without authentication", noAuthHopConfig(t, "http://mcp.example.com/mcp"), "travel in clear: the upstream credential"},
		{"with authentication", authHopConfig(t, "http://mcp.example.com/mcp"), "travel in clear: the identity assertion"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Doctor(context.Background(), tc.cfg, DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}},
				Resolve: resolvesTo("mcp.example.com", "203.0.113.7"), UpstreamProxy: func(*http.Request) (*url.URL, error) { return nil, nil }})
			if err != nil {
				t.Fatal(err)
			}
			hop := checkNamed(t, rep, "upstream hop")
			if hop.Status != doctor.Warn || !strings.Contains(hop.Message, tc.want) || !strings.HasPrefix(hop.Fix, "BYWARD_UPSTREAM_URL: ") {
				t.Fatalf("upstream hop %+v, want a warning with %q", hop, tc.want)
			}
		})
	}
}

// checkNamed is the report's check called name.
func checkNamed(t *testing.T, rep doctor.Report, name string) doctor.Result {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, rep.Checks)
	return doctor.Result{}
}

// Startup gives the lookup its own budget, shorter than doctor's.
func TestStartupBoundsTheLookupOfTheUpstreamsHost(t *testing.T) {
	var left time.Duration
	withResolver(t, func(ctx context.Context, _ string) ([]netip.Addr, error) {
		d, _ := ctx.Deadline()
		left = time.Until(d)
		return nil, errors.New("timed out")
	})
	if _, err := New(noAuthHopConfig(t, "http://mcp.example.com:9/mcp"), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if left <= 0 || left > startupResolveTimeout {
		t.Fatalf("the lookup had %v left, want at most %v", left, startupResolveTimeout)
	}
}

// doctor's own resolver, the one `byward doctor` runs with, resolves the upstream's host.
func TestDoctorResolvesTheUpstreamsHostByDefault(t *testing.T) {
	withResolver(t, resolvesTo("mcp.example.com", "203.0.113.7"))
	rep, err := Doctor(context.Background(), noAuthHopConfig(t, "http://mcp.example.com/mcp"),
		DoctorOptions{UpstreamProxy: func(*http.Request) (*url.URL, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if hop := checkNamed(t, rep, "upstream hop"); !strings.Contains(hop.Message, "203.0.113.7") {
		t.Fatalf("upstream hop %+v, want the address the system resolver gave", hop)
	}
}

// With authentication too, doctor names the environment's HTTP proxy.
func TestDoctorNamesTheEnvironmentsProxyWithAuthentication(t *testing.T) {
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: "00000000-0000-0000-0000-000000000002", Secrets: []string{"s3cret-entra"}}))
	rep, err := Doctor(context.Background(), authHopConfig(t, "http://10.0.0.7/mcp"), DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}},
		UpstreamProxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://egress.example:3128") }})
	if err != nil {
		t.Fatal(err)
	}
	if up := checkNamed(t, rep, "upstream"); !strings.Contains(up.Message, "HTTP proxy http://egress.example:3128") {
		t.Fatalf("upstream %+v, want the proxy named", up)
	}
}
