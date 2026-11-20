package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
)

// hostProbes are host spellings that the host settings once each read their own way (#486): case,
// a trailing dot, loopback, numeric IPv4 spellings, a name ending in a number, IPv6 forms, IDN,
// characters a DNS name never uses, and ports.
var hostProbes = []string{
	"mcp.example.com", "MCP.Example.com", "mcp.example.com.", "localhost", "LOCALHOST", "Localhost",
	"127.0.0.1", "127.0.0.2", "127.1", "0x7f.0.0.1", "010.0.0.1", "2130706433", "0.0.0.0",
	"mcp.10", "10.0.0.999", "[::1]", "[0:0::1]", "[2001:DB8::1]", "[::ffff:127.0.0.1]", "[fe80::1%25eth0]",
	"xn--bcher-kva.example", "bücher.example", "my_host.example", "my_mcp", "S3CRET~tok", "single", "a..b",
	"mcp.example.com:443", "mcp.example.com:8443", "[::1]:8080", "localhost:80",
}

// hostRule is what each host setting makes of h: the public URL (https and http), an allowed host,
// an origin, a CIMD list entry, a client denylist entry, the Host header form the public listener
// compares, and whether the host is loopback, by its host name and as written.
func hostRule(h string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", h)
	for _, scheme := range []string{"https", "http"} {
		if u, err := ParsePublicURL(scheme + "://" + h + "/mcp"); err != nil {
			fmt.Fprintf(&b, "  public %s: refused: %v\n", scheme, err)
		} else {
			fmt.Fprintf(&b, "  public %s: %s\n", scheme, u.Host)
		}
	}
	if stored, reason := hostPort(h); reason != "" {
		fmt.Fprintf(&b, "  allowed host: refused: it %s\n", reason)
	} else {
		fmt.Fprintf(&b, "  allowed host: %s\n", stored)
	}
	if u, reason := parseOrigin("https://" + h); reason != "" {
		fmt.Fprintf(&b, "  origin: refused: %s\n", reason)
	} else {
		fmt.Fprintf(&b, "  origin: %s\n", browserOrigin(u))
	}
	fmt.Fprintf(&b, "  cimd list: %q\n", hostNameReason(h))
	fmt.Fprintf(&b, "  denylist: %q\n", denylistReason(h))
	fmt.Fprintf(&b, "  host header: %s\n", CanonicalHost(h))
	fmt.Fprintf(&b, "  hostname: %s, loopback %v\n", Hostname(h), isLoopback(Hostname(h)))
	// The --dev issuer and the no-auth listen address ask about the host as written, case and all.
	if u, err := url.Parse("http://" + h); err == nil {
		fmt.Fprintf(&b, "  loopback as written: %v\n", isLoopback(u.Hostname()))
	}
	return b.String()
}

// The host rule of every host setting, for each probe spelling, is pinned in
// testdata/hostrule.golden. Moving the rule into one parser (#521, ADR-0032 slice 1) changes only
// A1, LOCALHOST as loopback (#482); every other line is the same. Regenerate with
// BYWARD_UPDATE_GOLDEN=1, and review the diff.
func TestEachHostSettingReadsEachProbeSpellingAsPinned(t *testing.T) {
	var b strings.Builder
	for _, h := range hostProbes {
		b.WriteString(hostRule(h))
	}
	const golden = "testdata/hostrule.golden"
	if os.Getenv("BYWARD_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != string(want) {
		t.Errorf("the host rule changed; if intended, regenerate with BYWARD_UPDATE_GOLDEN=1 and review the diff\ngot:\n%s", got)
	}
}
