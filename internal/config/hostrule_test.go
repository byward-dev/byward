package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/host"
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
	// An allowed host's host name, and whether the no-auth check reads it as loopback: both read
	// the entry as stored (hostPort), never as given.
	if stored, reason := hostPort(h); reason != "" {
		fmt.Fprintf(&b, "  allowed host: refused: it %s\n", reason)
	} else {
		fmt.Fprintf(&b, "  allowed host: %s, hostname %s, loopback %v\n", stored, host.Hostname(stored), host.LoopbackAsWritten(host.Hostname(stored)))
	}
	if u, reason := parseOrigin("https://" + h); reason != "" {
		fmt.Fprintf(&b, "  origin: refused: %s\n", reason)
	} else {
		fmt.Fprintf(&b, "  origin: %s\n", browserOrigin(u))
	}
	fmt.Fprintf(&b, "  cimd list: %q\n", hostNameReason(h))
	fmt.Fprintf(&b, "  denylist: %q\n", denylistReason(h))
	fmt.Fprintf(&b, "  host header: %s\n", host.Canonical(h))
	// The --dev issuer and the no-auth listen address ask about the host as written, not lower-cased (LoopbackAsWritten sets its case aside).
	if u, err := url.Parse("http://" + h); err == nil {
		fmt.Fprintf(&b, "  loopback as written: %v\n", host.LoopbackAsWritten(u.Hostname()))
	}
	return b.String()
}

// The host rule of every host setting, for each probe spelling, is pinned in
// testdata/hostrule.golden, so a change to any setting's reading of a host shows as a diff. When the
// rule moved into one parser (#521, ADR-0032 slice 1), only A1 changed: LOCALHOST as loopback (#482).
// Regenerate with BYWARD_UPDATE_GOLDEN=1, and review the diff.
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
		t.Errorf("the host rule changed at %s; if intended, regenerate with BYWARD_UPDATE_GOLDEN=1 and review the diff", firstDiff(got, string(want)))
	}
}

// firstDiff is the first line where got and want differ, numbered from 1, with both versions.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d:\n got: %q\nwant: %q", i+1, gl, wl)
		}
	}
	return "no line differs"
}
