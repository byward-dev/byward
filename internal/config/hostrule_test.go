package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/host"
	"github.com/byward-dev/byward/internal/testutil/golden"
)

// hostProbes are host spellings that the host settings once each read their own way (#486): case,
// a trailing dot, loopback, numeric IPv4 spellings, a name ending in a number, IPv6 forms, IDN,
// characters a DNS name never uses, and ports.
var hostProbes = []string{
	"mcp.example.com", "MCP.Example.com", "mcp.example.com.", "localhost", "LOCALHOST", "Localhost",
	"127.0.0.1", "127.0.0.2", "127.1", "0x7f.0.0.1", "010.0.0.1", "2130706433", "0.0.0.0",
	"mcp.10", "10.0.0.999", "[::1]", "[0:0::1]", "[2001:DB8::1]", "[::ffff:127.0.0.1]", "[fe80::1%25eth0]", "::1", "fe80::1%eth0", "app.0x",
	"xn--bcher-kva.example", "bücher.example", "my_host.example", "my_mcp", "S3CRET~tok", "single", "a..b",
	"mcp.example.com:443", "mcp.example.com:8443", "[::1]:8080", "localhost:80",
}

// hostRule is what each host setting makes of h: the public URL (https and http), the upstream URL
// and a listen address, an allowed host, an origin, a CIMD list entry, a client denylist entry, the
// Host header form the public listener compares, and whether the host is loopback, by its host name
// and as written.
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
	// The operator addresses (class O, ADR-0032 §2): their host names hold only §3's characters, and
	// the rest of the upstream's host is left to Go's dialer; a listen address gets port 80 if h has none.
	if u, err := ParseUpstreamURL("http://" + h + "/mcp"); err != nil {
		fmt.Fprintf(&b, "  upstream: refused: %v\n", err)
	} else {
		fmt.Fprintf(&b, "  upstream: %s\n", u.Host)
	}
	listen := h
	if _, _, err := net.SplitHostPort(h); err != nil {
		listen = net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"), "80")
	}
	if got, err := parseListen(Value{Setting: lookup("listen"), Given: NewOpaque(listen)}, "host:port such as 127.0.0.1:8080"); err != nil {
		fmt.Fprintf(&b, "  listen: refused: %v\n", err)
	} else {
		fmt.Fprintf(&b, "  listen: %s\n", got)
	}
	// An allowed host's host name, and whether the no-auth check reads it as loopback: both read
	// the entry as stored (hostPort), never as given.
	if stored, errs := parseAllowedHosts(Value{Setting: lookup("allowed-hosts"), Given: NewOpaque(h)}); len(errs) > 0 {
		fmt.Fprintf(&b, "  allowed host: refused: %v\n", errors.Join(errs...))
	} else {
		fmt.Fprintf(&b, "  allowed host: %s, hostname %s, loopback %v\n", stored[0], host.Hostname(stored[0]), host.LoopbackAsWritten(host.Hostname(stored[0])))
	}
	if u, reason := parseOrigin("https://" + h); reason != "" {
		fmt.Fprintf(&b, "  origin: refused: %s\n", reason)
	} else {
		fmt.Fprintf(&b, "  origin: %s\n", browserOrigin(u))
	}
	fmt.Fprintf(&b, "  cimd list: %q\n", hostNameReason(h))
	fmt.Fprintf(&b, "  denylist: %q\n", denylistReason(h))
	fmt.Fprintf(&b, "  host header: %s\n", host.MatchKey(h))
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
	golden.Check(t, "testdata/hostrule.golden", b.String(), "the file pins how each host setting reads each probe spelling (ADR-0032); a reading change is either one ADR-0032 §4 lists (slices 2–4) or needs an amendment to ADR-0032 (docs/adr/README.md); a reworded refusal needs neither")
}
