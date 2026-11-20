package host

import (
	"errors"
	"testing"
)

// Parse reads a host[:port] as a browser does for its scheme (ADR-0032 §1): a name folded to its
// ASCII lower case, a host ending in a number read as an IPv4 address or refused, an IPv6 address in
// its shortest form, and the scheme's default port dropped. Each refusal is a fixed reason.
func TestParseReadsAHostAsABrowserDoes(t *testing.T) {
	for _, tc := range []struct {
		hostport, scheme string
		kind             Kind
		canonical, port  string
		err              error
	}{
		{"mcp.example.com", "https", Name, "mcp.example.com", "", nil},
		{"MCP.Example.com", "https", Name, "mcp.example.com", "", nil},
		{"mcp.example.com.", "https", Name, "mcp.example.com.", "", nil}, // not the same host (WHATWG URL §3.1)
		{"bücher.example", "https", Name, "xn--bcher-kva.example", "", nil},
		{"XN--BCHER-KVA.example", "https", Name, "xn--bcher-kva.example", "", nil},
		{"ａｐｐ.example", "https", Name, "app.example", "", nil},
		{"my_mcp", "http", Name, "my_mcp", "", nil},
		{"localhost", "http", Name, "localhost", "", nil},
		{"127.0.0.1", "http", IPv4, "127.0.0.1", "", nil},
		{"127.1", "http", IPv4, "127.0.0.1", "", nil},
		{"0x7f.0.0.1", "http", IPv4, "127.0.0.1", "", nil},
		{"010.0.0.1", "http", IPv4, "8.0.0.1", "", nil},
		{"2130706433", "http", IPv4, "127.0.0.1", "", nil},
		{"[::1]", "https", IPv6, "[::1]", "", nil},
		{"[0:0::1]", "https", IPv6, "[::1]", "", nil},
		{"[2001:DB8::1]", "https", IPv6, "[2001:db8::1]", "", nil},
		{"[::ffff:127.0.0.1]", "https", IPv6, "[::ffff:7f00:1]", "", nil},
		{"::1", "https", IPv6, "[::1]", "", nil}, // a bare IPv6 address is taken whole, never as IPv6:port
		{"mcp.example.com:443", "https", Name, "mcp.example.com", "", nil},
		{"mcp.example.com:443", "http", Name, "mcp.example.com", "443", nil},
		{"localhost:80", "http", Name, "localhost", "", nil},
		{"mcp.example.com:08443", "https", Name, "mcp.example.com", "8443", nil},
		{"[::1]:8080", "https", IPv6, "[::1]", "8080", nil},
		{"", "https", 0, "", "", ErrEmpty},
		{":8080", "https", 0, "", "", ErrEmpty},
		{"[::1", "https", 0, "", "", ErrBrackets},
		{"[mcp.example.com]", "https", 0, "", "", ErrBrackets},
		{"a[b]", "https", 0, "", "", ErrBrackets},
		{"[fe80::1%25eth0]", "https", 0, "", "", ErrIPv6},
		{"[1.2.3.4::]", "https", 0, "", "", ErrIPv6},
		{"mcp.example.com:65536", "https", 0, "", "", ErrPort},
		{"mcp.example.com:-1", "https", 0, "", "", ErrPort},
		{"mcp.10", "https", 0, "", "", ErrEndsInANumber},
		{"10.0.0.999", "https", 0, "", "", ErrEndsInANumber},
		{"a b.example", "https", 0, "", "", ErrName},
		{"＠.example", "https", 0, "", "", ErrName},
	} {
		t.Run(tc.hostport+" for "+tc.scheme, func(t *testing.T) {
			h, err := Parse(tc.hostport, tc.scheme)
			if !errors.Is(err, tc.err) {
				t.Fatalf("Parse error %v; want %v", err, tc.err)
			}
			if err != nil {
				return
			}
			if h.Kind != tc.kind || h.Canonical != tc.canonical || h.Port != tc.port {
				t.Errorf("Parse = kind %v, %q, port %q; want kind %v, %q, port %q", h.Kind, h.Canonical, h.Port, tc.kind, tc.canonical, tc.port)
			}
			if want := tc.canonical; tc.port != "" && h.String() != want+":"+tc.port || tc.port == "" && h.String() != want {
				t.Errorf("String() = %q; want the canonical host and its port", h.String())
			}
		})
	}
}

// A parsed host is loopback by the address a browser reads (127.1 is 127.0.0.1), while
// LoopbackAsWritten takes an IPv4 address only in dotted decimal, the form Go's dialer reads. Both
// fold localhost's case (A1, #482). A redirect URI's loopback set is exact instead (ADR-0032 §5).
func TestLoopbackParsedAndAsWritten(t *testing.T) {
	for _, tc := range []struct {
		host              string
		parsed, asWritten bool
	}{
		{"localhost", true, true},
		{"LOCALHOST", true, true},
		{"Localhost", true, true},
		{"127.0.0.1", true, true},
		{"127.0.0.2", true, true},
		{"127.1", true, false}, // the two differ here only
		{"::1", true, true},
		{"::ffff:127.0.0.1", true, true},
		{"[::1]", true, false}, // as written, a host has no brackets
		{"0.0.0.0", false, false},
		{"10.0.0.5", false, false},
		{"localhost.", false, false},
		{"localhost.idp.example", false, false},
		{"evil-localhost", false, false},
		{"localhost:80", true, false}, // as written, a host has no port
		{"fe80::1%eth0", false, false},
		{"", false, false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			h, err := Parse(tc.host, "http")
			if got := err == nil && h.Loopback(); got != tc.parsed {
				t.Errorf("Parse(%q).Loopback() = %v (error %v); want %v", tc.host, got, err, tc.parsed)
			}
			if got := LoopbackAsWritten(tc.host); got != tc.asWritten {
				t.Errorf("LoopbackAsWritten(%q) = %v; want %v", tc.host, got, tc.asWritten)
			}
		})
	}
}
