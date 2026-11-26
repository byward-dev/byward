package host

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
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
		{"xn--a.example", "https", Name, "xn--a.example", "", nil}, // an ASCII domain is not checked by IDNA
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
		{"[::1]8080", "https", 0, "", "", ErrBrackets}, // after "]" comes a port's ":" or nothing
		{"[::1]x", "https", 0, "", "", ErrBrackets},
		{"[fe80::1%25eth0]", "https", 0, "", "", ErrIPv6},
		{"[1.2.3.4::]", "https", 0, "", "", ErrIPv6},
		{"mcp.example.com:65536", "https", 0, "", "", ErrPort},
		{"mcp.example.com:-1", "https", 0, "", "", ErrPort},
		{"mcp.10", "https", 0, "", "", ErrEndsInANumber},
		{"10.0.0.999", "https", 0, "", "", ErrEndsInANumber},
		{"a b.example", "https", 0, "", "", ErrName},
		{"＠.example", "https", 0, "", "", ErrName},
		{"\u0080.example", "https", 0, "", "", ErrName}, // the first code point past ASCII goes to IDNA, which refuses this one
	} {
		t.Run(fmt.Sprintf("%q for %s", tc.hostport, tc.scheme), func(t *testing.T) {
			h, err := Parse(tc.hostport, tc.scheme)
			if err != tc.err { //nolint:errorlint // the fixed reason itself, never one wrapping or quoting the input (ADR-0031 §1)
				t.Fatalf("Parse error %v; want exactly %v", err, tc.err)
			}
			if err != nil {
				return
			}
			if h.Kind != tc.kind || h.Canonical != tc.canonical || h.Port != tc.port {
				t.Errorf("Parse = kind %v, %q, port %q; want kind %v, %q, port %q", h.Kind, h.Canonical, h.Port, tc.kind, tc.canonical, tc.port)
			}
			// A name has no address; an IP host's address is the one its canonical form names.
			var addr netip.Addr
			if tc.kind != Name {
				addr = netip.MustParseAddr(strings.Trim(tc.canonical, "[]"))
			}
			if h.Addr != addr {
				t.Errorf("Addr = %v; want %v", h.Addr, addr)
			}
			want := tc.canonical
			if tc.port != "" {
				want += ":" + tc.port
			}
			if h.String() != want {
				t.Errorf("String() = %q; want %q", h.String(), want)
			}
		})
	}
}

// A parsed host is loopback by the host a browser reads (127.1 is 127.0.0.1, a full-width localhost
// is localhost), while LoopbackAsWritten takes a name or an IPv4 address only in ASCII and as Parse
// writes it, case aside, and an IPv6 address in any form but without brackets. Both fold localhost's
// case (A1, #482). A redirect URI's loopback set is exact instead (ADR-0032 §5).
func TestLoopbackReadsTheParsedHostButAsWrittenOnlyANameOrIPv4InTheFormParseWrites(t *testing.T) {
	for _, tc := range []struct {
		host              string
		parsed, asWritten bool
	}{
		{"localhost", true, true},
		{"LOCALHOST", true, true},
		{"Localhost", true, true},
		{"127.0.0.1", true, true},
		{"127.0.0.2", true, true},
		// Addresses that are not loopback, whatever their form.
		{"0.0.0.0", false, false},
		{"10.0.0.5", false, false},
		{"2001:db8::1", false, false},
		{"[2001:db8::1]", false, false},
		{"::ffff:10.0.0.1", false, false},
		// Spellings a browser reads as 127.0.0.1, or as localhost, that are not the form Parse writes.
		{"127.1", true, false},
		{"0x7f.0.0.1", true, false},
		{"0177.0.0.1", true, false},
		{"2130706433", true, false},
		{"127.000.000.001", true, false},
		{"ｌｏｃａｌｈｏｓｔ", true, false},
		{"localhoſt", true, false},
		{"local\u00adhost", true, false},
		{"LOCALHOST\u200b", true, false},
		// An IPv6 address counts in any form, but not in brackets.
		{"::1", true, true},
		{"::ffff:127.0.0.1", true, true},
		{"0:0:0:0:0:0:0:1", true, true},
		{"[::1]", true, false}, // as written, a host has no brackets
		// Names that are not localhost, and hosts with a port, a zone or nothing.
		{"localhost.", false, false},
		{"localhost.idp.example", false, false},
		{"evil-localhost", false, false},
		{"localhost:80", true, false}, // as written, a host has no port
		{"localhost:", true, false},
		{"fe80::1%eth0", false, false},
		{"", false, false},
	} {
		t.Run(fmt.Sprintf("%q", tc.host), func(t *testing.T) {
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

// A host name holds only letters, digits, "-", "." and "_" (ADR-0032 §3): BadNameChar
// names the place of the first other character, counted in characters, and none in an IP address.
func TestBadNameCharNamesThePlaceOfTheFirstCharacterNoHostNameHolds(t *testing.T) {
	for name, want := range map[string]int{
		"mcp.example.com": 0, "my_mcp": 0, "a-b.c": 0, "": 0, "MCP.Example": 0,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._": 0, // every one of them
		"127.0.0.1": 0, "::1": 0, "fe80::1%eth0": 0, // an address, and an IPv6 zone's "%"
		"s3cret~tok": 7, "a!b": 2, "a$b": 2, "a&b": 2, "a'b": 2, "a(b": 2, "a)b": 2, "a*b": 2, "a+b": 2,
		"a,b": 2, "a;b": 2, "a=b": 2, "a%b": 2, `a"b`: 2, "a<b": 2, "a b": 2, "a/b": 2,
		"bü~x": 2, "ü": 1, // a non-ASCII character is itself the first one no host name holds
		"bx~ü": 3, // ASCII before it
	} {
		if got := BadNameChar(name); got != want {
			t.Errorf("BadNameChar(%q) = %d, want %d", name, got, want)
		}
	}
}

// DefaultPort is the port browsers drop from a URL of each special scheme, and none for others.
func TestDefaultPortIsTheOneBrowsersDrop(t *testing.T) {
	for scheme, want := range map[string]string{"https": "443", "http": "80", "wss": "443", "ws": "80", "ftp": "21", "file": "", "": ""} {
		if got := DefaultPort(scheme); got != want {
			t.Errorf("DefaultPort(%q) = %q, want %q", scheme, got, want)
		}
	}
}

// ReadsOctal says whether a browser reads a part of an IPv4 host with a leading 0 as octal, and not
// a 0x or 0X prefix or a lone 0.
func TestReadsOctalIsALeadingZeroThatIsNoHexPrefix(t *testing.T) {
	for h, want := range map[string]bool{
		"010.0.0.1": true, "10.010.0.1": true, "00.0.0.1": true, "0.0.0.010": true,
		"10.0.0.1": false, "0.0.0.0": false, "0x7f.0.0.1": false, "0X7F.0.0.1": false, "127.1": false, "0x.0.0.1": false,
	} {
		if got := ReadsOctal(h); got != want {
			t.Errorf("ReadsOctal(%q) = %v, want %v", h, got, want)
		}
	}
}

// A name has an empty label when it starts or ends with a dot or holds two in a row; a host name
// never does (a trailing dot names the root, a different host to a browser, WHATWG URL §3.1).
func TestHasEmptyLabelIsALeadingDoubleOrTrailingDot(t *testing.T) {
	for name, want := range map[string]bool{
		".a.example": true, "a..example": true, "a.example.": true, ".": true, "..": true,
		"a.example": false, "a": false, "": false, "127.0.0.1": false,
	} {
		if got := HasEmptyLabel(name); got != want {
			t.Errorf("HasEmptyLabel(%q) = %v, want %v", name, got, want)
		}
	}
}

// A host name's labels never start or end with a hyphen (RFC 952, RFC 1123 §2.1).
func TestHasEdgeHyphenIsALeadingOrTrailingHyphenInAnyLabel(t *testing.T) {
	for name, want := range map[string]bool{
		"-": true, "-a.example": true, "a-.example": true, "a.-b.example": true, "a.b-": true,
		"a-b.example": false, "xn--bcher-kva.example": false, "a": false, "": false,
	} {
		if got := HasEdgeHyphen(name); got != want {
			t.Errorf("HasEdgeHyphen(%q) = %v, want %v", name, got, want)
		}
	}
}

// MatchKey is a Host header as the Host check compares it with an allowed host: as Canonical writes
// it, without one default port, trimmed once; nothing else is folded.
func TestMatchKeyFoldsCaseAddressSpellingAndOneDefaultPortAndNothingElse(t *testing.T) {
	for given, want := range map[string]string{
		"MCP.example:80": "mcp.example", "127.1:443": "127.0.0.1", "[0:0::1]:443": "[::1]", "::1": "[::1]",
		"[::1]:80:443": "[::1]:80", "mcp.example:8443": "mcp.example:8443",
		"x:0443": "x:0443", "x:": "x:", "ｘ": "ｘ", "x.": "x.",
	} {
		if got := MatchKey(given); got != want {
			t.Errorf("MatchKey(%q) = %q, want %q", given, got, want)
		}
	}
}

// Origin is an origin as the Origin check compares it (ADR-0032 A3): Canonical's host and port without
// the scheme's own default port only.
func TestOriginIsTheCanonicalHostWithoutTheSchemesOwnDefaultPortOnly(t *testing.T) {
	for _, tc := range []struct{ scheme, hostport, want string }{
		{"https", "APP.example:443", "https://app.example"},
		{"https", "127.1", "https://127.0.0.1"},
		{"https", "[0:0::1]:443", "https://[::1]"},
		{"http", "plain.example:80", "http://plain.example"},
		{"https", "app.example:80", "https://app.example:80"},
		{"http", "plain.example:443", "http://plain.example:443"},
		{"https", "app.example:0443", "https://app.example:0443"},
	} {
		if got := Origin(tc.scheme, tc.hostport); got != tc.want {
			t.Errorf("Origin(%q, %q) = %q, want %q", tc.scheme, tc.hostport, got, tc.want)
		}
	}
}

// A host[:port] with a stray bracket, one that is not a leading pair around an IPv6 address, is no
// host a browser sends: Canonical lower-cases it whole, as it does a malformed [IPv6], and reads
// no address in it (#644). These are the 24 of 15,081 probe inputs where main's looser copy of the bracket rule
// read the part before the first ":" instead; no decision on them changed (origin's
// TestAHostOrOriginWithAStrayBracketIsRefusedByEveryCheck).
var strayBracketHosts = map[string]string{
	"127.1:443]":           "127.1:443]",
	"127.1:8080]":          "127.1:8080]",
	"2130706433:8080]":     "2130706433:8080]",
	"0x7f.0.0.1:8080]":     "0x7f.0.0.1:8080]",
	"0177.0.0.1:8080]":     "0177.0.0.1:8080]",
	"127.1:9090]":          "127.1:9090]",
	"HTTPS://APP.EXAMPLE]": "https://app.example]",
	"https://APP.Example]": "https://app.example]",
	"https://APP.example]": "https://app.example]",
	"Origin %q: got %d, Access-Control-Allow-Origin %q; want it echoed as sent]":       "origin %q: got %d, access-control-allow-origin %q; want it echoed as sent]",
	"BYWARD_PUBLIC_URL=https://MCP.Example.com/mcp]":                                   "byward_public_url=https://mcp.example.com/mcp]",
	"BYWARD_PUBLIC_URL=https://b%C3%BCcher.example/mcp]":                               "byward_public_url=https://b%c3%bccher.example/mcp]",
	"BYWARD_ALLOWED_ORIGINS=https://192.168.0.0xFF]":                                   "byward_allowed_origins=https://192.168.0.0xff]",
	"(12 CHARACTERS, NOT SHOWN): IT HAS A \"[\" IN ITS HOST WITHOUT ITS \"]\"":         "(12 characters, not shown): it has a \"[\" in its host without its \"]\"",
	"(18 characters, not shown): it has a control character, which a URL cannot hold]": "(18 characters, not shown): it has a control character, which a url cannot hold]",
	"(10 characters, not shown): it is not an IPv6 address without a zone; ]":          "(10 characters, not shown): it is not an ipv6 address without a zone; ]",
	"(19 characters, not shown): it is not an IPv6 address without a zone; ]":          "(19 characters, not shown): it is not an ipv6 address without a zone; ]",
	"(12 characters, not shown): it is not an IPv6 address without a zone; ]":          "(12 characters, not shown): it is not an ipv6 address without a zone; ]",
	"(5 characters, not shown): it is not an IPv6 address without a zone; ]":           "(5 characters, not shown): it is not an ipv6 address without a zone; ]",
	"HTTPS://XN--BCHER-KVA.example]":                                                   "https://xn--bcher-kva.example]",
	"without dev: want error pointing at the _FILE variable, got %v]":                  "without dev: want error pointing at the _file variable, got %v]",
	" (14 characters, not shown): it is neither a CIDR nor an IP address]":             " (14 characters, not shown): it is neither a cidr nor an ip address]",
	" (8 characters, not shown): its address, before the \"/\", is not an IP address]": " (8 characters, not shown): its address, before the \"/\", is not an ip address]",
	"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read]":                         "byward_obo_scopes=https://graph.microsoft.com/user.read]",
}

func TestCanonicalLowerCasesAHostWithAStrayBracketWhole(t *testing.T) {
	for in, want := range strayBracketHosts {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasZoneFindsAZoneOnlyInAnIPv6Address(t *testing.T) {
	for h, want := range map[string]bool{
		"fe80::1%eth0": true, "FE80::1%25": true,
		"::1": false, "a%b": false, "a%25b": false, "127.0.0.1": false, "mcp.example.com": false, "[fe80::1%eth0]": false, "": false,
	} {
		if got := HasZone(h); got != want {
			t.Errorf("HasZone(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestParseIPv6TakesAnIPv6AddressWithoutAZoneOnly(t *testing.T) {
	for h, want := range map[string]bool{
		"::1": true, "FE80::1": true, "::ffff:127.0.0.1": true,
		"fe80::1%eth0": false, "127.0.0.1": false, "mcp.example.com": false, "[::1]": false, "": false,
	} {
		if _, ok := ParseIPv6(h); ok != want {
			t.Errorf("ParseIPv6(%q) ok = %v, want %v", h, ok, want)
		}
	}
}

// Split is the one bracket rule (#644): brackets come first and enclose a host with a ":", then nothing
// or a ":" and whatever follows; the port comes back as written, with its colon, so a colon with no
// port after it is told from none. A bare IPv6 address is taken whole. It reads neither the address
// nor the port, which its callers judge.
func TestSplitCutsAHostPortByTheOneBracketRule(t *testing.T) {
	for _, tc := range []struct {
		in, host, port string
		err            error
	}{
		{"mcp.example.com", "mcp.example.com", "", nil},
		{"mcp.example.com:443", "mcp.example.com", ":443", nil},
		{"mcp.example.com:", "mcp.example.com", ":", nil},
		{":80", "", ":80", nil},
		{"[::1]", "::1", "", nil},
		{"[::1]:8080", "::1", ":8080", nil},
		{"[::1]:", "::1", ":", nil},
		{"[fe80::1%eth0]:80", "fe80::1%eth0", ":80", nil},
		{"::1", "::1", "", nil},
		{"2001:db8::1", "2001:db8::1", "", nil},
		{"[not an address:]", "not an address:", "", nil}, // brackets around something with a ":": its callers judge it
		{"[::1]:80]", "::1", ":80]", nil},                 // the port is not read: its callers judge it
		{"[a:[b]", "a:[b", "", nil},                       // a second "[" inside is the host's: its callers judge it
		{"[127.0.0.1]", "", "", ErrBrackets},
		{"[::1]x", "", "", ErrBrackets},
		{"[::1", "", "", ErrBrackets},
		{"::1]", "", "", ErrBrackets},
		{"a[b", "", "", ErrBrackets},
		{"127.1:443]", "", "", ErrBrackets},
	} {
		h, port, err := Split(tc.in)
		if h != tc.host || port != tc.port || !errors.Is(err, tc.err) {
			t.Errorf("Split(%q) = %q, %q, %v; want %q, %q, %v", tc.in, h, port, err, tc.host, tc.port, tc.err)
		}
	}
}
