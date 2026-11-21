package host

import "testing"

// Canonical writes a host[:port] as browsers do, whichever spelling it was given in. The
// expected values are what Node 25.1.0's WHATWG URL parser gives for http://<host>/ (checked
// 2026-11-17); a host it refuses (marked) keeps its spelling, in lower case, since no browser sends it.
func TestCanonicalWritesAnAddressAsBrowsersDoAndAnyOtherHostInLowerCase(t *testing.T) {
	for given, want := range map[string]string{
		"10.1":                       "10.0.0.1",
		"0x0a.0.0.1":                 "10.0.0.1",
		"010.0.0.1":                  "8.0.0.1",
		"0X10.1":                     "16.0.0.1",
		"0":                          "0.0.0.0",
		"0x":                         "0.0.0.0",
		"1.":                         "0.0.0.1",
		"10.0.0.1.":                  "10.0.0.1",
		"1.256":                      "1.0.1.0",
		"1.16777215":                 "1.255.255.255",
		"1.16777216":                 "1.16777216", // refused: the last of two numbers fills 3 bytes
		"1.0x":                       "1.0.0.0",
		"0x7f000001":                 "127.0.0.1",
		"017700000001":               "127.0.0.1",
		"4294967295":                 "255.255.255.255",
		"0xffffffff":                 "255.255.255.255",
		"127.1:8080":                 "127.0.0.1:8080",
		"4294967296":                 "4294967296",                 // refused: too large
		"256.0.0.1":                  "256.0.0.1",                  // refused
		"1.2.65536":                  "1.2.65536",                  // refused
		"09":                         "09",                         // refused: not octal
		"1..2":                       "1..2",                       // refused
		"a.0X0123456789abcdefABCDEF": "a.0x0123456789abcdefabcdef", // refused: a is not a number
		"mcp.10":                     "mcp.10",                     // refused: mcp is not a number
		"0x0g":                       "0x0g",                       // a name
		"[FE80::1%25ETH0]:80":        "[fe80::1%25eth0]:80",        // refused: a zone, which no URL carries
		"[::FFFF:1.2.3.4]:8080":      "[::ffff:102:304]:8080",      // a mapped address whose byte 14 is not 0
		"FE80::1%ETH0":               "fe80::1%eth0",               // refused: a bare IPv6 address, with a zone
		"0x10000000000000000":        "0x10000000000000000",        // refused: too large, never 0.0.0.0
		"18446744073709551616":       "18446744073709551616",       // refused: too large, never 0.0.0.0
		"1.2.3.4.0":                  "1.2.3.4.0",                  // refused: five numbers (the last, 0, is in range)
		"[127.0.0.1]":                "[127.0.0.1]",                // refused: IPv4 in brackets
		"[FE80::1]X":                 "[fe80::1]x",                 // refused: text after the brackets
		"255.1":                      "255.0.0.1",
		"Mcp.Example":                "mcp.example",
		"[2001:DB8:0:0::1]":          "[2001:db8::1]",
		"[2001:DB8:0:0::1]:8443":     "[2001:db8::1]:8443",
		"[::FFFF:127.0.0.1]":         "[::ffff:7f00:1]",
		"[1:0:0:0:2:0:0:3]":          "[1::2:0:0:3]",
		"[::1.2.3.4]":                "[::102:304]",
		"2001:db8::1":                "[2001:db8::1]", // a bare IPv6 address, a Host header form no URL carries: bracketed
		"[X]":                        "[x]",           // refused
	} {
		if got := Canonical(given); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", given, got, want)
		}
	}
}

// Hostname reduces a host[:port], a bracketed IPv6 address included, to its lower-case host name
// (#319).
func TestHostnameReducesAHostPortToItsLowerCaseHostName(t *testing.T) {
	for hostport, want := range map[string]string{
		"mcp.example.com":      "mcp.example.com",
		"mcp.example.com:8443": "mcp.example.com",
		"MCP.Example.COM:8443": "mcp.example.com",
		"[::1]":                "::1",
		"[::1]:8443":           "::1",
		"::1":                  "::1",
		"[FE80::1]:8443":       "fe80::1",
		"127.0.0.1:8080":       "127.0.0.1",
		"localhost":            "localhost",
	} {
		if got := Hostname(hostport); got != want {
			t.Errorf("Hostname(%q) = %q, want %q", hostport, got, want)
		}
	}
}
