package host

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The web-platform-tests URL suites, pinned in testdata/wpt (see its README): IdnaTestV2.json, WPT's
// form of Unicode's UTS #46 conformance file for 17.0.0, the Unicode version of Go 1.27's IDNA
// tables; toascii.json; and the host of each special-scheme URL in urltestdata.json, kept in
// urltestdata-hosts.json (ADR-0032 §6).

// deviation is a suite case Parse reads differently from a browser, on purpose: why, and what Parse
// reads instead (the host it writes, or the reason it refuses the host).
type deviation struct {
	why  string
	host string
	err  error
}

// deviations are the suite cases Parse reads differently from a browser, by their input.
var deviations = map[string]deviation{
	"http://2001::1":                           {why: "Parse takes a bare IPv6 address whole, as BYWARD_ALLOWED_HOSTS gives one; a URL must bracket it", host: "[2001::1]"},
	"http://%30%78%63%30%2e%30%32%35%30.01":    {why: percentEncoded, err: ErrName},
	"http://%30%78%63%30%2e%30%32%35%30.01%2e": {why: percentEncoded, err: ErrName},
	"ftp://%e2%98%83":                          {why: percentEncoded, err: ErrName},
	"https://%e2%98%83":                        {why: percentEncoded, err: ErrName},
	"https://a%C2%ADb/":                        {why: percentEncoded, err: ErrName},
}

// suiteSizes are the number of cases each suite holds, so a refresh that truncates or reshapes a
// file fails instead of testing less.
var suiteSizes = map[string]int{"IdnaTestV2.json": 2670, "toascii.json": 87, "urltestdata-hosts.json": 284}

// percentEncoded is why Parse refuses a percent-encoded host that the URL parser decodes first: no
// setting or header byward reads carries one (ADR-0032 §3 refuses "%" in a host).
const percentEncoded = "Parse does not percent-decode a host"

// suiteCase is one host to parse for scheme, and the host and port a browser serializes, or failure.
type suiteCase struct {
	name, hostport, scheme, want string
	failure                      bool
}

// hostSuite is a WPT host file (IdnaTestV2.json, toascii.json): each input as an https URL's host,
// and its output, or null for a host the parser refuses. An empty input is skipped, as WPT's harness
// skips it: no URL has an empty special host.
func hostSuite(t *testing.T, file string) []suiteCase {
	t.Helper()
	var cases []suiteCase
	for _, r := range suiteEntries(t, file) {
		var c struct {
			Input  string  `json:"input"`
			Output *string `json:"output"`
		}
		if err := json.Unmarshal(r, &c); err != nil {
			t.Fatalf("%s: an entry that is not a host case: %v", file, err)
		}
		if c.Input == "" {
			continue
		}
		sc := suiteCase{name: c.Input, hostport: c.Input, scheme: "https", failure: c.Output == nil}
		if c.Output != nil {
			sc.want = *c.Output
		}
		cases = append(cases, sc)
	}
	return cases
}

// urlCase is a urltestdata.json entry as urltestdata-hosts.json keeps it: a URL, and the host it
// parses to, or its failure.
type urlCase struct {
	Input   string `json:"input"`
	Host    string `json:"host"`
	Failure bool   `json:"failure,omitempty"`
}

// urlSuite is the host of each URL in urltestdata-hosts.json, with the host it parses to, or its
// failure.
func urlSuite(t *testing.T) []suiteCase {
	t.Helper()
	var cases []suiteCase
	for _, r := range suiteEntries(t, "urltestdata-hosts.json") {
		var c urlCase
		if err := json.Unmarshal(r, &c); err != nil {
			t.Fatal(err)
		}
		scheme, hostport, ok := urlHost(c.Input)
		if !ok {
			t.Fatalf("urltestdata-hosts.json holds %q, whose host cannot be cut out", c.Input)
		}
		cases = append(cases, suiteCase{name: c.Input, hostport: hostport, scheme: scheme, want: c.Host, failure: c.Failure})
	}
	return cases
}

// TestRegenerateTheURLHostSuiteFromURLTestData writes urltestdata-hosts.json from WPT's
// urltestdata.json: the entries whose authority urlHost can cut out, which leaves out every URL with
// userinfo. It checks nothing: it runs only with BYWARD_WPT_URLTESTDATA set to the absolute path of
// a downloaded urltestdata.json (testdata/wpt/README.md).
func TestRegenerateTheURLHostSuiteFromURLTestData(t *testing.T) {
	src := os.Getenv("BYWARD_WPT_URLTESTDATA")
	if src == "" {
		t.Skip("BYWARD_WPT_URLTESTDATA is not set; nothing to regenerate")
	}
	b, err := os.ReadFile(src) //nolint:gosec // G304: the suite file the operator of the test names
	if err != nil {
		t.Fatal(err)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var kept []urlCase
	for _, r := range raw {
		var c urlCase
		if json.Unmarshal(r, &c) != nil {
			continue // a comment
		}
		if _, _, ok := urlHost(c.Input); ok {
			kept = append(kept, c)
		}
	}
	out, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/wpt/urltestdata-hosts.json", append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// suiteEntries are the JSON objects of a suite file; its strings are comments.
func suiteEntries(t *testing.T, file string) []json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("testdata/wpt/" + file) //nolint:gosec // G304: a suite file under testdata/ that the test names
	if err != nil {
		t.Fatal(err)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var objects []json.RawMessage
	for _, r := range raw {
		if len(r) > 0 && r[0] == '{' {
			objects = append(objects, r)
		}
	}
	return objects
}

// urlHost is the scheme and host[:port] of input, a special-scheme URL whose authority can be cut
// out as written: a lower-case scheme and "//", no userinfo, and nothing the URL parser strips or
// rewrites before the host parser runs (whitespace, controls, backslashes).
func urlHost(input string) (scheme, hostport string, ok bool) {
	if strings.ContainsAny(input, "\\ ") || strings.ContainsFunc(input, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", "", false
	}
	for _, s := range []string{"ftp", "http", "https", "ws", "wss"} {
		rest, found := strings.CutPrefix(input, s+"://")
		if !found {
			continue
		}
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		if hostport = rest[:end]; strings.Contains(hostport, "@") {
			return "", "", false
		}
		return s, hostport, true
	}
	return "", "", false
}

// Parse reads each host of the pinned suites as a browser does, but for the deviations listed, each
// with its reason. A new mismatch fails, and so does a listed deviation Parse now reads as a browser.
func TestParseAgreesWithTheWPTHostSuites(t *testing.T) {
	suites := map[string][]suiteCase{
		"IdnaTestV2.json":        hostSuite(t, "IdnaTestV2.json"),
		"toascii.json":           hostSuite(t, "toascii.json"),
		"urltestdata-hosts.json": urlSuite(t),
	}
	deviated := map[string]bool{}
	for file, cases := range suites {
		if len(cases) != suiteSizes[file] {
			t.Errorf("%s: %d cases read, want %d (testdata/wpt/README.md)", file, len(cases), suiteSizes[file])
		}
		for _, c := range cases {
			h, err := Parse(c.hostport, c.scheme)
			agrees := err == nil && !c.failure && h.String() == c.want || err != nil && c.failure
			if d, listed := deviations[c.name]; listed {
				deviated[c.name] = true
				if agrees {
					t.Errorf("%s %q is listed as a deviation, but Parse now reads it as a browser does; drop it from the list", file, c.name)
				}
				if err != d.err || err == nil && h.String() != d.host { //nolint:errorlint // the fixed reason itself
					t.Errorf("%s %q: Parse reads it as %q (error %v); the deviation says %q (error %v)", file, c.name, h.String(), err, d.host, d.err)
				}
				continue
			}
			if !agrees {
				want := c.want
				if c.failure {
					want = "a failure"
				}
				got := "a failure: " + errString(err)
				if err == nil {
					got = h.String()
				}
				t.Errorf("%s %q: Parse reads %q as %s; a browser reads %s", file, c.name, c.hostport, got, want)
			}
		}
	}
	for name := range deviations {
		if !deviated[name] {
			t.Errorf("deviation %q is in no suite", name)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
