// Package hostfamilies generates the host inputs that the checks deciding on a host name or a
// host[:port] are judged on, and records each check's decisions (#656). Each package that owns such a
// check runs its columns with Run, which writes a summary golden (testdata/hostdecisions.golden) and
// fails when the inputs a check passes (for a denylist, the inputs it stops) differ from the
// hand-edited baseline (testdata/hostdecisions.allowed). Regeneration rewrites the summary only, never
// the baseline, so a widening is a reviewed edit to the baseline and a narrowing a reviewed deletion.
// Not covered: the trusted proxies and X-Forwarded-For, which take IP addresses and prefixes (netip);
// the class X identifiers no column judges, such as an assertion's aud, compared byte for byte; the access
// gate's email and hosted domains, which compare an identity claim, not a host the proxy reads; and
// the consent page's display of a client's site and its other-site warning. The package imports no
// production package, so a package it judges (internal/host among them) can use it in its own tests.
package hostfamilies

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/golden"
)

// columns are the checks that read a host, by the package whose test runs them. Run fails a package
// whose columns differ from its entry, and TestEveryListedPackageRunsAndRecordsItsColumns fails an
// entry no test of its package runs, or whose golden lacks a column. Nothing finds a new check that
// reads a host by itself: it gets a column here and in its package's Run call.
var columns = map[string][]string{
	"internal/config": {
		"public-url", "upstream-url", "resource-documentation", "oidc-issuer", "allowed-origins",
		"allowed-hosts", "cimd-trusted-hosts", "cimd-allowed-hosts", "client-denylist host", "client-denylist client ID",
		"listen", "internal-listen", "no-auth public-url", "no-auth listen", "no-auth allowed-hosts", "no-auth allowed-origins",
	},
	"internal/broker":       {"consent Origin"},
	"internal/origin":       {"public Host", "internal Host", "Origin"},
	"internal/registration": {"CIMD client ID", "CIMD allowed host", "CIMD trusted host", "denylist entry", "denylist client ID", "denylist redirect", "redirect URI", "loopback redirect"},
	"internal/idp/oidc":     {"IdP endpoint", "IdP endpoint, --dev", "IdP endpoint, loopback issuer without --dev"},
	"internal/ssrfguard":    {"SSRF guard URL"},
	"internal/host":         {"loopback as written"},
}

// A Probe is one input and the families it belongs to: what the host is, how it is wrapped (for a URL
// shape, the shape), and the port after it ("-" for a URL shape).
type Probe struct {
	Family, Wrap, Port string
	Input              string
}

// hostBases are the hosts the families start from. Each family is meant to hold forms a host check
// could take and forms it should refuse; each column's summary shows which it does.
var hostBases = []struct {
	family string
	hosts  []string
}{
	{"name", []string{"mcp.example.com", "MCP.Example.COM", "app.example", "evil.example", "localhost", "LOCALHOST", "byward-metrics.monitoring.svc", "my_mcp", "single"}},
	{"name edge", []string{"mcp.example.com.", "a..b", ".mcp.example.com", "-a.example", "a-.example", "mcp.10", "app.0x", "10.0.0.999", "localhost.", "*.example.com", "u@mcp.example.com", "a?b.example", "a b.example", "a%41.example", "S3CRET~tok", "*", ""}},
	{"idn", []string{"xn--bcher-kva.example", "bücher.example", "ｍｃｐ.example.com", "b%C3%BCcher.example", "faß.example", "faẞ.example"}},
	{"ipv4", []string{"127.0.0.1", "127.0.0.2", "10.244.1.17", "0.0.0.0", "8.8.8.8"}},
	{"ipv4 spelling", []string{"127.0.0.1.", "127.1", "0x7f.0.0.1", "0177.0.0.1", "2130706433", "010.0.0.1", "127.0.0.1.5", "4294967296"}},
	{"ipv6", []string{"::1", "0:0::1", "2001:DB8::1", "2001:db8::1", "fd00::17", "fe80::1", "::"}},
	{"ipv4-mapped", []string{"::ffff:127.0.0.1", "::FFFF:7f00:1", "::ffff:8.8.8.8"}},
	{"zone", []string{"fe80::1%eth0", "fe80::1%25eth0", "fe80::1%", "fe80::1%25", "::1%lo0", "fe80::1%eth0]", "fe80::1%eth0:-1"}},
}

// wraps place a host in a host[:port]: bare, in brackets, and the bracket forms no client writes.
var wraps = []struct {
	name string
	wrap func(string) string
}{
	{"bare", func(h string) string { return h }},
	{"[h]", func(h string) string { return "[" + h + "]" }},
	{"[h", func(h string) string { return "[" + h }},
	{"h]", func(h string) string { return h + "]" }},
	{"[h]]", func(h string) string { return "[" + h + "]]" }},
	{"[h]x", func(h string) string { return "[" + h + "]x" }},
}

// ports are what follows a host: none, a colon alone, ports in and out of range, and the spellings
// no client writes (a sign, leading zeros, hex, full-width digits, a second port, a stray bracket).
var ports = []string{
	"", ":", ":443", ":80", ":8080", ":9090", ":65535", ":0", ":65536", ":123456", ":080", ":+80", ":-1",
	":0x50", ":8a", ":８０", ":80:80", ":80]",
}

// HostProbes are every host family, wrapped every way, with every port: the inputs a check that
// reads a host[:port] or a host header is judged on, in a fixed order, each input once.
func HostProbes() []Probe {
	seen := map[string]bool{}
	var out []Probe
	for _, b := range hostBases {
		for _, h := range b.hosts {
			for _, w := range wraps {
				for _, p := range ports {
					in := w.wrap(h) + p
					if seen[in] {
						continue
					}
					seen[in] = true
					out = append(out, Probe{Family: b.family, Wrap: w.name, Port: portName(p), Input: in})
				}
			}
		}
	}
	return out
}

// portName is a port's family name: "none" for no port, the port as written otherwise.
func portName(p string) string {
	if p == "" {
		return "none"
	}
	return p
}

// urlShapes are what a URL holds besides its host: case in the scheme, user information, a query, a
// fragment (empty or not), a trailing slash, an empty host before a port, a missing or single "/", another scheme or none, an escaped
// bracket, white space, a backslash, a zoned host (a URL writes a zone as %25) with a user, a query
// or a port, and a path that looks like a zone.
var urlShapes = []struct{ name, url string }{
	{"scheme in upper case", "HTTPS://mcp.example.com"},
	{"user", "https://u@mcp.example.com"},
	{"user and password", "https://u:pw@mcp.example.com"},
	{"empty user info", "https://@mcp.example.com"},
	{"query", "https://mcp.example.com?x=1"},
	{"empty query", "https://mcp.example.com?"},
	{"fragment", "https://mcp.example.com#f"},
	{"empty fragment", "https://mcp.example.com#"},
	{"trailing slash", "https://mcp.example.com/"},
	{"no host before a port", "https://:443"},
	{"no //", "https:mcp.example.com"},
	{"one /", "https:/mcp.example.com"},
	{"another scheme", "ftp://mcp.example.com"},
	{"no scheme", "mcp.example.com"},
	{"zone and user", "https://u@[fe80::1%25eth0]"},
	{"zone and query", "https://[fe80::1%25eth0]?x"},
	{"zone and port", "https://[fe80::1%25eth0]:443"},
	{"zone in a path", "https://mcp.example.com/%25eth0"},
	{"escaped bracket", "https://%5B::1%5D"},
	{"white space", "https://mcp.example.com /x"},
	{"backslash", "https:\\\\mcp.example.com"},
}

// URLProbes are every host probe as scheme://host[:port] plus path for each scheme, then every URL
// shape once, with path appended (path "" for an origin), each input once. A URL shape's scheme is
// its own.
func URLProbes(path string, schemes ...string) []Probe {
	seen := map[string]bool{}
	var out []Probe
	add := func(p Probe) {
		if !seen[p.Input] {
			seen[p.Input] = true
			out = append(out, p)
		}
	}
	for _, scheme := range schemes {
		for _, p := range HostProbes() {
			p.Input = scheme + "://" + p.Input + path
			add(p)
		}
	}
	for _, s := range urlShapes {
		add(Probe{Family: "url shape", Wrap: s.name, Port: "-", Input: s.url + path})
	}
	return out
}

// Only is the probes of the named families, for a check that judges only those and leaves the rest
// to another check, whose column judges them.
func Only(probes []Probe, families ...string) []Probe {
	var out []Probe
	for _, p := range probes {
		if slices.Contains(families, p.Family) {
			out = append(out, p)
		}
	}
	return out
}

// A Column is one check: its name, its inputs, and its judgement of one input: whether the input
// passes the check (is accepted, allowed, or not denied: what a widening would add to), and, when
// it does not, a reason class that never holds the input. A Judge may also assert what its check
// does beside deciding, such as what it audits, since it sees each input once.
type Column struct {
	Name   string
	Probes []Probe
	Judge  func(input string) (pass bool, reason string)
	// Denies marks a denylist, whose baseline lists the inputs it stops: a denylist widens by
	// stopping fewer, so the input it no longer stops is the one that fails.
	Denies bool
}

// Run judges every input of every column, checks the summary against testdata/hostdecisions.golden,
// and the inputs that pass against testdata/hostdecisions.allowed and testdata/hostdecisions.residuals,
// both in the package's directory. A package calls it once, from one test, with every column its
// entry in columns lists; pkg is the package's directory from the repository root.
func Run(t testing.TB, pkg string, cols []Column) {
	t.Helper()
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	if len(columns[pkg]) == 0 || !slices.Equal(names, columns[pkg]) {
		t.Fatalf("%s runs the columns %q; hostfamilies lists %q for it: list every check that reads a host in both", pkg, names, columns[pkg])
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "# The decision of each check in %s that decides on a host, by input family (#656).\n", pkg)
	summary.WriteString("# Generated: BYWARD_UPDATE_GOLDEN=1 rewrites it. The inputs that pass are listed in hostdecisions.allowed,\n")
	summary.WriteString("# which is edited by hand; a denylist's lines there are the inputs it stops. A Go version that reads\n")
	summary.WriteString("# a URL or an address differently changes these lines: that is a decision change too.\n")
	given := map[string]bool{}  // the baseline lines the checks give: what each passes, or a denylist stops
	passes := map[string]bool{} // the lines of the inputs each check lets through, a denylist included
	denies := map[string]bool{} // whether a column is a denylist
	for _, c := range cols {
		denies[c.Name] = c.Denies
		decisions := make([]decision, 0, len(c.Probes))
		for _, p := range c.Probes {
			pass, reason := c.Judge(p.Input)
			if pass {
				reason = ""
			}
			if pass != c.Denies {
				given[line(c.Name, p.Input)] = true
			}
			if pass {
				passes[line(c.Name, p.Input)] = true
			}
			decisions = append(decisions, decision{p, pass, reason})
		}
		writeColumn(&summary, c.Name, decisions)
	}
	golden.Check(t, "testdata/hostdecisions.golden", summary.String(), "the file summarises each host check's decisions (#656); a changed count is a decision that changed, which hostdecisions.allowed must show too")
	checkBaseline(t, given, denies)
	checkResiduals(t, passes)
}

type decision struct {
	Probe
	pass   bool
	reason string
}

// line is an input's line in the baseline: its column, a tab, and the input quoted as Go quotes it.
func line(column, input string) string { return column + "\t" + strconv.Quote(input) }

// writeColumn writes one column's summary: its totals, its pass and refuse counts by family, wrap
// and port, and the count of each refusal reason.
func writeColumn(b *strings.Builder, name string, ds []decision) {
	pass := 0
	for _, d := range ds {
		if d.pass {
			pass++
		}
	}
	fmt.Fprintf(b, "\n## %s: %d pass, %d refused, of %d\n", name, pass, len(ds)-pass, len(ds))
	for _, by := range []struct {
		name string
		key  func(decision) string
	}{
		{"family", func(d decision) string { return d.Family }},
		{"wrap", func(d decision) string { return d.Wrap }},
		{"port", func(d decision) string { return d.Port }},
	} {
		fmt.Fprintf(b, "by %s:\n", by.name)
		var order []string
		counts := map[string]*[2]int{}
		for _, d := range ds {
			k := by.key(d)
			if counts[k] == nil {
				counts[k] = &[2]int{}
				order = append(order, k)
			}
			if d.pass {
				counts[k][0]++
			} else {
				counts[k][1]++
			}
		}
		for _, k := range order {
			fmt.Fprintf(b, "  %-24s pass %5d  refused %5d\n", k, counts[k][0], counts[k][1])
		}
	}
	reasons := map[string]int{}
	for _, d := range ds {
		if !d.pass {
			reasons[d.reason]++
		}
	}
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] != reasons[keys[j]] {
			return reasons[keys[i]] > reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	b.WriteString("refused because:\n")
	for _, k := range keys {
		fmt.Fprintf(b, "  %5d  %s\n", reasons[k], k)
	}
}

// checkBaseline fails each line the checks give that hostdecisions.allowed lacks, and each line it
// has that the checks no longer give, naming whether that widens or narrows the check.
func checkBaseline(t testing.TB, given, denies map[string]bool) {
	t.Helper()
	allowed, err := readLines("testdata/hostdecisions.allowed")
	if err != nil {
		t.Fatalf("read the allowed baseline: %v", err)
	}
	listed := map[string]bool{}
	for _, l := range allowed {
		if _, ok := parseLine(t, "hostdecisions.allowed", l, 2); ok {
			if listed[l] {
				t.Errorf("hostdecisions.allowed lists %s twice: delete one", l)
			}
			listed[l] = true
		}
	}
	var newly, gone []string
	for l := range given {
		if !listed[l] {
			newly = append(newly, l)
		}
	}
	for l := range listed {
		if !given[l] {
			gone = append(gone, l)
		}
	}
	sort.Strings(newly)
	sort.Strings(gone)
	column := func(l string) string { c, _, _ := strings.Cut(l, "\t"); return c }
	for _, l := range newly {
		what := "newly allowed (a widening)"
		if denies[column(l)] {
			what = "newly denied (a narrowing)"
		}
		t.Errorf("%s: %s: not in testdata/hostdecisions.allowed; if intended, add the line by hand and say why in the PR", what, l)
	}
	for _, l := range gone {
		what := "no longer allowed (a narrowing)"
		if denies[column(l)] {
			what = "no longer denied (a widening)"
		}
		t.Errorf("%s: %s: in testdata/hostdecisions.allowed; if intended, delete the line from hostdecisions.allowed (and its residual, if any) and say why in the PR", what, l)
	}
}

// checkResiduals fails each line of hostdecisions.residuals that is malformed, listed twice, or
// names an input its check no longer lets through: its issue has fixed it, and the line is deleted
// there and from hostdecisions.allowed (for a denylist, the fix adds the input there instead).
func checkResiduals(t testing.TB, passes map[string]bool) {
	t.Helper()
	residuals, err := readLines("testdata/hostdecisions.residuals")
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("read the residuals: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range residuals {
		f, ok := parseLine(t, "hostdecisions.residuals", r, 4)
		if !ok {
			continue
		}
		if !issueRef.MatchString(f[2]) || strings.TrimSpace(f[3]) == "" {
			t.Errorf("hostdecisions.residuals: %q: want column, tab, quoted input, tab, #issue number, tab, why", r)
			continue
		}
		l := f[0] + "\t" + f[1]
		if seen[l] {
			t.Errorf("hostdecisions.residuals lists %s twice: delete one", l)
		}
		seen[l] = true
		if !passes[l] {
			t.Errorf("residual %s (%s): its check no longer lets it through: if %s fixed it, delete the residual, and update hostdecisions.allowed as the test says", l, f[2], f[2])
		}
	}
}

var issueRef = regexp.MustCompile(`^#\d+$`)

// parseLine splits a baseline or residual line into its n tab-separated fields, and fails it unless
// its input, the second field, is quoted as strconv.Quote quotes it, so that one input has one line.
func parseLine(t testing.TB, file, l string, n int) ([]string, bool) {
	t.Helper()
	f := strings.SplitN(l, "\t", n)
	if len(f) != n {
		t.Errorf("%s: %q: want %d tab-separated fields", file, l, n)
		return nil, false
	}
	if in, err := strconv.Unquote(f[1]); err != nil || strconv.Quote(in) != f[1] {
		t.Errorf("%s: %q: the input must be quoted as strconv.Quote quotes it", file, l)
		return nil, false
	}
	return f, true
}

// readLines is a file's lines, without blank lines and lines that start with "#".
func readLines(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a test's own testdata file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		if l := s.Text(); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, s.Err()
}
