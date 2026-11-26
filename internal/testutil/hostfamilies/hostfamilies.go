// Package hostfamilies generates the host inputs that every check reading a host is judged on, and
// records each check's decisions (#656). Each package that owns a host check runs its columns with
// Run, which writes a summary golden (testdata/hostdecisions.golden) and fails when an input passes
// a check without being in the hand-edited baseline (testdata/hostdecisions.allowed), or is in the
// baseline without passing. Regeneration rewrites the summary only, never the baseline, so a
// widening is a reviewed edit to the baseline and a narrowing a reviewed deletion from it.
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

// Columns are the checks that read a host, by the package whose test runs them. Run fails a package
// whose columns differ from its entry, and TestEveryColumnIsInItsPackagesGolden fails an entry whose
// golden lacks it. A new check that reads a host gets a column here and in its package's test.
var Columns = map[string][]string{
	"internal/config": {
		"public-url", "upstream-url", "resource-documentation", "oidc-issuer", "allowed-origins",
		"allowed-hosts", "cimd-trusted-hosts", "cimd-allowed-hosts", "client-denylist host", "client-denylist client ID",
		"listen", "internal-listen",
	},
	"internal/origin":       {"public Host", "internal Host", "Origin"},
	"internal/registration": {"CIMD client ID", "CIMD allowed host", "denylist entry", "denylist client ID", "denylist redirect"},
	"internal/idp/oidc":     {"IdP endpoint", "IdP endpoint, --dev"},
}

// A Probe is one input and the families it belongs to: what the host is, how it is wrapped, and the
// port after it, or, for a URL shape, what else the URL holds.
type Probe struct {
	Family, Wrap, Port string
	Input              string
}

// hostBases are the hosts the families start from. Each family has members a check takes and
// members it refuses, wherever the check takes any.
var hostBases = []struct {
	family string
	hosts  []string
}{
	{"name", []string{"mcp.example.com", "MCP.Example.COM", "app.example", "evil.example", "localhost", "LOCALHOST", "byward-metrics.monitoring.svc", "my_mcp", "single"}},
	{"name edge", []string{"mcp.example.com.", "a..b", ".mcp.example.com", "-a.example", "a-.example", "mcp.10", "10.0.0.999", "a b.example", "a%41.example", "S3CRET~tok", "*", ""}},
	{"idn", []string{"xn--bcher-kva.example", "bücher.example", "ｍｃｐ.example.com", "b%C3%BCcher.example"}},
	{"ipv4", []string{"127.0.0.1", "127.0.0.2", "10.244.1.17", "0.0.0.0", "8.8.8.8"}},
	{"ipv4 spelling", []string{"127.1", "0x7f.0.0.1", "0177.0.0.1", "2130706433", "010.0.0.1", "127.0.0.1.5", "4294967296"}},
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

// urlShapes are what a URL holds besides its host: case in the scheme, a user name, a password, a
// query, a fragment, a path or none, an empty host before a port, a missing "//", and a zoned host
// with each of them (a URL writes a zone as %25).
var urlShapes = []struct{ name, url string }{
	{"scheme in upper case", "HTTPS://mcp.example.com"},
	{"user", "https://u@mcp.example.com"},
	{"user and password", "https://u:pw@mcp.example.com"},
	{"empty user info", "https://@mcp.example.com"},
	{"query", "https://mcp.example.com?x=1"},
	{"empty query", "https://mcp.example.com?"},
	{"fragment", "https://mcp.example.com#f"},
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
// it does not, a reason class that never holds the input.
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
// both in the package's directory. pkg is the package's directory from the repository root, as
// Columns names it.
func Run(t *testing.T, pkg string, cols []Column) {
	t.Helper()
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	if !slices.Equal(names, Columns[pkg]) {
		t.Fatalf("%s runs the columns %q; hostfamilies.Columns lists %q for it: list every check that reads a host in both", pkg, names, Columns[pkg])
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "# The decision of every check in %s that reads a host, by input family (#656).\n", pkg)
	summary.WriteString("# Generated: BYWARD_UPDATE_GOLDEN=1 rewrites it. The inputs that pass are listed in hostdecisions.allowed,\n")
	summary.WriteString("# which is edited by hand; a denylist's lines there are the inputs it stops. The refusal messages per\n")
	summary.WriteString("# setting are in internal/config/testdata/hostrule.golden.\n")
	listed := map[string]bool{} // a baseline line, and whether its column is a denylist
	denies := map[string]bool{}
	for _, c := range cols {
		denies[c.Name] = c.Denies
		decisions := make([]decision, 0, len(c.Probes))
		for _, p := range c.Probes {
			pass, reason := c.Judge(p.Input)
			if pass {
				reason = ""
			}
			if pass != c.Denies {
				listed[line(c.Name, p.Input)] = true
			}
			decisions = append(decisions, decision{p, pass, reason})
		}
		writeColumn(&summary, c.Name, decisions)
	}
	golden.Check(t, "testdata/hostdecisions.golden", summary.String(), "the file summarises each host check's decisions (#656); a changed count is a decision that changed, which hostdecisions.allowed must show too")
	checkBaseline(t, listed, denies)
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
// has that the checks no longer give, naming whether that widens or narrows the check; and each
// residual that is not a line the checks give.
func checkBaseline(t *testing.T, passing, denies map[string]bool) {
	t.Helper()
	allowed, err := readLines("testdata/hostdecisions.allowed")
	if err != nil {
		t.Fatalf("read the allowed baseline: %v", err)
	}
	listed := map[string]bool{}
	for _, l := range allowed {
		listed[l] = true
	}
	var newly, gone []string
	for l := range passing {
		if !listed[l] {
			newly = append(newly, l)
		}
	}
	for l := range listed {
		if !passing[l] {
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
		t.Errorf("%s: %s: in testdata/hostdecisions.allowed; if intended, delete the line (and its residual, if any) and say why in the PR", what, l)
	}
	residuals, err := readLines("testdata/hostdecisions.residuals")
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("read the residuals: %v", err)
	}
	for _, r := range residuals {
		f := strings.SplitN(r, "\t", 4)
		if len(f) != 4 || !strings.HasPrefix(f[2], "#") {
			t.Errorf("residual %q: want column, tab, quoted input, tab, #issue, tab, why", r)
			continue
		}
		if l := f[0] + "\t" + f[1]; !passing[l] {
			t.Errorf("residual %s (%s) no longer passes: if %s fixed it, delete it here and in hostdecisions.allowed", l, f[2], f[2])
		}
	}
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

var (
	lengthNote = regexp.MustCompile(`\(\d+ characters?, not shown\)`)
	entryNote  = regexp.MustCompile(`entry \d+ of \d+`)
	position   = regexp.MustCompile(`at position \d+`)
)

// Reason is a refusal's message as a reason class: its value's length, its entry's place and a
// character's position replaced, so that refusals for one reason count as one class.
func Reason(msg string) string {
	msg = lengthNote.ReplaceAllString(msg, "(N characters, not shown)")
	msg = entryNote.ReplaceAllString(msg, "entry N of N")
	return position.ReplaceAllString(msg, "at position N")
}
