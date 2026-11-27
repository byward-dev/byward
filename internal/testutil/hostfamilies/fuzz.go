package hostfamilies

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Fuzz is pkg's fuzz target over the columns that columns builds, the same ones its Run call judges
// (#661). It fuzzes the host[:port] a check reads, seeded with one host probe per family, wrap and
// port, and places the fuzzed host in each column's input as that column's probes place theirs:
// bare, or in a URL with the probes' scheme and path. The URL shapes stay the golden's.
//
// Every column must not panic. An input it passes must pass again with its host as browsers write
// it (split, then serialize, then the port as written). A column marked Lists passes only spellings
// of the hosts on a fixed list, so an input it passes must be a line of testdata/hostdecisions.allowed,
// in any ASCII letter case. A denylist must stop every input that is a line it stops there, in any
// ASCII letter case. The other columns take an open set of hosts, which a list of inputs cannot hold
// (#661's scope), so they get the first two rules only. split and serialize are internal/host's Split
// and Serialize, passed in because this package imports no production package.
func Fuzz(f *testing.F, columns func(testing.TB) []Column, split func(string) (string, string, error), serialize func(string) string) {
	f.Helper()
	placings := map[string][][2]string{}
	for _, c := range columns(f) {
		placings[c.Name] = placing(c.Probes)
	}
	listed := foldedBaseline(f)
	for _, in := range cellSeeds() {
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, h string) {
		for i, c := range columns(t) {
			for _, at := range placings[c.Name] {
				in := at[0] + h + at[1]
				pass, _ := c.Judge(in)
				known := listed[line(c.Name, foldASCII(in))]
				switch {
				case c.Denies && known && pass:
					t.Errorf("%s no longer stops %q, a spelling of an input testdata/hostdecisions.allowed says it stops (a widening)", c.Name, in)
				case c.Lists && pass && !known:
					t.Errorf("%s passes %q, which testdata/hostdecisions.allowed lists in no letter case (a widening): fix the check, or add the form to hostfamilies' families and its line by hand", c.Name, in)
				}
				if !pass || c.Denies {
					continue
				}
				if host, port, err := split(h); err == nil && hasWrittenForm(h, host, at[0] != "") {
					written := at[0] + bracketed(serialize(host)) + port + at[1]
					// A fresh column: a check may remember an input it judged (the CIMD registry caches
					// a fetch), and the form browsers write may be the input itself.
					if again, reason := columns(t)[i].Judge(written); !again {
						t.Errorf("%s passes %q but refuses %q, its host as browsers write it: %s", c.Name, in, written, reason)
					}
				}
			}
		}
	})
}

// hasWrittenForm reports whether h, split into host, has a form browsers write to compare: it is
// valid UTF-8 (Serialize writes U+FFFD for a byte that is not), with no white space at either end
// (a list parser trims it, so the form would not be h's), and, in a URL, an IPv6 address is in
// brackets (without them it is no host a browser reads).
func hasWrittenForm(h, host string, inURL bool) bool {
	return utf8.ValidString(h) && strings.TrimSpace(h) == h && (!inURL || strings.HasPrefix(h, "[") || !strings.Contains(host, ":"))
}

// bracketed is a serialized host in brackets when it holds a ":" without them: Serialize brackets
// an IPv6 address but writes a zoned one, which no URL carries, as it is.
func bracketed(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

// placing is the distinct text around the host[:port] of probes that hold one, in their order: an
// empty pair for a bare host, a scheme and a path for a URL.
func placing(probes []Probe) [][2]string {
	seen := map[[2]string]bool{}
	var out [][2]string
	for _, p := range probes {
		at := [2]string{p.before, p.after}
		if p.hosted && !seen[at] {
			seen[at] = true
			out = append(out, at)
		}
	}
	return out
}

// cellSeeds is one host probe per family, wrap and port, a cell of the golden's summary, taking each
// family's hosts in turn so that every host seeds some cell.
func cellSeeds() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range hostBases {
		i := 0
		for _, w := range wraps {
			for _, p := range ports {
				in := w.wrap(b.hosts[i%len(b.hosts)]) + p
				i++
				if !seen[in] {
					seen[in] = true
					out = append(out, in)
				}
			}
		}
	}
	return out
}

// foldedBaseline is the lines of testdata/hostdecisions.allowed, each input in ASCII lower case.
func foldedBaseline(t testing.TB) map[string]bool {
	t.Helper()
	allowed, err := readLines("testdata/hostdecisions.allowed")
	if err != nil {
		t.Fatalf("read the allowed baseline: %v", err)
	}
	out := map[string]bool{}
	for _, l := range allowed {
		if f, ok := parseLine(t, "hostdecisions.allowed", l, 2); ok {
			in, _ := strconv.Unquote(f[1]) // parseLine checked the quoting
			out[line(f[0], foldASCII(in))] = true
		}
	}
	return out
}

// foldASCII is s with its ASCII letters in lower case and every other byte as it is: the one fold
// every list check makes, and one that cannot merge two hosts a browser tells apart.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
