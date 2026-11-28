package hostfamilies

import (
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/host"
)

// Each of Fuzz's rules fails a fake column that breaks it, by name, and none fails a column that
// keeps it: a listed host in another letter case or spelling, a path after a listed host, a form
// browsers write that differs only in its brackets, and a host with no written form to compare.
func TestEachFuzzRuleFailsTheColumnThatBreaksIt(t *testing.T) {
	const col = "c"
	bare, inURL := [][2]string{{"", ""}}, [][2]string{{"https://", "/x"}}
	passes := func(ins ...string) func(string) (bool, string) {
		return func(in string) (bool, string) { return slices.Contains(ins, in), "refused" }
	}
	for _, tc := range []struct {
		name   string
		column Column
		at     [][2]string
		listed []string // the inputs the baseline lists for the column
		h      string
		want   string // the start of the one report, or "" for none
	}{
		{"a list check passes an unlisted host", Column{Lists: true, Judge: passes("evil.example")}, bare, []string{"mcp.example.com"}, "evil.example",
			`c passes "evil.example", which testdata/hostdecisions.allowed lists in no letter case (a widening)`},
		{"a list check in a URL passes an unlisted host", Column{Lists: true, Judge: passes("https://evil.example/x")}, inURL, []string{"https://mcp.example.com/x"}, "evil.example",
			`c passes "https://evil.example/x", which testdata/hostdecisions.allowed lists in no letter case (a widening)`},
		{"a list check passes an unlisted host before a path that names a listed one", Column{Lists: true, Judge: passes("https://evil.example/@mcp.example.com/x")}, inURL, []string{"https://mcp.example.com/x"}, "evil.example/@mcp.example.com",
			`c passes "https://evil.example/@mcp.example.com/x", which testdata/hostdecisions.allowed lists in no letter case (a widening)`},
		{"a bare list check passes a listed host and a path", Column{Lists: true, Judge: passes("mcp.example.com/a")}, bare, []string{"mcp.example.com"}, "mcp.example.com/a",
			`c passes "mcp.example.com/a", which testdata/hostdecisions.allowed lists in no letter case (a widening)`},
		{"a list check passes another spelling of a listed address before a path", Column{Lists: true, Judge: passes("https://127.1/a/x")}, inURL, []string{"https://127.0.0.1/x"}, "127.1/a", ""},
		{"a list check passes a path with two delimiters after a listed host", Column{Lists: true, Judge: passes("https://mcp.example.com/a/b/x")}, inURL, []string{"https://mcp.example.com/x"}, "mcp.example.com/a/b", ""},
		{"a denylist passes a path after a host it stops", Column{Denies: true, Judge: passes("https://mcp.example.com/a/x")}, inURL, []string{"https://mcp.example.com/x"}, "mcp.example.com/a", ""},
		{"a list check passes a listed input whose host holds a delimiter", Column{Lists: true, Judge: passes("https://a?b.example/x")}, inURL, []string{"https://a?b.example/x"}, "a?b.example", ""},
		{"a list check passes a query after a listed host", Column{Lists: true, Judge: passes("https://mcp.example.com?a/x")}, inURL, []string{"https://mcp.example.com/x"}, "mcp.example.com?a", ""},
		{"a list check passes a fragment after a listed host", Column{Lists: true, Judge: passes("https://mcp.example.com#a/x")}, inURL, []string{"https://mcp.example.com/x"}, "mcp.example.com#a", ""},
		{"a list check passes a backslash path after a listed host", Column{Lists: true, Judge: passes("https://mcp.example.com\\a/x")}, inURL, []string{"https://mcp.example.com/x"}, "mcp.example.com\\a", ""},
		{"a list check passes a listed host in another letter case", Column{Lists: true, Judge: passes("MCP.example.com", "mcp.example.com")}, bare, []string{"mcp.example.com"}, "MCP.example.com", ""},
		// A browser writes the Kelvin sign as k (UTS 46), so the form browsers write of it is listed.
		{"a list check passes a host whose written form is listed", Column{Lists: true, Judge: passes("\u212a.example", "k.example")}, bare, []string{"k.example"}, "\u212a.example", ""},
		{"a list check passes another spelling of a listed address", Column{Lists: true, Judge: passes("127.1:8080", "127.0.0.1:8080")}, bare, []string{"127.0.0.1:8080"}, "127.1:8080", ""},
		{"a list check passes a path after a listed host", Column{Lists: true, Judge: passes("https://mcp.example.com/a/x")}, inURL, []string{"https://mcp.example.com/x"}, "mcp.example.com/a", ""},
		{"a denylist stops a listed host", Column{Denies: true, Judge: passes()}, bare, []string{"evil.example"}, "EVIL.example", ""},
		{"a denylist no longer stops a listed host", Column{Denies: true, Judge: passes("EVIL.example")}, bare, []string{"evil.example"}, "EVIL.example",
			`c no longer stops "EVIL.example", a spelling of an input testdata/hostdecisions.allowed says it stops (a widening)`},
		{"a check refuses the form browsers write", Column{Judge: passes("0177.0.0.1:8080")}, bare, nil, "0177.0.0.1:8080",
			`c passes "0177.0.0.1:8080" but refuses "127.0.0.1:8080", its host as browsers write it: refused`},
		{"a check takes the form browsers write", Column{Judge: passes("0177.0.0.1:8080", "127.0.0.1:8080")}, bare, nil, "0177.0.0.1:8080", ""},
		{"a zoned address keeps its brackets", Column{Judge: passes("[FE80::1%25eth0]", "[fe80::1%25eth0]")}, bare, nil, "[FE80::1%25eth0]", ""},
		{"a host that is not UTF-8 has no written form", Column{Judge: passes("\xb6")}, bare, nil, "\xb6", ""},
		{"a host with white space at an end has no written form", Column{Judge: passes(" ::1")}, bare, nil, " ::1", ""},
		{"an IPv6 address without brackets in a URL has no written form", Column{Judge: passes("https://::1/x")}, inURL, nil, "::1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.column.Name = col
			listed := map[string]bool{}
			for _, in := range tc.listed {
				listed[line(col, foldASCII(in))] = true
			}
			z := fuzzer{columns: func(testing.TB) []Column { return []Column{tc.column} }, placings: map[string][][2]string{col: tc.at}, listed: listed, split: host.Split, serialize: host.Serialize}
			got := record(t, func(tb testing.TB) { z.check(tb, tc.h) })
			if tc.want == "" && len(got) != 0 || tc.want != "" && (len(got) != 1 || !strings.HasPrefix(got[0], tc.want)) {
				t.Errorf("check(%q) reported %q; want %q", tc.h, got, tc.want)
			}
		})
	}
}

// The round trip judges the form browsers write with a fresh column, so a check that remembers what
// it judged (a cache) is not refused for the second look.
func TestTheRoundTripJudgesWithAFreshColumn(t *testing.T) {
	columns := func(testing.TB) []Column {
		seen := false
		return []Column{{Name: "c", Judge: func(string) (bool, string) { first := !seen; seen = true; return first, "seen before" }}}
	}
	z := fuzzer{columns: columns, placings: map[string][][2]string{"c": {{"", ""}}}, listed: map[string]bool{}, split: host.Split, serialize: host.Serialize}
	if got := record(t, func(tb testing.TB) { z.check(tb, "mcp.example.com") }); len(got) != 0 {
		t.Errorf("a cached check reported %q", got)
	}
}

// A column places a fuzzed host as its probes do: bare for the host probes, after each scheme and
// before the path for the URL probes, and a URL shape, which holds no host, adds nothing.
func TestAColumnPlacesAHostAsItsProbesDo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probes []Probe
		want   [][2]string
	}{
		{"host probes", HostProbes(), [][2]string{{"", ""}}},
		{"URL probes", URLProbes("/cb", "https", "http"), [][2]string{{"https://", "/cb"}, {"http://", "/cb"}}},
		{"both", append(HostProbes(), URLProbes("/x", "https")...), [][2]string{{"", ""}, {"https://", "/x"}}},
	} {
		if got := placing(tc.probes); !slices.Equal(got, tc.want) {
			t.Errorf("%s: placing = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The seeds hold every host of every family, each input once.
func TestTheSeedsHoldEveryHostOfEveryFamily(t *testing.T) {
	seeds := cellSeeds()
	if len(seeds) != len(slices.Compact(slices.Sorted(slices.Values(seeds)))) {
		t.Errorf("a seed is given twice")
	}
	for _, b := range hostBases {
		for _, h := range b.hosts {
			if !slices.ContainsFunc(seeds, func(s string) bool { return strings.HasPrefix(s, h) || strings.HasPrefix(s, "["+h) }) {
				t.Errorf("%s: no seed holds %q", b.family, h)
			}
		}
	}
}

// A probe list is built once and shared, so a caller that appends to one gets its own copy.
func TestAppendingToAProbeListLeavesTheSharedListAsItIs(t *testing.T) {
	a := append(HostProbes(), Probe{Input: "a"})
	b := append(HostProbes(), Probe{Input: "b"})
	if a[len(a)-1].Input != "a" || b[len(b)-1].Input != "b" || len(HostProbes()) != len(a)-1 {
		t.Errorf("appending to HostProbes changed what another caller holds")
	}
}

// The baseline lookup folds ASCII letters only, so a check that folds more is a finding.
func TestFoldASCIILowersASCIILettersOnly(t *testing.T) {
	for in, want := range map[string]string{
		"MCP.Example.COM": "mcp.example.com",
		"K":               "K", // the Kelvin sign, which strings.ToLower maps to k
		"İ":               "İ", // İ, which strings.ToLower maps to i̇
		"\xb6Z":           "\xb6z",
		"[::FFFF:7F00:1]": "[::ffff:7f00:1]",
	} {
		if got := foldASCII(in); got != want {
			t.Errorf("foldASCII(%q) = %q, want %q", in, got, want)
		}
	}
}
