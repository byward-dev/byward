package hostfamilies

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every column Columns lists is in its package's decision golden, so a check dropped from its
// package's test, or a package whose test no longer runs, fails here by name.
func TestEveryColumnIsInItsPackagesGolden(t *testing.T) {
	for pkg, cols := range Columns {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", pkg, "testdata", "hostdecisions.golden")) //nolint:gosec // G304: a package's own testdata file
		if err != nil {
			t.Errorf("%s: %v", pkg, err)
			continue
		}
		for _, c := range cols {
			if !strings.Contains(string(b), "\n## "+c+": ") {
				t.Errorf("%s: the column %q is not in its hostdecisions.golden", pkg, c)
			}
		}
	}
}

// Every family has inputs in it, and every input is generated once, so a summary's counts are
// counts of distinct inputs, and a check with a cache judges each input afresh.
func TestEachFamilyHasDistinctInputs(t *testing.T) {
	families := map[string]int{}
	for name, probes := range map[string][]Probe{"hosts": HostProbes(), "URLs": URLProbes("/x", "https", "http")} {
		seen := map[string]bool{}
		for _, p := range probes {
			if seen[p.Input] {
				t.Errorf("%s: input %q is generated twice", name, p.Input)
			}
			seen[p.Input] = true
			families[p.Family]++
		}
	}
	if families["url shape"] == 0 {
		t.Error("family \"url shape\" has no inputs")
	}
	for _, b := range hostBases {
		if families[b.family] == 0 {
			t.Errorf("family %q has no inputs", b.family)
		}
	}
}

func TestReasonCountsRefusalsForOneReasonAsOneClass(t *testing.T) {
	for in, want := range map[string]string{
		"BYWARD_ALLOWED_HOSTS: want a host; got entry 2 of 3 (12 characters, not shown): it has a port":   "BYWARD_ALLOWED_HOSTS: want a host; got entry N of N (N characters, not shown): it has a port",
		"got a value (1 character, not shown): its host has a character no host name holds at position 7": "got a value (N characters, not shown): its host has a character no host name holds at position N",
		"misdirected": "misdirected",
	} {
		if got := Reason(in); got != want {
			t.Errorf("Reason(%q) = %q, want %q", in, got, want)
		}
	}
}
