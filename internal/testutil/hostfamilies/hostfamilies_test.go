package hostfamilies

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every package columns lists has a test that runs its columns, and a decision golden that holds
// each of them, so a package whose decision test was deleted, or a column never regenerated, fails
// here by name. (A column dropped from a package's Run call fails that package's Run.)
func TestEveryListedPackageRunsAndRecordsItsColumns(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for pkg, cols := range columns {
		call := "hostfamilies.Run(t, " + strconv.Quote(pkg) + ","
		tests, err := filepath.Glob(filepath.Join(root, pkg, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		runs := false
		for _, f := range tests {
			b, err := os.ReadFile(f) //nolint:gosec // G304: a package's own test file
			if err != nil {
				t.Fatal(err)
			}
			runs = runs || strings.Contains(string(b), call)
		}
		if !runs {
			t.Errorf("%s: no test calls %s ...): its host checks are no longer judged", pkg, call)
		}
		b, err := os.ReadFile(filepath.Join(root, pkg, "testdata", "hostdecisions.golden")) //nolint:gosec // G304: a package's own testdata file
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
		t.Error(`family "url shape" has no inputs`)
	}
	for _, b := range hostBases {
		if families[b.family] == 0 {
			t.Errorf("family %q has no inputs", b.family)
		}
	}
}

// recorder is a testing.TB that keeps what a check reports instead of failing.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, a ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, a...))
}
func (r *recorder) Fatalf(format string, a ...any) { r.Errorf(format, a...) }

// The baseline check names each line that differs from the checks' decisions as a widening or a
// narrowing, a denylist's the other way round, and the residual check each residual its check no
// longer lets through, each malformed line, and each line given twice.
func TestTheBaselineNamesEachChangedDecisionAsAWideningOrANarrowing(t *testing.T) {
	const host, deny = "public Host", "denylist redirect"
	for _, tc := range []struct {
		name               string
		allowed, residuals []string
		given, passes      []string // the lines the checks give, and the inputs they let through
		want               []string // the start of each report, in order
	}{
		{"nothing changed", []string{host + "\t\"a\""}, nil, []string{host + "\t\"a\""}, []string{host + "\t\"a\""}, nil},
		{"a check passes a new input", nil, nil, []string{host + "\t\"a\""}, nil, []string{"newly allowed (a widening): public Host\t\"a\""}},
		{"a check no longer passes one", []string{host + "\t\"a\""}, nil, nil, nil, []string{"no longer allowed (a narrowing): public Host\t\"a\""}},
		{"a denylist stops a new input", nil, nil, []string{deny + "\t\"a\""}, nil, []string{"newly denied (a narrowing): denylist redirect\t\"a\""}},
		{"a denylist no longer stops one", []string{deny + "\t\"a\""}, nil, nil, nil, []string{"no longer denied (a widening): denylist redirect\t\"a\""}},
		{"a line listed twice", []string{host + "\t\"a\"", host + "\t\"a\""}, nil, []string{host + "\t\"a\""}, nil, []string{"hostdecisions.allowed lists public Host\t\"a\" twice"}},
		{"an input not quoted as Go quotes it", []string{host + "\ta"}, nil, nil, nil, []string{"hostdecisions.allowed: \"public Host\\ta\": the input must be quoted"}},
		{"a residual still let through", nil, []string{host + "\t\"a\"\t#1\twhy"}, nil, []string{host + "\t\"a\""}, nil},
		{"a residual its issue fixed", nil, []string{host + "\t\"a\"\t#1\twhy"}, nil, nil, []string{"residual public Host\t\"a\" (#1): its check no longer lets it through"}},
		{"a denylist residual not stopped", nil, []string{deny + "\t\"a\"\t#1\twhy"}, nil, []string{deny + "\t\"a\""}, nil},
		{"a residual without an issue number", nil, []string{host + "\t\"a\"\t#\twhy"}, nil, []string{host + "\t\"a\""}, []string{"hostdecisions.residuals: "}},
		{"a residual without a why", nil, []string{host + "\t\"a\"\t#1\t "}, nil, []string{host + "\t\"a\""}, []string{"hostdecisions.residuals: "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.Mkdir("testdata", 0o700); err != nil {
				t.Fatal(err)
			}
			write := func(name string, lines []string) {
				if err := os.WriteFile(filepath.Join("testdata", name), []byte("# header\n"+strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("hostdecisions.allowed", tc.allowed)
			if tc.residuals != nil {
				write("hostdecisions.residuals", tc.residuals)
			}
			set := func(lines []string) map[string]bool {
				m := map[string]bool{}
				for _, l := range lines {
					m[l] = true
				}
				return m
			}
			r := &recorder{TB: t}
			checkBaseline(r, set(tc.given), map[string]bool{deny: true})
			checkResiduals(r, set(tc.passes))
			if len(r.errs) != len(tc.want) || !slices.EqualFunc(r.errs, tc.want, strings.HasPrefix) {
				t.Errorf("reports:\n%s\nwant ones starting:\n%s", strings.Join(r.errs, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}
