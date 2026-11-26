package hostfamilies

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/recordtb"
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

// record runs check under recordtb.Run and returns what it reported, in the order reported: a
// fatal ends the check.
func record(t *testing.T, check func(testing.TB)) []string {
	rep := recordtb.Run(t, check)
	return slices.Concat(rep.Errors, rep.Fatals)
}

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
		{"a residual without an issue number", nil, []string{host + "\t\"a\"\t#\twhy"}, nil, []string{host + "\t\"a\""}, []string{"hostdecisions.residuals: \"public Host\\t\\\"a\\\"\\t#\\twhy\": want column"}},
		{"a residual without a why", nil, []string{host + "\t\"a\"\t#1\t "}, nil, []string{host + "\t\"a\""}, []string{"hostdecisions.residuals: \"public Host\\t\\\"a\\\"\\t#1\\t \": want column"}},
		{"a residual listed twice", nil, []string{host + "\t\"a\"\t#1\twhy", host + "\t\"a\"\t#1\twhy"}, nil, []string{host + "\t\"a\""}, []string{"hostdecisions.residuals lists public Host\t\"a\" twice"}},
		{"an input quoted another way", []string{host + "\t\"\\x61\""}, nil, nil, nil, []string{"hostdecisions.allowed: \"public Host\\t\\\"\\\\x61\\\"\": the input must be quoted"}},
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
			errs := record(t, func(r testing.TB) {
				checkBaseline(r, set(tc.given), map[string]bool{deny: true})
				checkResiduals(r, set(tc.passes))
			})
			if len(errs) != len(tc.want) || !slices.EqualFunc(errs, tc.want, strings.HasPrefix) {
				t.Errorf("reports:\n%s\nwant ones starting:\n%s", strings.Join(errs, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// Run refuses a package whose columns are not the ones listed for it, or that has none listed, before
// it judges anything, so a check missing from either list fails by name.
func TestRunRefusesColumnsTheListDoesNotHold(t *testing.T) {
	for _, tc := range []struct {
		name, pkg string
		cols      []Column
	}{
		{"a package with no columns listed", "internal/unlisted", nil},
		{"a column the list lacks", "internal/broker", []Column{{Name: "consent Origin"}, {Name: "another"}}},
		{"a listed column left out", "internal/broker", nil},
		{"a column named otherwise", "internal/broker", []Column{{Name: "another"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := record(t, func(r testing.TB) { Run(r, tc.pkg, tc.cols) })
			if len(errs) != 1 || !strings.HasPrefix(errs[0], tc.pkg+" runs the columns") {
				t.Errorf("reports %q, want one starting %q", errs, tc.pkg+" runs the columns")
			}
		})
	}
}

// Run reads a denylist's baseline as the inputs it stops: a residual is an input it should stop and
// does not, checked against what it lets through, and an input it no longer stops is a widening.
func TestRunReadsADenylistsBaselineAsTheInputsItStops(t *testing.T) {
	for _, tc := range []struct {
		name, allowed, residuals string
		want                     []string
	}{
		{"a residual it lets through", "", "deny\t\"a\"\t#1\tshould be stopped\n", nil},
		{"an input it no longer stops", "deny\t\"a\"\n", "", []string{"no longer denied (a widening): deny\t\"a\""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BYWARD_UPDATE_GOLDEN", "1")
			t.Chdir(t.TempDir())
			if err := os.Mkdir("testdata", 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"hostdecisions.allowed": "# header\n" + tc.allowed, "hostdecisions.residuals": "# header\n" + tc.residuals} {
				if err := os.WriteFile(filepath.Join("testdata", name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			columns["test/deny"] = []string{"deny"}
			defer delete(columns, "test/deny")
			errs := record(t, func(r testing.TB) {
				Run(r, "test/deny", []Column{{Name: "deny", Denies: true, Probes: []Probe{{Family: "f", Wrap: "w", Port: "none", Input: "a"}},
					Judge: func(string) (bool, string) { return true, "" }}})
			})
			if len(errs) != len(tc.want) || !slices.EqualFunc(errs, tc.want, strings.HasPrefix) {
				t.Errorf("reports %q, want ones starting %q", errs, tc.want)
			}
		})
	}
}

// Run checks the residuals against what each check lets through: a residual its check now refuses,
// as after its issue's fix, is reported, so the fix deletes it.
func TestRunReportsAResidualItsCheckNoLongerLetsThrough(t *testing.T) {
	t.Setenv("BYWARD_UPDATE_GOLDEN", "1")
	t.Chdir(t.TempDir())
	if err := os.Mkdir("testdata", 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"hostdecisions.allowed": "# header\n", "hostdecisions.residuals": "# header\nhost\t\"a\"\t#1\tlet through\n"} {
		if err := os.WriteFile(filepath.Join("testdata", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	columns["test/host"] = []string{"host"}
	defer delete(columns, "test/host")
	errs := record(t, func(r testing.TB) {
		Run(r, "test/host", []Column{{Name: "host", Probes: []Probe{{Family: "f", Wrap: "w", Port: "none", Input: "a"}},
			Judge: func(string) (bool, string) { return false, "refused" }}})
	})
	if want := "residual host\t\"a\" (#1): its check no longer lets it through"; len(errs) != 1 || !strings.HasPrefix(errs[0], want) {
		t.Errorf("reports %q, want one starting %q", errs, want)
	}
}
