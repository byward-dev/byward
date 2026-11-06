package server

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// How TestIntegrationConformanceAuthorization judges the conformance CLI's results. No build tag:
// the rules are checked in `test`, without Docker or the CLI.

// requiredScenarios are the scenarios of the pinned CLI's `authorization` suite and, for each,
// the check IDs that must succeed, or the reason the whole scenario must skip. A scenario the CLI
// adds, drops or empties fails the test.
var requiredScenarios = map[string]struct {
	succeed []string
	skip    string
}{
	"authorization-server-metadata-endpoint": {succeed: []string{"authorization-server-metadata", "authorization-server-metadata-cimd"}},
	"authorization-code-grant":               {succeed: []string{"authorization-code-grant"}},
	"dpop":                                   {skip: "byward advertises no dpop_signing_alg_values_supported: DPoP is not in v0.1 (ADR-0011 §8)"},
}

// allowedWarnings are SHOULD checks byward does not meet, by check ID, each with the reason. Any
// other WARNING fails the test, so a regression on a SHOULD byward meets today is noticed.
var allowedWarnings = map[string]string{}

// judgeScenario applies requiredScenarios and the allowed warnings (by check ID, with reasons) to
// one scenario's checks and returns every problem found.
func judgeScenario(scenario string, checks []conformanceCheck, allowed map[string]string) []string {
	req := requiredScenarios[scenario]
	if len(checks) == 0 {
		return []string{scenario + " reported no checks"}
	}
	var problems []string
	succeeded := map[string]bool{}
	skipped := false
	for _, c := range checks {
		switch c.Status {
		case "SUCCESS", "INFO":
			succeeded[c.ID] = succeeded[c.ID] || c.Status == "SUCCESS"
			if req.skip != "" && c.Status == "SUCCESS" {
				problems = append(problems, fmt.Sprintf("%s: %s succeeded, but the scenario must skip (%s)", scenario, c.ID, req.skip))
			}
		case "SKIPPED":
			skipped = true
			if req.skip == "" {
				problems = append(problems, fmt.Sprintf("%s: %s skipped (%s); this scenario must run", scenario, c.ID, c.ErrorMessage))
			}
		case "WARNING":
			if allowed[c.ID] == "" {
				problems = append(problems, fmt.Sprintf("%s: %s is a WARNING (a SHOULD byward no longer meets?): %s", scenario, c.ID, c.ErrorMessage))
			}
		default:
			problems = append(problems, fmt.Sprintf("%s: %s is %s: %s", scenario, c.ID, c.Status, c.ErrorMessage))
		}
	}
	if req.skip != "" && !skipped {
		problems = append(problems, fmt.Sprintf("%s: no check skipped, but the scenario must skip (%s)", scenario, req.skip))
	}
	for _, id := range req.succeed {
		if !succeeded[id] {
			problems = append(problems, fmt.Sprintf("%s: check %s did not succeed", scenario, id))
		}
	}
	return problems
}

type conformanceCheck struct {
	ID, Status, ErrorMessage string
}

// resultDir is the CLI's per-scenario directory, authorization-server-<scenario>-<ISO time with
// ':' and '.' replaced by '-'> (src/runner/utils.ts, createResultDir).
var resultDir = regexp.MustCompile(`^authorization-server-(.+)-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$`)

// The judging of results, without the CLI: crafted check lists for each rule.
func TestConformanceResultsAreJudged(t *testing.T) {
	ok := func(id string) conformanceCheck { return conformanceCheck{ID: id, Status: "SUCCESS"} }
	with := func(id, status string) conformanceCheck { return conformanceCheck{ID: id, Status: status} }
	cases := []struct {
		name, scenario string
		checks         []conformanceCheck
		want           string // a substring of the one expected problem; "" means none
	}{
		{"metadata passes", "authorization-server-metadata-endpoint", []conformanceCheck{ok("authorization-server-metadata"), ok("authorization-server-metadata-cimd")}, ""},
		{"no checks", "authorization-server-metadata-endpoint", nil, "reported no checks"},
		{"a required check missing", "authorization-server-metadata-endpoint", []conformanceCheck{ok("authorization-server-metadata")}, "authorization-server-metadata-cimd did not succeed"},
		{"an unlisted warning", "authorization-server-metadata-endpoint", []conformanceCheck{ok("authorization-server-metadata"), with("authorization-server-metadata-cimd", "WARNING")}, "is a WARNING"},
		{"a failure", "authorization-code-grant", []conformanceCheck{with("authorization-code-grant", "FAILURE")}, "is FAILURE"},
		{"a skip where the scenario must run", "authorization-code-grant", []conformanceCheck{with("authorization-code-grant", "SKIPPED")}, "this scenario must run"},
		{"dpop skips", "dpop", []conformanceCheck{with("sep-1932-as-metadata", "SKIPPED")}, ""},
		{"dpop succeeding where it must skip", "dpop", []conformanceCheck{ok("sep-1932-as-metadata")}, "succeeded, but the scenario must skip"},
		{"dpop succeeding beside a skip", "dpop", []conformanceCheck{ok("sep-1932-as-metadata"), with("sep-1932-as-token-binding", "SKIPPED")}, "succeeded, but the scenario must skip"},
		{"dpop with only INFO does not skip", "dpop", []conformanceCheck{with("sep-1932-as-metadata", "INFO")}, "no check skipped"},
		{"an INFO does not satisfy a required check", "authorization-code-grant", []conformanceCheck{with("authorization-code-grant", "INFO")}, "did not succeed"},
		{"a success after an INFO still satisfies it", "authorization-code-grant", []conformanceCheck{with("authorization-code-grant", "INFO"), ok("authorization-code-grant")}, ""},
		{"a listed warning", "authorization-code-grant", []conformanceCheck{ok("authorization-code-grant"), with("listed-should", "WARNING")}, ""},
		{"a warning not listed", "authorization-code-grant", []conformanceCheck{ok("authorization-code-grant"), with("other-should", "WARNING")}, "other-should is a WARNING"},
		{"an unknown status", "authorization-code-grant", []conformanceCheck{with("authorization-code-grant", "PENDING")}, "is PENDING"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems := judgeScenario(c.scenario, c.checks, map[string]string{"listed-should": "a reason"})
			switch {
			case c.want == "" && len(problems) > 0:
				t.Errorf("problems %q, want none", problems)
			case c.want != "" && (len(problems) == 0 || !strings.Contains(strings.Join(problems, "|"), c.want)):
				t.Errorf("problems %q, want one containing %q", problems, c.want)
			}
		})
	}
}

// The CLI's per-scenario results directories map to scenario names.
func TestConformanceResultDirsAreParsed(t *testing.T) {
	for dir, scenario := range map[string]string{
		"authorization-server-authorization-server-metadata-endpoint-2026-11-06T22-41-09-142Z": "authorization-server-metadata-endpoint",
		"authorization-server-dpop-2026-11-06T22-30-01-000Z":                                   "dpop",
	} {
		t.Run(scenario, func(t *testing.T) {
			if m := resultDir.FindStringSubmatch(dir); m == nil || m[1] != scenario {
				t.Errorf("results directory %s: got %v, want scenario %s", dir, m, scenario)
			}
		})
	}
}
