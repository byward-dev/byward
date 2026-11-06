//go:build integration

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"testing"
)

// conformanceCLI is where `mise run test:conformance:install` (scripts/conformance/run.sh
// --install-only) builds the pinned MCP conformance CLI (0.2.0-alpha.12, pinned in run.sh).
var conformanceCLI = filepath.Join("..", "..", "build", "conformance", "src")

// ADR-0024 §4b: the MCP conformance `authorization` suite against byward's authorization server
// (the broker): its metadata, the authorization code grant with PKCE and resource, signed in
// through the consent page and the fake IdP by the scripted browser, and DPoP. Runs with the real
// clients (BYWARD_REAL_CLIENTS=1, Linux) once the CLI is built.
func TestIntegrationConformanceAuthorization(t *testing.T) {
	requireRealClients(t)
	if _, err := os.Stat(filepath.Join(conformanceCLI, "dist", "index.js")); err != nil {
		t.Fatalf("the conformance CLI is not built (%v): run `mise run test:conformance:install` first", err)
	}
	src, err := filepath.Abs(conformanceCLI)
	if err != nil {
		t.Fatal(err)
	}
	env := newRealClientEnv(t)
	out := t.TempDir()
	runCtx, cancel := context.WithTimeout(context.Background(), runBudget)
	defer cancel()
	// The CLI is mounted read-only; its results go to the test's directory (/w).
	cmd := docker(runCtx, t, out, nodeImage(t), "host", nil, []string{"node", "/cli/dist/index.js", "authorization",
		"--url", env.public, "--client-id", realClientID, "--resource", env.MCPURL, "--port", strconv.Itoa(freePort(t)), "-o", "/w"},
		src+":/cli")
	_, output := runSigningIn(t, runCtx, cancel, env.browse, env.public+"/authorize?", cmd)

	results := conformanceResults(t, out)
	var got, want []string
	for s := range results {
		got = append(got, s)
	}
	for s := range requiredScenarios {
		want = append(want, s)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("scenarios run: %v, want %v (update requiredScenarios when the pinned CLI changes)\n%s", got, want, output)
	}
	for _, scenario := range got {
		for _, p := range judgeScenario(scenario, results[scenario], allowedWarnings) {
			t.Error(p)
		}
	}
	if t.Failed() {
		t.Logf("conformance output:\n%s", output)
	}
}

// conformanceResults reads every scenario's checks.json under out.
func conformanceResults(t *testing.T, out string) map[string][]conformanceCheck {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(out, "authorization-server-*", "checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	results := map[string][]conformanceCheck{}
	for _, f := range files {
		m := resultDir.FindStringSubmatch(filepath.Base(filepath.Dir(f)))
		if m == nil {
			t.Fatalf("unexpected results directory %s", filepath.Dir(f))
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: the test's own results directory
		if err != nil {
			t.Fatal(err)
		}
		var checks []conformanceCheck
		if err := json.Unmarshal(b, &checks); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		results[m[1]] = append(results[m[1]], checks...)
	}
	return results
}
