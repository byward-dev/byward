package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/golden"
	"github.com/byward-dev/byward/internal/testutil/pgtest"
)

// walkKinds are the forms in secretForms that are a kind of the catalogue of secrets (#657):
// what config refuses in a setting that is not secret, and logs hide. The opaque Bearer credential is
// redact-only, a Known gap (docs/security-posture.md), so its "shown" cells are pinned in walk.shown.
var walkKinds = []string{"userinfo", "DSN key=value", "GitHub token", "Slack token", "JWT",
	"GitHub token after a line break", "GitHub token percent-escaped", "opaque Bearer credential"}

// walkSurface is one place byward prints a value it was given: run gives it v and returns the exit
// code and everything printed. command and flag name what it covers, for walkGaps.
type walkSurface struct {
	name, command, flag string
	run                 func(v string) (int, string)
}

// walkSurfaces lists every surface that prints a value it was given, literally, so a reader sees them
// all. Each command in the commands map has one here or is in walkNoValue; each of init's flags has one.
func walkSurfaces(t *testing.T) []walkSurface {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	entra := leakContexts(t, program)["entra"]
	proxy := func(args []string, setting string) func(string) (int, string) {
		return func(v string) (int, string) {
			code, stdout, stderr := runDone(args, append(withFormat(slices.Clone(entra), "json"), setting+"="+v)...)
			return code, stdout + stderr
		}
	}
	cli := func(args func(v string) []string, env ...string) func(string) (int, string) {
		return func(v string) (int, string) {
			code, stdout, stderr := runWith(args(v), env...)
			return code, stdout + stderr
		}
	}
	initWith := func(flags ...string) func(v string) []string {
		return func(v string) []string {
			args := []string{"init", "entra", "--tenant", tenant, "--public-url", "https://m.example/mcp"}
			for _, f := range flags {
				args = append(args, strings.ReplaceAll(f, "@v@", v))
			}
			return args
		}
	}
	attribute := func(format, msg, key string) func(string) (int, string) {
		return func(v string) (int, string) {
			var b bytes.Buffer
			logging.New(&b, format).Info(msg, key, v)
			return exitOK, b.String()
		}
	}
	revokeEnv := append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)
	return []walkSurface{
		{"startup log, a free-text setting", "", "", proxy(nil, "BYWARD_OPERATOR_NAME")},
		{"--print-config, a free-text setting", "", "", proxy([]string{"--print-config"}, "BYWARD_OPERATOR_NAME")},
		{"--print-config, a URL setting's path", "", "", func(v string) (int, string) {
			return proxy([]string{"--print-config"}, "BYWARD_RESOURCE_DOCUMENTATION")("https://docs.example/" + v)
		}},
		{"--print-config, a list setting's entry", "", "", func(v string) (int, string) {
			return proxy([]string{"--print-config"}, "BYWARD_ALLOWED_HOSTS")("a.example," + v)
		}},
		{"check --offline, a free-text setting", "check", "", proxy([]string{"check", "--offline"}, "BYWARD_OPERATOR_NAME")},
		{"doctor, a free-text setting", "doctor", "", proxy([]string{"doctor"}, "BYWARD_OPERATOR_NAME")},
		{"init entra --tenant", "init", "tenant", cli(func(v string) []string { return []string{"init", "entra", "--tenant", v} })},
		{"init entra --public-url, in its path", "init", "public-url", cli(func(v string) []string {
			return []string{"init", "entra", "--tenant", tenant, "--public-url", "https://m.example/" + v}
		})},
		{"init entra --upstream-url, in its query", "init", "upstream-url", cli(initWith("--upstream-url=https://up.example/mcp?k=@v@"))},
		{"init entra --secret-years", "init", "secret-years", cli(initWith("--secret-years=@v@"))},
		{"init entra --credential", "init", "credential", cli(initWith("--credential=@v@"))},
		{"revoke-user, the user key", "revoke-user", "", cli(func(v string) []string { return []string{"revoke-user", v} }, revokeEnv...)},
		{"a log attribute, JSON", "", "", attribute("json", "refused", "reason")},
		{"a log attribute, text", "", "", attribute("text", "refused", "reason")},
		{"a stdio upstream's stderr line, as stdio logs it", "", "", attribute("json", "upstream stderr", "line")},
	}
}

// walkNoValue are the commands that print no value they are given, each with the test that shows it.
var walkNoValue = map[string]string{
	"revoke-all":       "takes only --yes: TestOperatorCommandsShowNoArgumentTheyAreGiven",
	"store":            "takes only new-epoch --yes: TestOperatorCommandsShowNoArgumentTheyAreGiven",
	"jwks":             "takes no argument: TestOperatorCommandsShowNoArgumentTheyAreGiven",
	"downstream-token": "takes only --json; reads only its socket: TestOperatorCommandsShowNoArgumentTheyAreGiven",
}

// walkGaps names each command with no surface and no entry in noValue, and each of init's flags with
// no surface, so a new command or flag that can print a value fails the walk by name.
func walkGaps(surfaces []walkSurface, cmds map[string]command, noValue map[string]string, initFlags *flag.FlagSet) []string {
	var gaps []string
	for name := range cmds {
		if noValue[name] == "" && !slices.ContainsFunc(surfaces, func(s walkSurface) bool { return s.command == name }) {
			gaps = append(gaps, "command "+name)
		}
	}
	initFlags.VisitAll(func(f *flag.Flag) {
		if !slices.ContainsFunc(surfaces, func(s walkSurface) bool { return s.command == "init" && s.flag == f.Name }) {
			gaps = append(gaps, "init flag --"+f.Name)
		}
	})
	sort.Strings(gaps)
	return gaps
}

// walkOutcome is what a surface did with a value of a kind: shown (the canary is in its output),
// refused (exit 2, the canary nowhere), redacted ([REDACTED] in its place), or kept out (accepted, and
// printed without it).
func walkOutcome(code int, out string) string {
	switch {
	case shows(out):
		return "shown"
	case code == exitConfig:
		return "refused"
	case strings.Contains(out, "[REDACTED]"):
		return "redacted"
	}
	return "kept out"
}

// Every surface that prints a value it was given decides every kind of the catalogue as
// testdata/walk.golden records (#657, the decision golden of AGENTS.md's Pinned tier). The cells a
// surface shows are listed again in testdata/walk.shown, so a cell newly shown is a reviewed diff of
// that file: today only the opaque Bearer credential in a setting shown as given, a Known gap.
// Regenerate with BYWARD_UPDATE_GOLDEN=1 and review both diffs.
func TestEveryPrintingSurfaceDecidesEveryKindAsPinned(t *testing.T) {
	t.Setenv("PGSSLMODE", "verify-full")
	pgtest.ClearEnv(t)
	resolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("a cell resolved a name through DNS")
		return nil, errors.New("the walk resolves no names")
	}}
	t.Cleanup(func() { net.DefaultResolver = resolver })
	processStderr := redirectStderr(t)
	surfaces := walkSurfaces(t)
	fs, _ := newInitFlags(nil)
	if gaps := walkGaps(surfaces, commands, walkNoValue, fs); len(gaps) > 0 {
		t.Errorf("no surface in walkSurfaces for: %s; add one, or a command that prints no value to walkNoValue", strings.Join(gaps, ", "))
	}
	var all, shown strings.Builder
	all.WriteString("# Generated: BYWARD_UPDATE_GOLDEN=1 rewrites it. surface | kind | outcome (#657)\n")
	shown.WriteString("# Generated: the cells of walk.golden that show a value; each is a Known gap (docs/security-posture.md)\n")
	for _, s := range surfaces {
		for _, form := range secretForms {
			if !slices.Contains(walkKinds, form.name) {
				continue
			}
			code, out := s.run(form.value)
			line := s.name + " | " + form.name + " | " + walkOutcome(code, out) + "\n"
			all.WriteString(line)
			if walkOutcome(code, out) == "shown" {
				shown.WriteString(line)
			}
		}
	}
	if got := processStderr(t); got != "" {
		t.Errorf("the walk wrote %q to os.Stderr or the log package, want nothing", got)
	}
	golden.Check(t, "testdata/walk.golden", all.String(), "each line is one surface's decision for one kind (#657); a changed line is a changed decision, which walk.shown must show if it now shows a value")
	golden.Check(t, "testdata/walk.shown", shown.String(), "a cell that newly shows a value is a new leak unless it is a Known gap in docs/security-posture.md")
}

// The walk fails, by name, on a command or a flag of init that has no surface, and calls a surface
// that prints its value "shown": a probe command that echoes its argument is caught both ways.
func TestTheWalkNamesASurfaceItDoesNotCover(t *testing.T) {
	probe := map[string]command{"probe": {run: func(_ context.Context, args, _ []string, stdout, _ io.Writer) int {
		_, _ = io.WriteString(stdout, strings.Join(args, " "))
		return exitOK
	}}}
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.String("probe-flag", "", "")
	if got, want := walkGaps(nil, probe, nil, fs), []string{"command probe", "init flag --probe-flag"}; !slices.Equal(got, want) {
		t.Errorf("walkGaps = %q, want %q", got, want)
	}
	var out bytes.Buffer
	code := probe["probe"].run(context.Background(), []string{"x-" + canary}, nil, &out, &out)
	if got := walkOutcome(code, out.String()); got != "shown" {
		t.Errorf("a probe that echoes its value is %q, want shown", got)
	}
	for _, tc := range []struct {
		code int
		out  string
		want string
	}{{exitConfig, "BYWARD_X: want …; got a value (9 characters, not shown)", "refused"}, {exitOK, `{"reason":"[REDACTED]"}`, "redacted"}, {exitOK, "BYWARD_X=a", "kept out"}} {
		if got := walkOutcome(tc.code, tc.out); got != tc.want {
			t.Errorf("walkOutcome(%d, %q) = %q, want %q", tc.code, tc.out, got, tc.want)
		}
	}
}
