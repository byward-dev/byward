package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/server"
	"github.com/byward-dev/byward/internal/tracing"
)

// checkOffline is `check --offline` (ADR-0020 §7). Without --offline it refuses, so that a future
// online check never changes what an existing script does.
func checkOffline(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	flags, upstream := splitAtDashes(args)
	if !slices.Equal(flags, []string{"--offline"}) {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward check --offline [-- stdio-upstream-command [args...]] (for the network checks, run byward doctor)")
		return exitConfig
	}
	cfg, ok := operatorLoad(upstream, environ, stderr)
	if !ok {
		return exitConfig
	}
	// The trace exporter, as startup builds it and in startup's order, before the rest (L157): a
	// setting startup refuses fails check too. It connects to nothing, and is shut down at once.
	exp, err := tracing.NewExporter(ctx, getenv(environ), logging.New(stderr, cfg.LogFormat))
	if err != nil {
		return reportConfigError(stderr, fmt.Errorf("OTEL_* tracing settings: %w", err))
	}
	if exp != nil {
		_ = exp.Shutdown(ctx)
	}
	report, err := server.CheckOfflineReport(cfg)
	if err != nil {
		return reportConfigError(stderr, err)
	}
	// As the startup log has them (security invariant 12), labelled neutrally: --insecure-no-auth's
	// are not development mode.
	for _, r := range cfg.Relaxations {
		_, _ = fmt.Fprintf(stdout, "warn  relaxation: %s\n", r)
	}
	for _, w := range report.Warnings {
		_, _ = fmt.Fprintf(stdout, "warn  %s\n", w)
	}
	if report.ClientCredentialDesc != "" {
		_, _ = fmt.Fprintf(stdout, "info  client credential: %s\n", report.ClientCredentialDesc)
	}
	_, _ = fmt.Fprintln(stdout, "configuration OK (offline: the IdP and the running proxy were not contacted; run byward doctor for those)")
	return exitOK
}

// exportJWKS is `jwks` (ADR-0016 §3): the assertion's public keys on standard output.
func exportJWKS(_ context.Context, args, environ []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward jwks (prints the JWKS; redirect it to a file)")
		return exitConfig
	}
	cfg, err := config.LoadEnvironment(environ, os.ReadFile) // jwks takes no --, so no error suggests a command after it (#499)
	if err != nil {
		return reportConfigError(stderr, err)
	}
	set, err := server.ExportJWKS(cfg)
	if err != nil {
		return reportConfigError(stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", set)
	return exitOK
}

// splitAtDashes splits a command's arguments at "--": its own flags, then "--" and the stdio
// upstream command (nil when there is none), which config reads as the proxy does.
func splitAtDashes(args []string) (flags, upstream []string) {
	if i := slices.Index(args, "--"); i >= 0 {
		return args[:i], args[i:]
	}
	return args, nil
}

// doctorOptions are doctor's HTTP clients, resolver and upstream proxy; tests point them at fakes,
// so they never reach Entra or the network.
var doctorOptions server.DoctorOptions

// runDoctor is `doctor [--json]` (ADR-0021 §11). The exit code is the report's: 0, or the OR of 4
// (proxy) and 8 (IdP); a configuration error is 2 and runs no check.
func runDoctor(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	flags, upstream := splitAtDashes(args)
	asJSON := slices.Equal(flags, []string{"--json"})
	if len(flags) > 0 && !asJSON {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward doctor [--json] [-- stdio-upstream-command [args...]]")
		return exitConfig
	}
	cfg, ok := operatorLoad(upstream, environ, stderr)
	if !ok {
		return exitConfig
	}
	report, err := server.Doctor(ctx, cfg, doctorOptions)
	if err != nil {
		return reportConfigError(stderr, err)
	}
	if asJSON {
		if err := report.WriteJSON(stdout); err != nil {
			return exitRuntime
		}
	} else {
		report.WriteText(stdout)
	}
	return report.ExitCode()
}

// initFlagRefusal is the text init prints for the flag package's error, with nothing given in it (#576),
// as config maps its own (#512): an argument or flag name only by its length, and a flag that needs a
// value named, since it is one of init's own. init's flags are strings, so the flag package never
// refuses a value. Any other message is refused without its text, so a new one cannot show a value.
func initFlagRefusal(err error) string {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, "bad flag syntax: "); ok {
		return "want flags as --name=value; got an argument with a bad flag syntax " + logging.NotShown(rest)
	}
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		return "want flags init takes; got an undefined flag " + logging.NotShown(name)
	}
	if strings.HasPrefix(msg, "flag needs an argument: -") {
		return msg
	}
	return "the command line is refused (the flag package's message is not shown)"
}

// initFlags are init's flags. Each is a string, read by init, so the flag package never quotes a value
// it cannot parse (#576).
type initFlags struct{ tenant, publicURL, upstreamURL, secretYears, credential *string }

// newInitFlags is init's flag set. The URL flags default to their settings in environ.
func newInitFlags(environ []string) (*flag.FlagSet, initFlags) {
	env := getenv(environ)
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs, initFlags{
		tenant:      fs.String("tenant", "", ""),
		publicURL:   fs.String("public-url", env(config.Setting{Name: "public-url"}.Env()), ""),
		upstreamURL: fs.String("upstream-url", env(config.Setting{Name: "upstream-url"}.Env()), ""),
		secretYears: fs.String("secret-years", "1", ""),
		credential:  fs.String("credential", "secret", ""),
	}
}

// initIdP is `init entra` (ADR-0020 §8, ADR-0012 §12): it prints a script of az commands and a
// minimal env file. It runs nothing, calls no API and never sees a secret.
func initIdP(_ context.Context, args, environ []string, stdout, stderr io.Writer) int {
	const usage = "byward: usage: byward init entra --tenant <tenant-id> [--public-url <url>] [--upstream-url <url>] [--secret-years 1|2] [--credential secret|certificate]"
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintln(stderr, usage+" (init prints the setup of an entra IdP; for an oidc IdP see docs/how-to/oidc.md)")
		return exitConfig
	}
	fs, f := newInitFlags(environ)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, usage)
		} else {
			_, _ = fmt.Fprintf(stderr, "%s\nbyward: init: %s\n", usage, initFlagRefusal(err))
		}
		return exitConfig
	}
	// Base 0, as the flag package reads a number (0x2 is 2).
	secretYears, err := strconv.ParseInt(*f.secretYears, 0, 0)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s\nbyward: init: --secret-years: want a whole number of years; got a value it does not take (not shown)\n", usage)
		return exitConfig
	}
	if fs.NArg() > 0 || *f.tenant == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return exitConfig
	}
	u, err := config.ParsePublicURL(*f.publicURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: init: %v (give --public-url)\n", err)
		return exitConfig
	}
	if *f.upstreamURL != "" { // empty leaves BYWARD_UPSTREAM_URL for the operator to fill in
		if _, err := config.ParseUpstreamURL(*f.upstreamURL); err != nil {
			_, _ = fmt.Fprintf(stderr, "byward: init: %v (give --upstream-url)\n", err)
			return exitConfig
		}
	}
	script, err := server.InitScript(server.InitOptions{IdP: args[0], Tenant: *f.tenant, PublicURL: u, UpstreamURL: *f.upstreamURL,
		SecretYears: int(secretYears), Credential: *f.credential, Now: time.Now()})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: init: %v\n", err)
		return exitConfig
	}
	_, _ = io.WriteString(stdout, script)
	return exitOK
}
