package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/server"
)

// checkOffline is `check --offline` (ADR-0020 §7). Without --offline it refuses, so that a future
// online check never changes what an existing script does.
func checkOffline(_ context.Context, args, environ []string, stdout, stderr io.Writer) int {
	flags, upstream := splitAtDashes(args)
	if !slices.Equal(flags, []string{"--offline"}) {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward check --offline [-- stdio-upstream-command [args...]] (for the network checks, run byward doctor)")
		return exitConfig
	}
	cfg, ok := operatorLoad(upstream, environ, stderr)
	if !ok {
		return exitConfig
	}
	warnings, err := server.CheckOffline(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return exitConfig
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(stdout, "warn  %s\n", w)
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
	cfg, ok := operatorLoad(nil, environ, stderr)
	if !ok {
		return exitConfig
	}
	set, err := server.ExportJWKS(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return exitConfig
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

// doctorOptions are doctor's HTTP clients; tests point them at fakes, so they never reach Entra.
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
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return exitConfig
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

// initIdP is `init entra` (ADR-0020 §8, ADR-0012 §12): it prints a script of az commands and a
// minimal env file. It runs nothing, calls no API and never sees a secret.
func initIdP(_ context.Context, args, environ []string, stdout, stderr io.Writer) int {
	const usage = "byward: usage: byward init entra --tenant <tenant-id> [--public-url <url>] [--upstream-url <url>] [--secret-years 1|2]"
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintln(stderr, usage+" (entra is the only IdP so far)")
		return exitConfig
	}
	env := getenv(environ)
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tenant := fs.String("tenant", "", "")
	publicURL := fs.String("public-url", env(config.Setting{Name: "public-url"}.Env()), "")
	upstreamURL := fs.String("upstream-url", env(config.Setting{Name: "upstream-url"}.Env()), "")
	years := fs.Int("secret-years", 1, "")
	if err := fs.Parse(args[1:]); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s\nbyward: init %s: %v\n", usage, args[0], err)
		return exitConfig
	}
	if fs.NArg() > 0 || *tenant == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return exitConfig
	}
	u, err := config.ParsePublicURL(*publicURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: init %s: %v (give --public-url)\n", args[0], err)
		return exitConfig
	}
	script, err := server.InitScript(server.InitOptions{IdP: args[0], Tenant: *tenant, PublicURL: u, UpstreamURL: *upstreamURL,
		SecretYears: *years, Now: time.Now()})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: init %s: %v\n", args[0], err)
		return exitConfig
	}
	_, _ = io.WriteString(stdout, script)
	return exitOK
}
