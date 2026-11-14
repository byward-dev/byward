package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/server"
)

// command is a subcommand of byward. Each reads the same BYWARD_* environment as the proxy, unless its
// usage says otherwise.
type command struct {
	usage string                                                                          // for --help: the call, then indented lines
	run   func(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int // args exclude the command name
}

var commands = map[string]command{
	"revoke-user": {
		usage: "byward revoke-user <user key>\n      end one user's access: their grants go, and every proxy refuses their tokens within seconds;\n      works while the proxy runs",
		run:   revokeUser,
	},
	"revoke-all": {
		usage: "byward revoke-all --yes\n      end every user's access at once (incident response); works while the proxy runs",
		run:   revokeAll,
	},
	"store": {
		usage: "byward store new-epoch --yes\n      after restoring the PostgreSQL store (pg_restore, point-in-time recovery): start a new epoch, so refresh tokens\n      from before it stop working and their users sign in again; works while the proxy runs",
		run:   storeCommand,
	},
	"check": {
		usage: "byward check --offline [-- stdio-upstream-command [args...]]\n      validate the configuration, keys and static clients without network access; exit 0 or 2",
		run:   checkOffline,
	},
	"doctor": {
		usage: "byward doctor [--json] [-- stdio-upstream-command [args...]]\n      probe the running proxy as MCP clients do, and the IdP app; exit 0, 2 (configuration), 4 (proxy), 8 (IdP) or 12 (both)",
		run:   runDoctor,
	},
	"jwks": {
		usage: "byward jwks\n      print the public keys of the identity assertion as a JWKS, for an upstream that loads them from a file; run again after every key rotation",
		run:   exportJWKS,
	},
	"init": {
		usage: "byward init entra --tenant <tenant-id> [--public-url <url>] [--upstream-url <url>] [--secret-years 1|2] [--credential secret|certificate]\n      print the az commands for the Entra app registration and a minimal env file; runs nothing",
		run:   initIdP,
	},
	"downstream-token": {
		usage: "byward downstream-token [--json]\n      run by a stdio upstream process or one of its descendants: print its user's On-Behalf-Of token\n      (--json: with expires_at); reads only BYWARD_DOWNSTREAM_TOKEN_SOCKET; on an error answer, its code alone on stderr and exit 1",
		run:   downstreamToken,
	},
}

// commandsUsage is the commands block of --help, in name order.
func commandsUsage() string {
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString("\nCommands (read the same BYWARD_* environment as the proxy, unless their line says otherwise):\n")
	for _, n := range names {
		fmt.Fprintf(&b, "  %s\n", commands[n].usage)
	}
	return b.String()
}

// commandHint explains a command that came after flags: commands go first and read settings from
// the environment only.
func commandHint(args []string) string {
	for _, a := range args {
		if _, ok := commands[a]; ok {
			return fmt.Sprintf(" (to run %s, put it first: byward %s ...; commands take their settings from BYWARD_* environment variables, not flags)", a, a)
		}
	}
	return ""
}

// operatorLoad reads the configuration a command runs with; args is nil, or "--" and a stdio
// upstream command, as the proxy takes it. A failure is reported and exits 2.
func operatorLoad(args, environ []string, stderr io.Writer) (*config.Config, bool) {
	cfg, _, err := config.Load(args, environ, os.ReadFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return nil, false
	}
	return cfg, true
}

// revokeUser is revoke-user (ADR-0006 §9).
func revokeUser(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward revoke-user <user key>")
		return exitConfig
	}
	cfg, ok := operatorLoad(nil, environ, stderr)
	if !ok {
		return exitConfig
	}
	key := args[0]
	user, err := server.RevokeUser(ctx, cfg, logging.New(stderr, cfg.LogFormat), key)
	switch {
	case errors.Is(err, server.ErrNotAUserKey):
		_, _ = fmt.Fprintf(stderr, "byward: revoke-user %q: %v\n", key, err)
		return exitConfig
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "byward: revoke-user failed: %v\n", err)
		return exitRuntime
	}
	_, _ = fmt.Fprintf(stdout, "revoked user %s: their grants are gone and their tokens stop working within seconds\n", user)
	return exitOK
}

// revokeAll is revoke-all (ADR-0006 §9); --yes, because it signs every user out.
func revokeAll(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	if !slices.Equal(args, []string{"--yes"}) {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward revoke-all --yes (signs every user out)")
		return exitConfig
	}
	cfg, ok := operatorLoad(nil, environ, stderr)
	if !ok {
		return exitConfig
	}
	if err := server.RevokeAll(ctx, cfg, logging.New(stderr, cfg.LogFormat)); err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: revoke-all failed: %v\n", err)
		return exitRuntime
	}
	_, _ = fmt.Fprintln(stdout, "revoked every user: their grants are gone and their tokens stop working within seconds")
	return exitOK
}

// storeCommand is `store new-epoch --yes` (ADR-0007 §9); --yes, because users sign in again.
func storeCommand(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	if !slices.Equal(args, []string{"new-epoch", "--yes"}) {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward store new-epoch --yes (refresh tokens from before it stop working)")
		return exitConfig
	}
	cfg, ok := operatorLoad(nil, environ, stderr)
	if !ok {
		return exitConfig
	}
	epoch, err := server.NewEpoch(ctx, cfg, logging.New(stderr, cfg.LogFormat))
	switch {
	case errors.Is(err, server.ErrNewEpochNeedsPostgres):
		_, _ = fmt.Fprintf(stderr, "byward: store new-epoch: %v\n", err)
		return exitConfig
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "byward: store new-epoch failed: %v\n", err)
		return exitRuntime
	}
	_, _ = fmt.Fprintf(stdout, "started store epoch %d: refresh tokens from before it stop working, and their users sign in again\n", epoch)
	return exitOK
}
