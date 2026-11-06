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

// command is a subcommand of byward. Each reads the same BYWARD_* environment as the proxy.
type command struct {
	usage string                                                                          // for --help: the call, then indented lines
	run   func(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int // args exclude the command name
}

var commands = map[string]command{
	"revoke-user": {
		usage: "byward revoke-user <tid:oid>\n      end one user's access: their grants go, and every proxy refuses their tokens within seconds;\n      works while the proxy runs",
		run:   revokeUser,
	},
	"revoke-all": {
		usage: "byward revoke-all --yes\n      end every user's access at once (incident response); works while the proxy runs",
		run:   revokeAll,
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
	b.WriteString("\nCommands (read the same BYWARD_* environment as the proxy):\n")
	for _, n := range names {
		fmt.Fprintf(&b, "  %s\n", commands[n].usage)
	}
	return b.String()
}

// operatorLoad reads the configuration a command runs with; a failure is reported and exits 2.
func operatorLoad(environ []string, stderr io.Writer) (*config.Config, bool) {
	cfg, _, err := config.Load(nil, environ, os.ReadFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return nil, false
	}
	return cfg, true
}

// revokeUser is revoke-user (ADR-0006 §9).
func revokeUser(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward revoke-user <tid:oid>")
		return exitConfig
	}
	cfg, ok := operatorLoad(environ, stderr)
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
	cfg, ok := operatorLoad(environ, stderr)
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
