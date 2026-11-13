package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/byward-dev/byward/internal/upstream/stdio"
)

// downstreamTokenWait bounds downstream-token: the socket answers one connection within 40 s
// (the On-Behalf-Of exchange takes at most 30 s), and a connection may wait behind another.
const downstreamTokenWait = 90 * time.Second

// downstreamToken is downstream-token (#181): a credential command for a stdio upstream. It asks the
// process's token socket and prints the token alone, or with --json the token and its expiry. It
// reads no configuration and logs nothing, so the token is only ever on standard output.
func downstreamToken(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	asJSON := slices.Equal(args, []string{"--json"})
	if len(args) > 0 && !asJSON {
		_, _ = fmt.Fprintln(stderr, "byward: usage: byward downstream-token [--json] (run by a stdio upstream process or one of its children)")
		return exitConfig
	}
	path := getenv(environ)(stdio.EnvDownstreamTokenSocket)
	if path == "" {
		_, _ = fmt.Fprintf(stderr, "byward: downstream-token: %s is not set: run it from a stdio upstream process while On-Behalf-Of is on (BYWARD_OBO_SCOPES)\n", stdio.EnvDownstreamTokenSocket)
		return exitConfig
	}
	ctx, cancel := context.WithTimeout(ctx, downstreamTokenWait)
	defer cancel()
	t, err := stdio.AskDownstreamToken(ctx, path)
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "byward: downstream-token: %v\n", err)
		return exitRuntime
	case t.Error != "":
		_, _ = fmt.Fprintln(stderr, t.Error)
		return exitRuntime
	case asJSON:
		_ = json.NewEncoder(stdout).Encode(map[string]string{"access_token": t.AccessToken, "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339)})
	default:
		_, _ = fmt.Fprintln(stdout, t.AccessToken)
	}
	return exitOK
}
