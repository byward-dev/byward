package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/faketokensocket"
)

// downstream-token prints the token alone and nothing on stderr; an
// error answer is its code alone on stderr and exit 1; a usage mistake or no socket in the
// environment exits 2. The token is never on stderr.
func TestDownstreamTokenOutputAndExitCodes(t *testing.T) {
	const tok = "eyJ.downstream.token"
	const ok = `{"access_token":"` + tok + `","expires_at":"2026-11-08T13:00:00Z"}` + "\n"
	const (
		answers  = iota // a socket that answers with answer
		noSocket        // the variable names a path where no socket is
		unset           // the variable is not set
	)
	cases := []struct {
		name        string
		args        []string
		socket      int
		answer      string
		code        int
		stdout      string
		stderr      string // exact when exactStderr is set, otherwise a part
		exactStderr bool
	}{
		{name: "the token", answer: ok, code: exitOK, stdout: tok + "\n", exactStderr: true},
		{name: "an error answer", answer: `{"error":"consent_required"}` + "\n", code: exitRuntime, stderr: "consent_required\n", exactStderr: true},
		{name: "an error answer with --json", args: []string{"--json"}, answer: `{"error":"refused"}` + "\n", code: exitRuntime, stderr: "refused\n", exactStderr: true},
		{name: "a token without an expiry", answer: `{"access_token":"` + tok + `"}` + "\n", code: exitRuntime, stderr: "byward: downstream-token: "},
		{name: "no socket at the path", socket: noSocket, code: exitRuntime, stderr: "connect: no such file or directory"},
		{name: "no socket in the environment", socket: unset, code: exitConfig, stderr: "BYWARD_DOWNSTREAM_TOKEN_SOCKET is not set"},
		{name: "an unknown flag", args: []string{"--yaml"}, answer: ok, code: exitConfig, stderr: "usage: byward downstream-token [--json]"},
		{name: "an extra argument", args: []string{"--json", "now"}, answer: ok, code: exitConfig, stderr: "usage: byward downstream-token [--json]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var env []string
			var connected <-chan struct{}
			switch tc.socket {
			case answers:
				s := faketokensocket.Scripted(t, tc.answer)
				connected = s.Connected
				env = []string{"BYWARD_DOWNSTREAM_TOKEN_SOCKET=" + s.Path}
			case noSocket:
				env = []string{"BYWARD_DOWNSTREAM_TOKEN_SOCKET=" + filepath.Join(faketokensocket.Dir(t), "token.sock")}
			}
			code, stdout, stderr := runWith(append([]string{"downstream-token"}, tc.args...), env...)
			okStderr := stderr == tc.stderr || (!tc.exactStderr && strings.Contains(stderr, tc.stderr))
			if code != tc.code || stdout != tc.stdout || !okStderr {
				t.Fatalf("code %d (want %d)\nstdout %q (want %q)\nstderr %q (want %q)", code, tc.code, stdout, tc.stdout, stderr, tc.stderr)
			}
			if strings.Contains(stderr, tok) {
				t.Fatalf("the token reached stderr: %q", stderr)
			}
			if tc.code == exitConfig && connected != nil {
				select {
				case <-connected:
					t.Fatal("a usage mistake connected to the socket")
				default:
				}
			}
		})
	}
}

// --json prints the token and its expiry (RFC 3339, UTC) as one JSON object on one line.
func TestDownstreamTokenAsJSONHasTheTokenAndItsExpiry(t *testing.T) {
	// The expiry is given in another zone with a fraction of a second; it is printed in UTC, in seconds.
	path := faketokensocket.Scripted(t, `{"access_token":"tok","expires_at":"2026-11-08T15:00:00.5+02:00"}`+"\n").Path
	code, stdout, stderr := runWith([]string{"downstream-token", "--json"}, "BYWARD_DOWNSTREAM_TOKEN_SOCKET="+path)
	var got map[string]string
	if code != exitOK || stderr != "" || strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") ||
		json.Unmarshal([]byte(stdout), &got) != nil || got["access_token"] != "tok" || got["expires_at"] != "2026-11-08T13:00:00Z" {
		t.Fatalf("code %d, stdout %q, stderr %q; want the token and its expiry as one JSON line", code, stdout, stderr)
	}
}

// A socket that takes the request and never answers holds the command only for its wait.
func TestDownstreamTokenGivesUpAfterItsWait(t *testing.T) {
	wait := downstreamTokenWait
	downstreamTokenWait = 50 * time.Millisecond
	t.Cleanup(func() { downstreamTokenWait = wait })
	path := faketokensocket.Silent(t).Path
	done := make(chan struct{})
	var code int
	var stderr string
	go func() {
		code, _, stderr = runWith([]string{"downstream-token"}, "BYWARD_DOWNSTREAM_TOKEN_SOCKET="+path)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("downstream-token is still waiting long after its wait")
	}
	if code != exitRuntime || !strings.Contains(stderr, "context deadline exceeded") {
		t.Fatalf("code %d, stderr %q; want exit 1 for the wait that ended", code, stderr)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is closed") }

// A token that cannot be written is a failure, not a success with nothing printed.
func TestDownstreamTokenThatCannotBeWrittenExits1(t *testing.T) {
	const tok = "eyJ.unwritten.token"
	for name, args := range map[string][]string{"the token": nil, "the token as JSON": {"--json"}} {
		t.Run(name, func(t *testing.T) {
			path := faketokensocket.Scripted(t, `{"access_token":"`+tok+`","expires_at":"2026-11-08T13:00:00Z"}`+"\n").Path
			var stderr bytes.Buffer
			code := run(context.Background(), append([]string{"downstream-token"}, args...), []string{"BYWARD_DOWNSTREAM_TOKEN_SOCKET=" + path}, failingWriter{}, &stderr)
			if code != exitRuntime || !strings.Contains(stderr.String(), "writing the token: stdout is closed") || strings.Contains(stderr.String(), tok) {
				t.Fatalf("code %d, stderr %q; want exit 1 naming the write error, never the token", code, stderr.String())
			}
		})
	}
}

func TestHelpListsDownstreamToken(t *testing.T) {
	code, stdout, _ := runWith([]string{"--help"})
	if code != exitOK || !strings.Contains(stdout, "byward downstream-token [--json]") {
		t.Fatalf("code=%d help=%q", code, stdout)
	}
}
