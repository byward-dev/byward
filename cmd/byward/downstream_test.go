package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// answeringSocket is a token socket that answers one connection with answer, in a directory short
// enough for a socket path on macOS.
func answeringSocket(t *testing.T, answer string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "token.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Read(make([]byte, 64))
		_, _ = c.Write([]byte(answer))
	}()
	return path
}

// downstream-token prints the token alone (or with --json its expiry too) and nothing on stderr; an
// error answer is its code alone on stderr and exit 1; a usage mistake or no socket in the
// environment exits 2. The token is never on stderr.
func TestDownstreamTokenPrintsTheTokenOrTheErrorCode(t *testing.T) {
	const tok = "eyJ.downstream.token"
	const ok = `{"access_token":"` + tok + `","expires_at":"2026-11-08T13:00:00Z"}` + "\n"
	cases := []struct {
		name        string
		args        []string
		answer      string // "" serves no socket; "-" leaves the variable unset
		code        int
		stdout      string
		stderr      string // exact when exact is set, otherwise a part
		exactStderr bool
	}{
		{"the token", nil, ok, exitOK, tok + "\n", "", true},
		{"the token as JSON", []string{"--json"}, ok, exitOK, ok, "", true},
		{"an error answer", nil, `{"error":"consent_required"}` + "\n", exitRuntime, "", "consent_required\n", true},
		{"an error answer with --json", []string{"--json"}, `{"error":"refused"}` + "\n", exitRuntime, "", "refused\n", true},
		{"an answer that is not one", nil, `{"access_token":"` + tok + `"}` + "\n", exitRuntime, "", "neither a token nor an error code", false},
		{"no socket at the path", nil, "", exitRuntime, "", "byward: downstream-token: token socket:", false},
		{"no socket in the environment", nil, "-", exitConfig, "", "BYWARD_DOWNSTREAM_TOKEN_SOCKET is not set", false},
		{"an unknown flag", []string{"--yaml"}, ok, exitConfig, "", "usage: byward downstream-token [--json]", false},
		{"an extra argument", []string{"--json", "now"}, ok, exitConfig, "", "usage: byward downstream-token [--json]", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var env []string
			switch tc.answer {
			case "-":
			case "":
				env = []string{"BYWARD_DOWNSTREAM_TOKEN_SOCKET=" + filepath.Join(t.TempDir(), "token.sock")}
			default:
				env = []string{"BYWARD_DOWNSTREAM_TOKEN_SOCKET=" + answeringSocket(t, tc.answer)}
			}
			code, stdout, stderr := runWith(append([]string{"downstream-token"}, tc.args...), env...)
			okStderr := stderr == tc.stderr || (!tc.exactStderr && strings.Contains(stderr, tc.stderr))
			if code != tc.code || stdout != tc.stdout || !okStderr {
				t.Fatalf("code %d (want %d)\nstdout %q (want %q)\nstderr %q (want %q)", code, tc.code, stdout, tc.stdout, stderr, tc.stderr)
			}
			if strings.Contains(stderr, tok) {
				t.Fatalf("the token reached stderr: %q", stderr)
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
