//go:build integration

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pythonImage is pinned by digest. The node image is read from the conformance lane's pin
// (nodeImage), so the two lanes cannot drift apart and scripts/test-pins-check.sh, which flags
// newer releases of that pin, covers both. Dependabot watches the clients' lockfiles.
const pythonImage = "python:3.13.16-slim@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f"

// nodeImage returns the `image=` pin of scripts/conformance/run.sh.
func nodeImage(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "conformance", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if img, ok := strings.CutPrefix(line, "image="); ok && strings.Contains(img, "@sha256:") {
			return img
		}
	}
	t.Fatal("scripts/conformance/run.sh has no digest-pinned image= line")
	return ""
}

// Image names in containerClients; "node" is resolved by nodeImage.
const nodeImageRef = "node"

// Per-client budgets. Three clients in sequence stay inside the lane's `go test -timeout 11m`, so
// a slow registry fails the client it slowed, with that client's output.
const (
	installBudget = 90 * time.Second
	runBudget     = 90 * time.Second
)

var npmCI = []string{"npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--fetch-retries=5", "--fetch-retry-mintimeout=2000"}

// containerClient is a real open-source MCP client run in a pinned container: its dependencies are
// installed from the committed lockfile, then it runs on the host network, so it reaches byward
// on 127.0.0.1 and the harness reaches its loopback callback.
type containerClient struct {
	dir     string   // under testdata/realclients
	image   string   //
	install []string // in the client's directory, with network
	run     func(mcpURL, clientID string, port int, text string) []string
	env     []string
}

var containerClients = map[string]containerClient{
	// @modelcontextprotocol/sdk 1.32.2 (package-lock.json).
	"TypeScriptSDK": {dir: "ts", image: nodeImageRef, install: npmCI,
		run: func(u, id string, port int, text string) []string {
			return []string{"node", "client.mjs", u, id, strconv.Itoa(port), text}
		}},
	// mcp 2.3.0 (requirements.txt, hashes, wheels only).
	"PythonSDK": {dir: "python", image: pythonImage,
		install: []string{"pip", "install", "--quiet", "--no-cache-dir", "--disable-pip-version-check", "--require-hashes", "--no-deps",
			"--only-binary", ":all:", "--target", "/w/site", "-r", "requirements.txt"},
		run: func(u, id string, port int, text string) []string {
			return []string{"python", "client.py", u, id, strconv.Itoa(port), text}
		},
		env: []string{"PYTHONPATH=/w/site"}},
	// @modelcontextprotocol/inspector 2.12.0 (package-lock.json), its CLI's own OAuth sign-in. Its
	// OAuth runs on the v2 SDK (@modelcontextprotocol/client 2.3.1), a second client code path.
	"InspectorCLI": {dir: "inspector", image: nodeImageRef, install: npmCI,
		run: func(u, id string, port int, text string) []string {
			return []string{"node", "node_modules/@modelcontextprotocol/inspector/clients/launcher/build/index.js", "--cli", u,
				"--method", "tools/call", "--tool-name", echoTool, "--tool-arg", "text=" + text,
				"--client-id", id, "--callback-url", fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", port), "--format", "json"}
		},
		// Headless sign-in: no TTY, so the CLI needs this to start interactive OAuth at all.
		env: []string{"MCP_AUTO_OPEN_ENABLED=true", "MCP_STORAGE_DIR=/tmp/inspector"}},
}

// ADR-0024 §3: each real open-source client signs in through byward (static registration, PKCE,
// the consent page and the fake IdP), calls the upstream's tool, and no token reaches the upstream.
// Docker and the network are needed, so the tests run only with BYWARD_REAL_CLIENTS=1 (the
// integration-go CI job sets it).
func TestIntegrationRealClientsSignInAndCallATool(t *testing.T) {
	requireRealClients(t)
	for name, c := range containerClients {
		t.Run(name, func(t *testing.T) {
			env := newRealClientEnv(t)
			image := c.image
			if image == nodeImageRef {
				image = nodeImage(t)
			}
			work := t.TempDir()
			if err := os.CopyFS(work, os.DirFS(filepath.Join("testdata", "realclients", c.dir))); err != nil {
				t.Fatal(err)
			}
			installCtx, cancelInstall := context.WithTimeout(context.Background(), installBudget)
			defer cancelInstall()
			if out, err := docker(installCtx, t, work, image, "bridge", nil, c.install).CombinedOutput(); err != nil {
				t.Fatalf("installing %s from its lockfile: %v%s\n%s", name, err, budgetNote(installCtx, installBudget), out)
			}
			runCtx, cancelRun := context.WithTimeout(context.Background(), runBudget)
			defer cancelRun()
			cmd := docker(runCtx, t, work, image, "host", c.env, c.run(env.MCPURL, realClientID, freePort(t), realClientText))
			stdout := runSigningIn(t, runCtx, cancelRun, env.browse, cmd)
			if !strings.Contains(stdout, realClientText) {
				t.Fatalf("%s output lacks the tool's answer %q:\n%s", name, realClientText, stdout)
			}
			env.requireOneToolCallWithoutToken(t)
		})
	}
}

func requireRealClients(t *testing.T) {
	t.Helper()
	if os.Getenv("BYWARD_REAL_CLIENTS") != "1" {
		t.Skip("set BYWARD_REAL_CLIENTS=1 to run the real clients (needs Docker, the network and a Linux host network)")
	}
	if runtime.GOOS != "linux" {
		// Docker Desktop's --network host is its VM's network: the client would not reach byward.
		t.Skip("the containerised clients need a Linux host network (--network host)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("BYWARD_REAL_CLIENTS=1 but docker is not available: %v", err)
	}
}

// docker runs args in image with the client's directory mounted at /w, as the calling user. The
// container is named and removed when the test ends: cancelling kills only the docker CLI.
func docker(ctx context.Context, t *testing.T, work, image, network string, env, args []string) *exec.Cmd {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "byward-real-client-" + hex.EncodeToString(b)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) //nolint:gosec // G204: our own container name
	a := []string{"run", "--rm", "--name", name, "--network", network, "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp", "-e", "npm_config_cache=/tmp/npm", "-v", work + ":/w", "-w", "/w"}
	for _, e := range env {
		a = append(a, "-e", e)
	}
	a = append(append(a, image), args...)
	return exec.CommandContext(ctx, "docker", a...) //nolint:gosec // G204: fixed images and the test's own arguments
}

// runSigningIn runs a client and plays its browser: on the line "Please navigate to: <URL>" it
// signs in with browse and requests the client's callback. A failed step cancels the client, so
// the test fails at once with the client's output. It returns the client's stdout.
func runSigningIn(t *testing.T, ctx context.Context, cancel context.CancelFunc, browse func(string) (string, error), cmd *exec.Cmd) string {
	t.Helper()
	var stdout, stderrLog bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	callback := &http.Client{Timeout: 30 * time.Second}
	var signIns int
	var stepErr error
	lines := bufio.NewScanner(stderr)
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		line := lines.Text()
		stderrLog.WriteString(line + "\n")
		_, url, ok := strings.Cut(line, "Please navigate to: ")
		if !ok || stepErr != nil {
			continue
		}
		signIns++
		if stepErr = signIn(callback, browse, strings.TrimSpace(url)); stepErr != nil {
			cancel()
		}
	}
	scanErr := lines.Err()
	waitErr := cmd.Wait()
	switch {
	case stepErr != nil:
		t.Fatalf("sign-in: %v\nstdout:\n%s\nstderr:\n%s", stepErr, stdout.String(), stderrLog.String())
	case scanErr != nil:
		t.Fatalf("reading the client's stderr: %v\nstderr:\n%s", scanErr, stderrLog.String())
	case waitErr != nil:
		t.Fatalf("client: %v%s\nstdout:\n%s\nstderr:\n%s", waitErr, budgetNote(ctx, runBudget), stdout.String(), stderrLog.String())
	case signIns != 1:
		t.Fatalf("sign-ins: %d, want exactly 1\nstderr:\n%s", signIns, stderrLog.String())
	}
	return stdout.String()
}

// signIn plays the browser for one authorization URL and delivers the redirect to the client.
func signIn(callback *http.Client, browse func(string) (string, error), authorize string) error {
	redirect, err := browse(authorize)
	if err != nil {
		return fmt.Errorf("scripted browser: %w", err)
	}
	res, err := callback.Get(redirect) //nolint:gosec // G107: the client's own loopback callback
	if err != nil {
		return fmt.Errorf("the client's callback %s: %w", redirect, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode >= http.StatusBadRequest {
		return errors.New("the client's callback answered " + res.Status)
	}
	return nil
}

// budgetNote names an expired budget, so a hang is not read as a crash ("signal: killed").
func budgetNote(ctx context.Context, budget time.Duration) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Sprintf(" (its %s budget ran out)", budget)
	}
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
