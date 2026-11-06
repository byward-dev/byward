//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
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
			stdout, output := runSigningIn(t, runCtx, cancelRun, env.browse, env.public+"/authorize?", cmd)
			if !strings.Contains(stdout, realClientText) {
				t.Fatalf("%s stdout lacks the tool's answer %q; output:\n%s", name, realClientText, output)
			}
			env.requireOneToolCallWithOnlyTheAssertion(t)
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

// docker runs args in image with the client's directory mounted at /w, as the calling user, plus
// any read-only mounts ("host path:container path"). The container is named and removed when the
// test ends: cancelling kills only the docker CLI.
func docker(ctx context.Context, t *testing.T, work, image, network string, env, args []string, readOnly ...string) *exec.Cmd {
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
	for _, m := range readOnly {
		a = append(a, "-v", m+":ro")
	}
	a = append(append(a, image), args...)
	return exec.CommandContext(ctx, "docker", a...) //nolint:gosec // G204: fixed images and the test's own arguments
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
