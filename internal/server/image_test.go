//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

// imageReadyTimeout bounds the wait for the container's /readyz: the image is local, so this is the
// proxy's start-up, which takes well under a second when it works.
const imageReadyTimeout = 30 * time.Second

// #278: the release image serves, not only `--version`. scripts/image-smoke.sh (`mise run
// release:smoke`) runs this against the snapshot image, started the README way: as the caller's
// uid and gid, the data directory mounted on /var/lib/byward, the client secret a read-only file.
// The data directory is laid out as the quickstarts do (a sealing key, an assertion key and the
// static clients file); the proxy must create its store there, answer an unauthenticated MCP
// request with the challenge, sign a user in through the IdP, and relay one MCP request with the
// identity assertion. The IdP is the fake generic OIDC one over https (Entra's endpoints cannot be
// pointed at a fake, and an http issuer needs --dev). The fakes listen on loopback, so the
// container runs on the host network: Linux only.
func TestIntegrationTheReleaseImageServes(t *testing.T) {
	image := os.Getenv("BYWARD_IMAGE")
	if image == "" {
		t.Skip("set BYWARD_IMAGE to the image to run (scripts/image-smoke.sh does)")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the container reaches the fakes on loopback, which needs a Linux host network (--network host)")
	}
	const public = "https://mcp.example.com"
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/oidc"}}
	idp := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app), fakeidp.WithTLS())

	work := t.TempDir()
	data, ca := filepath.Join(work, "data"), filepath.Join(work, "ca")
	for _, d := range []string{data, filepath.Join(data, "keys"), filepath.Join(data, "assertion-keys"), ca} {
		if err := os.Mkdir(d, 0o700); err != nil { // the proxy runs as our uid
			t.Fatal(err)
		}
	}
	write := func(p, content string) string {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sealing := make([]byte, 32)
	if _, err := rand.Read(sealing); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(data, "keys", "2026-11-13"), base64.StdEncoding.EncodeToString(sealing))
	assertionkey.Write(t, filepath.Join(data, "assertion-keys"), "2026-11-13", false)
	write(filepath.Join(data, "clients.json"), `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`)
	secret := write(filepath.Join(work, "oidc-client-secret"), "s3cret")
	// The proxy trusts the fake's certificate through SSL_CERT_DIR, which Go reads beside the
	// image's own CA bundle, not instead of it.
	write(filepath.Join(ca, "fakeidp.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate().Raw})))

	ports := freePorts(t, 2)
	listen, internal := ports[0], ports[1]
	env := []string{
		"SSL_CERT_DIR=/etc/byward/ca",
		"BYWARD_PUBLIC_URL=" + public + "/mcp",
		"BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
		"BYWARD_IDP=oidc",
		"BYWARD_OIDC_ISSUER=" + idp.Issuer(),
		"BYWARD_OIDC_CLIENT_ID=" + app.ID,
		"BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret",
		"BYWARD_GATE_ALLOW_EMPTY=true",
		"BYWARD_LISTEN=127.0.0.1:" + strconv.Itoa(listen),
		"BYWARD_INTERNAL_LISTEN=127.0.0.1:" + strconv.Itoa(internal),
	}
	name := containerName(t, "byward-image-smoke-")
	args := []string{"run", "-d", "--name", name, "--network", "host", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", data + ":/var/lib/byward", "-v", secret + ":/run/secrets/oidc-client-secret:ro", "-v", ca + ":/etc/byward/ca:ro"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	// Before the run: a run that fails after creating the container still leaves it behind.
	t.Cleanup(func() {
		if t.Failed() { // the proxy's own log says why; it never logs tokens or secrets
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput() //nolint:gosec // G204: our container
			t.Logf("container log:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: our container
	})
	if out, err := exec.Command("docker", append(args, image)...).CombinedOutput(); err != nil { //nolint:gosec // G204: fixed docker command; the image is the caller's
		t.Fatalf("docker run: %v\n%s", err, out)
	}

	awaitReady(t, name, "http://127.0.0.1:"+strconv.Itoa(internal)+"/readyz")
	base := "http://127.0.0.1:" + strconv.Itoa(listen)

	r, _ := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Host = "mcp.example.com"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("unauthenticated MCP request: %d, WWW-Authenticate %q; want 401 naming resource_metadata",
			res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}

	b := newTestBrowser(t, base, public)
	const verifier = "verifier-0123456789-0123456789-0123456789-abc"
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"}, "scope": {"mcp"},
		"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
	page := b.send(http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
	allow := b.allow(page, readAll(t, page))
	// The proxy reaches the IdP here (discovery, over https), so a trust failure shows as this answer.
	if allow.StatusCode != http.StatusSeeOther || !strings.HasPrefix(allow.Header.Get("Location"), idp.Issuer()) {
		t.Fatalf("consent answer: %d, want a redirect to the IdP at %s", allow.StatusCode, idp.Issuer())
	}
	back := b.viaIdP(idp, allow)
	done, err := url.Parse(back.Header.Get("Location"))
	if back.StatusCode != http.StatusFound || err != nil || done.Host != "127.0.0.1" || done.Path != "/callback" || done.Query().Get("code") == "" {
		t.Fatalf("callback: %d to %s://%s%s, want a redirect to the client's callback with a code", back.StatusCode, done.Scheme, done.Host, done.Path)
	}
	s := &oidcSession{b: b}
	s.tokens(t, url.Values{"grant_type": {"authorization_code"}, "code": {done.Query().Get("code")}, "client_id": {"test-app"},
		"redirect_uri": {"http://127.0.0.1/callback"}, "code_verifier": {verifier}})

	raw := mcpAssertion(t, base, "mcp.example.com", up, s.access)
	target, _ := url.Parse(base)
	verified(t, jwks(t, httputil.NewSingleHostReverseProxy(target), "mcp.example.com"), raw, up.URL+"/mcp")
	if fi, err := os.Stat(filepath.Join(data, "state")); err != nil || !fi.IsDir() {
		t.Fatalf("the store is not in the mounted data directory (%v)", err)
	}
}

// awaitReady polls url until it answers 200, failing early if the container has stopped.
func awaitReady(t *testing.T, name, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), imageReadyTimeout)
	defer cancel()
	var last string // the last answer or error, for the timeout
	for {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if res, err := http.DefaultClient.Do(r); err != nil {
			last = err.Error()
		} else {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
			last = res.Status
		}
		state, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output() //nolint:gosec // G204: our container
		switch {
		case err != nil:
			t.Fatalf("docker inspect %s: %v", name, err)
		case strings.TrimSpace(string(state)) != "true":
			t.Fatal("the container stopped before it was ready")
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s did not answer 200 within %s; last: %s", url, imageReadyTimeout, last)
		case <-time.After(200 * time.Millisecond):
		}
	}
}
