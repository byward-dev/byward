//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
// pointed at a fake, and an http issuer needs --dev). The fakes listen on loopback, so the container runs on the host network: Linux only.
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
	data := filepath.Join(work, "data")
	for _, d := range []string{data, filepath.Join(data, "keys"), filepath.Join(data, "assertion-keys")} {
		if err := os.Mkdir(d, 0o700); err != nil {
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
	ca := filepath.Join(work, "ca")
	if err := os.Mkdir(ca, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ca, "fakeidp.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate().Raw}), 0o600); err != nil { // the proxy runs as our uid
		t.Fatal(err)
	}
	listen, internal := freePort(t), freePort(t)
	name := randomName(t)
	run := exec.Command("docker", "run", "-d", "--name", name, "--network", "host", //nolint:gosec // G204: fixed docker command; the image is the caller's
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", data+":/var/lib/byward",
		"-v", secret+":/run/secrets/oidc-client-secret:ro",
		"-v", ca+":/etc/byward/ca:ro",
		"-e", "SSL_CERT_DIR=/etc/byward/ca",
		"-e", "BYWARD_PUBLIC_URL="+public+"/mcp",
		"-e", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp",
		"-e", "BYWARD_IDP=oidc",
		"-e", "BYWARD_OIDC_ISSUER="+idp.Issuer(),
		"-e", "BYWARD_OIDC_CLIENT_ID="+app.ID,
		"-e", "BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret",
		"-e", "BYWARD_GATE_ALLOW_EMPTY=true",
		"-e", "BYWARD_LISTEN=127.0.0.1:"+strconv.Itoa(listen),
		"-e", "BYWARD_INTERNAL_LISTEN=127.0.0.1:"+strconv.Itoa(internal),
		image)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() { // the proxy's own log says why; it never logs tokens or secrets
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput() //nolint:gosec // G204: our container
			t.Logf("container log:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: our container
	})

	awaitReady(t, name, "http://127.0.0.1:"+strconv.Itoa(internal)+"/readyz")
	base := "http://127.0.0.1:" + strconv.Itoa(listen)
	mcp := func(token string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		r.Host = "mcp.example.com"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}

	if res := mcp(""); res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("unauthenticated MCP request: %d, WWW-Authenticate %q; want 401 naming resource_metadata",
			res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}

	b := newTestBrowser(t, base, public)
	const verifier = "verifier-0123456789-0123456789-0123456789-abc"
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"}, "scope": {"mcp"},
		"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
	page := b.send(http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
	allow := b.allow(page, readAll(t, page))
	idpRes, err := idp.HTTPClient().Get(allow.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, err := url.Parse(idpRes.Header.Get("Location"))
	if err != nil || cb.Path != "/callback/oidc" {
		t.Fatalf("the IdP sent the browser to %q, want the proxy's callback", idpRes.Header.Get("Location"))
	}
	back := b.send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, allow.Cookies())
	done, _ := url.Parse(back.Header.Get("Location"))
	s := &oidcSession{b: b}
	s.tokens(t, url.Values{"grant_type": {"authorization_code"}, "code": {done.Query().Get("code")}, "client_id": {"test-app"},
		"redirect_uri": {"http://127.0.0.1/callback"}, "code_verifier": {verifier}})

	if res := mcp(s.access); res.StatusCode != http.StatusOK {
		t.Fatalf("signed-in MCP request: %d, want 200", res.StatusCode)
	}
	got, ok := up.Last()
	if !ok {
		t.Fatal("the upstream got no request")
	}
	raw, _ := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
	target, _ := url.Parse(base)
	verified(t, jwks(t, httputil.NewSingleHostReverseProxy(target), "mcp.example.com"), raw, up.URL+"/mcp")
}

// awaitReady polls url until it answers 200, failing early if the container has stopped.
func awaitReady(t *testing.T, name, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), imageReadyTimeout)
	defer cancel()
	for {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if res, err := http.DefaultClient.Do(r); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		state, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output() //nolint:gosec // G204: our container
		if strings.TrimSpace(string(state)) != "true" {
			t.Fatal("the container stopped before it was ready")
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s did not answer 200 within %s", url, imageReadyTimeout)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// randomName is a container name no other run uses.
func randomName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "byward-image-smoke-" + hex.EncodeToString(b)
}
