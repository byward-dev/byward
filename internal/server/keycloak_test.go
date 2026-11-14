//go:build integration

package server

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

// keycloakImage is Keycloak 26.8.0 (quay.io, 2026-10-10), pinned by digest. Dependabot does not
// see Go constants: keep it at least 14 days old by the registry date when updating (ADR-0024 §5).
const keycloakImage = "quay.io/keycloak/keycloak:26.8.0@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741"

// keycloakStartup bounds Keycloak's start and realm import.
const keycloakStartup = 3 * time.Minute

// The generic OIDC adapter against a real Keycloak (ADR-0024 §1, §5): a user with the gated realm
// role signs in through byward's consent page and Keycloak's login form, redeems the code and
// refreshes; a user without the role is denied by the access gate. The realm role reaches the
// gate through a "User Realm Role" mapper named roles, as docs/how-to/oidc.md says.
func TestIntegrationKeycloakSignsAUserInAndRefreshes(t *testing.T) {
	if os.Getenv("BYWARD_REAL_CLIENTS") != "1" {
		t.Skip("set BYWARD_REAL_CLIENTS=1 to run Keycloak (needs Docker and the network)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("BYWARD_REAL_CLIENTS=1 but docker is not available: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	public := "http://" + ln.Addr().String()
	kc := startKeycloak(t, keycloakRealm(public+"/callback/keycloak"))
	issuer := kc + "/realms/byward"

	up := fakeupstream.New()
	t.Cleanup(up.Close)
	env := append(oidcEnv(t, "keycloak", issuer, "byward", keycloakClientSecret), "BYWARD_GATE_ROLES=mcp-user",
		"BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp")
	// Keycloak in start-dev serves http on loopback, which only development mode accepts.
	cfg, _, err := config.Load([]string{"--dev"}, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s.closeStore != nil {
			_ = s.closeStore()
		}
	})
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: s.Public.Handler, ReadHeaderTimeout: 10 * time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)

	t.Run("a user with the role signs in and refreshes", func(t *testing.T) {
		const verifier = "verifier-0123456789-0123456789-0123456789-abc"
		code := keycloakSignIn(t, public, "alice", http.StatusFound, verifier)
		tok := tokenRequest(t, public, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"test-app"},
			"redirect_uri": {"http://127.0.0.1:5555/callback"}, "code_verifier": {verifier}})
		if tok["access_token"] == nil || tok["refresh_token"] == nil {
			t.Fatalf("token response %v, want an access and a refresh token", tok)
		}
		// The upstream's assertion is byward's, for Keycloak's subject, with the realm role.
		c := verified(t, jwks(t, s.Public.Handler, ln.Addr().String()), mcpAssertion(t, public, "", up, tok["access_token"].(string)), cfg.UpstreamURL.String())
		if c["iss"] != public || c["sub"] == "" || c["sub"] == "alice" || c["client_id"] != "test-app" || !reflect.DeepEqual(c["roles"], []any{"mcp-user"}) {
			t.Fatalf("assertion claims %v", c)
		}
		// The proxy's refresh refreshes at Keycloak too (ADR-0006 §5).
		again := tokenRequest(t, public, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"test-app"}})
		if again["access_token"] == nil || again["refresh_token"] == tok["refresh_token"] {
			t.Fatalf("refresh response %v, want new tokens", again)
		}
	})
	t.Run("a user without the role is denied", func(t *testing.T) {
		keycloakSignIn(t, public, "bob", http.StatusForbidden, "verifier-0123456789-0123456789-0123456789-xyz")
	})
}

const keycloakClientSecret = "byward-test-secret"

// startKeycloak runs Keycloak with realm and returns its base URL once the realm's discovery
// answers. The container publishes one loopback port, so no host network is needed.
func startKeycloak(t *testing.T, realm map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	// The image runs Keycloak as its own user, which must read the realm: world-readable test data.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: a directory of non-secret test data the container reads
		t.Fatal(err)
	}
	data, _ := json.Marshal(realm)
	if err := os.WriteFile(filepath.Join(dir, "byward-realm.json"), data, 0o644); err != nil { //nolint:gosec // G306: a test realm the container reads
		t.Fatal(err)
	}
	name := containerName(t, "byward-keycloak-")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) //nolint:gosec // G204: our own container name
	// Docker picks the host port, so no other process can take it between choosing and binding.
	run := exec.Command("docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8080", //nolint:gosec // G204: a pinned image and our own arguments
		"-v", dir+":/opt/keycloak/data/import:ro", keycloakImage, "start-dev", "--import-realm")
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run keycloak: %v\n%s", err, out)
	}
	published, err := exec.Command("docker", "port", name, "8080/tcp").Output() //nolint:gosec // G204: our own container name
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	base := "http://" + strings.TrimSpace(strings.Split(string(published), "\n")[0])
	ctx, cancel := context.WithTimeout(context.Background(), keycloakStartup)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/realms/byward/.well-known/openid-configuration", nil)
		if res, err := http.DefaultClient.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return base
			}
		}
		select {
		case <-ctx.Done():
			logs, _ := exec.Command("docker", "logs", "--tail", "60", name).CombinedOutput() //nolint:gosec // G204: our own container name
			t.Fatalf("Keycloak did not serve the realm within %s:\n%s", keycloakStartup, logs)
		case <-time.After(2 * time.Second):
		}
	}
}

// keycloakRealm is the test realm: the proxy's confidential client with a realm-role mapper named
// roles, alice with the mcp-user role and bob without it.
func keycloakRealm(redirect string) map[string]any {
	user := func(name string, roles ...string) map[string]any {
		return map[string]any{"username": name, "enabled": true, "email": name + "@example.com", "emailVerified": true,
			"firstName": name, "lastName": "Test", "credentials": []any{map[string]any{"type": "password", "value": name + "-password", "temporary": false}},
			"realmRoles": roles, "requiredActions": []any{}}
	}
	return map[string]any{
		"realm": "byward", "enabled": true,
		"roles": map[string]any{"realm": []any{map[string]any{"name": "mcp-user"}}},
		"clients": []any{map[string]any{
			"clientId": "byward", "enabled": true, "protocol": "openid-connect", "publicClient": false,
			"clientAuthenticatorType": "client-secret", "secret": keycloakClientSecret,
			"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "redirectUris": []any{redirect},
			"attributes": map[string]any{"pkce.code.challenge.method": "S256"},
			"protocolMappers": []any{map[string]any{"name": "realm roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper",
				"config": map[string]any{"claim.name": "roles", "multivalued": "true", "jsonType.label": "String",
					"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}}},
		}},
		"users": []any{user("alice", "mcp-user"), user("bob")},
	}
}

var keycloakLoginForm = regexp.MustCompile(`<form[^>]*\baction="([^"]+)"`)

// keycloakSignIn plays the user's browser: byward's consent page, Keycloak's login form as user,
// and the callback, which must answer want. With 302 it returns the code for the client.
func keycloakSignIn(t *testing.T, public, user string, want int, verifier string) string {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1:5555/callback"}, "response_type": {"code"},
		"scope": {"mcp offline_access"}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}, "state": {"s"}}
	page, err := c.Get(public + "/authorize?" + q.Encode()) //nolint:gosec // G107: byward's own loopback address
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, page)
	if page.StatusCode != http.StatusOK || !strings.Contains(body, "sign in with Keycloak next") {
		t.Fatalf("consent page: %d, want the page naming Keycloak: %s", page.StatusCode, body)
	}
	b := &testBrowser{t: t, base: public, public: public, c: c} // with this sign-in's cookie jar
	toKeycloak, err := redirect("consent answer", http.StatusSeeOther)(b.allow(page, body), nil)
	if err != nil {
		t.Fatal(err)
	}
	login, err := c.Get(toKeycloak) //nolint:gosec // G107: the Keycloak authorization URL byward built from its discovery
	if err != nil {
		t.Fatal(err)
	}
	form := keycloakLoginForm.FindStringSubmatch(readAll(t, login))
	if login.StatusCode != http.StatusOK || form == nil {
		t.Fatalf("Keycloak login page: %d, no form", login.StatusCode)
	}
	creds := url.Values{"username": {user}, "password": {user + "-password"}, "credentialId": {""}}
	toCallback, err := redirect("Keycloak login", http.StatusFound)(c.PostForm(html.UnescapeString(form[1]), creds))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(toCallback, public+"/callback/keycloak?") {
		t.Fatalf("Keycloak returned to %s, want byward's /callback/keycloak", toCallback)
	}
	back, err := c.Get(toCallback) //nolint:gosec // G107: byward's own callback
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, back.Body)
	_ = back.Body.Close()
	if back.StatusCode != want {
		t.Fatalf("callback for %s: %d, want %d", user, back.StatusCode, want)
	}
	if want != http.StatusFound {
		return ""
	}
	loc, _ := url.Parse(back.Header.Get("Location"))
	return loc.Query().Get("code")
}

func tokenRequest(t *testing.T, public string, form url.Values) map[string]any {
	t.Helper()
	res, err := http.PostForm(public+"/token", form) //nolint:gosec // G107: byward's own loopback address
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", res.StatusCode, body)
	}
	return body
}
