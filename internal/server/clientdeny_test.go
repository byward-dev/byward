package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/token"
)

// The operator's client denylist reaches the proxy-token check (#338): a proxy token of a denied
// CIMD client ID is refused at its next MCP request, before the upstream sees it. Another client's
// proxy token still passes, and so does one of a DCR client whose host is denied: the check does
// not look the client up, so that proxy token runs out within its hour.
func TestADeniedClientIDsProxyTokenIsRefused(t *testing.T) {
	const denied = "https://evil.example/client.json"
	a := newAsserting(t, "BYWARD_CLIENT_DENYLIST="+denied+",app.example")
	for clientID, want := range map[string]int{
		denied:                              http.StatusUnauthorized,
		"https://other.example/client.json": http.StatusOK,
		registration.DCRIDPrefix + "app":    http.StatusOK, // a DCR client returning to app.example
	} {
		now := time.Now()
		tok, err := a.sealer.Seal(token.Access, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: clientID, Roles: []string{"byward.user"},
			IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "Bearer "+tok)
		before := len(a.up.Requests())
		rec := httptest.NewRecorder()
		a.public.ServeHTTP(rec, r)
		reached := len(a.up.Requests()) > before
		switch {
		case rec.Code != want:
			t.Errorf("client %s: %d %s, want %d", clientID, rec.Code, rec.Body, want)
		case want == http.StatusUnauthorized && (reached || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)):
			t.Errorf("client %s: upstream reached %v, WWW-Authenticate %q: want a refusal before the upstream, with invalid_token", clientID, reached, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

// The denylist never refuses a static client, so an entry that names one is a mistake the proxy
// refuses to start with, naming the setting (#338).
func TestADenylistEntryNamingAStaticClientStopsTheProxyStarting(t *testing.T) {
	const id = "https://static.example/client.json"
	clients := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(clients, []byte(`{"clients":[{"client_id":"`+id+`","client_name":"Static","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadConfig(t, "https://m.example/mcp", "BYWARD_STATIC_CLIENTS_FILE="+clients, "BYWARD_CLIENT_DENYLIST="+id)
	if _, err := New(cfg, logging.New(io.Discard, "json")); err == nil || !strings.Contains(err.Error(), "BYWARD_CLIENT_DENYLIST") || !strings.Contains(err.Error(), "static client") {
		t.Fatalf("New with a denylist entry naming a static client: %v, want an error naming BYWARD_CLIENT_DENYLIST and the static client", err)
	}
}
