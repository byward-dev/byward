package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/token"
)

// The operator's client denylist reaches the access-token check (#338): a token of a denied CIMD
// client ID is refused at its next MCP request, before the upstream sees it; another client's
// token still passes.
func TestADeniedClientIDsAccessTokenIsRefused(t *testing.T) {
	const denied = "https://evil.example/client.json"
	a := newAsserting(t, "BYWARD_CLIENT_DENYLIST="+denied)
	for clientID, want := range map[string]int{
		denied:                            http.StatusUnauthorized,
		"https://app.example/client.json": http.StatusOK,
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
		rec := httptest.NewRecorder()
		a.public.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("client %s: %d %s, want %d", clientID, rec.Code, rec.Body, want)
		}
	}
}
