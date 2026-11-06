package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/resource"
)

// twoUsers accepts one token per user.
type twoUsers map[string]string

func (u twoUsers) Validate(_ context.Context, tok string) (resource.Identity, error) {
	if sub, ok := u[tok]; ok {
		return resource.Identity{Subject: sub}, nil
	}
	return resource.Identity{}, resource.ErrInvalid
}

// Invariant 13 end to end: through Guard, the wired session binding and the relay, a legacy-era
// session is usable by the user who started it and by no one else.
func TestALegacySessionIsBoundToTheUserWhoStartedIt(t *testing.T) {
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Mcp-Session-Id"))
		w.Header().Set("Mcp-Session-Id", "upstream-session-1")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp")
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	srv := httptest.NewServer(Handler(cfg, discard, twoUsers{"tok-alice": "tid:alice", "tok-bob": "tid:bob"}, nil, a.sessions, Observability{}))
	t.Cleanup(srv.Close)
	post := func(token, session string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		r.Host = "mcp.example.com"
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			r.Header.Set("Mcp-Session-Id", session)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}

	res := post("tok-alice", "")
	id := res.Header.Get("Mcp-Session-Id")
	if res.StatusCode != http.StatusOK || id == "" || strings.Contains(id, "upstream-session-1") {
		t.Fatalf("initialize: %d, session %q; want a sealed ID", res.StatusCode, id)
	}
	if res := post("tok-alice", id); res.StatusCode != http.StatusOK || seen[len(seen)-1] != "upstream-session-1" {
		t.Fatalf("the owner's next request: %d, upstream saw %q", res.StatusCode, seen[len(seen)-1])
	}
	calls := len(seen)
	if res := post("tok-bob", id); res.StatusCode != http.StatusNotFound || len(seen) != calls {
		t.Fatalf("another user with that session: %d, upstream calls +%d; want 404 and none", res.StatusCode, len(seen)-calls)
	}
}
