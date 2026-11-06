package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/token"
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
		seen = append(seen, r.Header.Get(mcpsession.Header))
		w.Header().Set(mcpsession.Header, "upstream-session-1")
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
			r.Header.Set(mcpsession.Header, session)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}

	res := post("tok-alice", "")
	id := res.Header.Get(mcpsession.Header)
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(id, mcpsession.Prefix) || strings.Contains(id, "upstream-session-1") {
		t.Fatalf("initialize: %d, session %q; want a sealed ID", res.StatusCode, id)
	}
	// The wiring: sealed with the mcp-session purpose, for alice and this upstream, for the grant
	// lifetime.
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		t.Fatal(err)
	}
	opensAt := func(at time.Time) ([]byte, error) {
		b, _ := token.NewBox(ring, "mcp-session", func() time.Time { return at })
		return b.Open(strings.TrimPrefix(id, mcpsession.Prefix))
	}
	plain, err := opensAt(time.Now().Add(broker.GrantLifetime - time.Hour))
	var bound struct{ S, U, X string }
	if err != nil || json.Unmarshal(plain, &bound) != nil || bound.U != "tid:alice" || bound.X != cfg.UpstreamURL.String() {
		t.Fatalf("the session ID opens as %s (%v); want alice and %s with the mcp-session purpose", plain, err, cfg.UpstreamURL)
	}
	if _, err := opensAt(time.Now().Add(broker.GrantLifetime + time.Hour)); err == nil {
		t.Fatal("the session ID outlives the grant lifetime")
	}
	if res := post("tok-alice", id); res.StatusCode != http.StatusOK || seen[len(seen)-1] != "upstream-session-1" {
		t.Fatalf("the owner's next request: %d, upstream saw %q", res.StatusCode, seen[len(seen)-1])
	}
	calls := len(seen)
	if res := post("tok-bob", id); res.StatusCode != http.StatusNotFound || len(seen) != calls {
		t.Fatalf("another user with that session: %d, upstream calls +%d; want 404 and none", res.StatusCode, len(seen)-calls)
	}
}

// Without a subject there is no user to bind a session to.
func TestAnIdentityWithoutASubjectIsNoSignedInUser(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if _, ok := signedInUser(r); ok {
		t.Fatal("a request without an identity counts as signed in")
	}
	var got, reached bool
	resource.Guard(resource.Metadata{Resource: &url.URL{Scheme: "https", Host: "mcp.example.com", Path: "/mcp"}}, twoUsers{"tok-nobody": ""}, nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		_, got = signedInUser(r)
	})).ServeHTTP(httptest.NewRecorder(), withBearer(r, "tok-nobody"))
	if !reached {
		t.Fatal("Guard refused the request, so this test proves nothing")
	}
	if got {
		t.Fatal("an identity with an empty subject counts as signed in")
	}
}

func withBearer(r *http.Request, tok string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}
