package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"slices"
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
	cfg, srv := bindingProxy(t, up.URL, twoUsers{"tok-alice": "tid:alice", "tok-bob": "tid:bob"})
	post := func(token, session string) *http.Response {
		t.Helper()
		r := mcpRequest(context.Background(), srv, token, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
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

// bindingProxy wires the proxy (Guard, the session binding and the relay) in front of the upstream at
// upstreamURL for users, and returns its configuration and server.
func bindingProxy(t *testing.T, upstreamURL string, users twoUsers) (*config.Config, *httptest.Server) {
	t.Helper()
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+upstreamURL+"/mcp")
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	srv := httptest.NewServer(Handler(cfg, discard, httpUpstream(cfg, discard), users, nil, a.sessions, Observability{}))
	t.Cleanup(srv.Close)
	return cfg, srv
}

// mcpRequest is a POST of body to srv's MCP endpoint with the token, as an MCP client sends it.
func mcpRequest(ctx context.Context, srv *httptest.Server, token, body string) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	r.Host = "mcp.example.com"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r
}

// Invariant 13 at the wire level: an upstream's Mcp-Session-Id sent as a response trailer, announced
// or not, never reaches the MCP client, nor does any other trailer; the session it sends as a header
// still reaches the client sealed.
func TestAnUpstreamSessionSentAsATrailerNeverReachesTheClient(t *testing.T) {
	const raw = "upstream-trailer-session"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(mcpsession.Header, "upstream-session-1")
		w.Header().Set("Trailer", mcpsession.Header+", X-Announced")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		w.Header().Set(mcpsession.Header, raw) // announced: becomes the trailer
		w.Header().Set("X-Announced", "upstream")
		w.Header().Set(http.TrailerPrefix+"X-Unannounced", raw)
		w.Header().Set(http.TrailerPrefix+"Set-Cookie", "upstream=1")
	}))
	t.Cleanup(up.Close)
	// The control: straight from the upstream, the client gets the trailers.
	direct, err := http.Post(up.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, direct.Body)
	_ = direct.Body.Close()
	if direct.Trailer.Get(mcpsession.Header) != raw || direct.Trailer.Get("X-Announced") != "upstream" ||
		direct.Trailer.Get("X-Unannounced") != raw || direct.Trailer.Get("Set-Cookie") != "upstream=1" {
		t.Fatalf("the upstream sent trailers %v, want its raw session in them", direct.Trailer)
	}

	_, srv := bindingProxy(t, up.URL, twoUsers{"tok-alice": "tid:alice"})
	res, err := http.DefaultClient.Do(mcpRequest(context.Background(), srv, "tok-alice", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body) // trailers arrive at the end of the body
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Fatalf("status %d, body %s", res.StatusCode, body)
	}
	if len(res.Trailer) != 0 { // an announced trailer is listed here too, even with no value
		t.Fatalf("trailers %v reached the client", res.Trailer)
	}
	if id := res.Header.Get(mcpsession.Header); !strings.HasPrefix(id, mcpsession.Prefix) || len(res.Header.Values(mcpsession.Header)) != 1 {
		t.Fatalf("session %q, want one sealed ID", res.Header.Values(mcpsession.Header))
	}
	for k, v := range res.Header {
		if slices.ContainsFunc(v, func(s string) bool { return strings.Contains(s, raw) }) {
			t.Fatalf("the upstream's trailer session reached the client in %s: %q", k, v)
		}
	}
}

// Through the session binding, an upstream's 103 reaches the MCP client with its Mcp-Session-Id
// sealed and nothing else but Link: never Set-Cookie or the headers the relay cleans. The final
// response still carries the proxy's own CORS answer and request ID.
func TestAnUpstreamsEarlyHintsReachTheClientSealedAndClean(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(mcpsession.Header, "upstream-hint-session")
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.Header().Set("Set-Cookie", "up=1")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Set-Cookie")
		w.Header().Del("Access-Control-Allow-Origin")
		w.Header().Del("Link")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(up.Close)
	_, srv := bindingProxy(t, up.URL, twoUsers{"tok-alice": "tid:alice"})
	var hint http.Header
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			hint = http.Header(h).Clone()
		}
		return nil
	}}
	r := mcpRequest(httptrace.WithClientTrace(context.Background(), trace), srv, "tok-alice", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	r.Header.Set("Origin", "https://mcp.example.com")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || hint == nil {
		t.Fatalf("status %d, 103 %v; want a 103 before the 200", res.StatusCode, hint)
	}
	id := hint.Get(mcpsession.Header)
	if !strings.HasPrefix(id, mcpsession.Prefix) || hint.Get("Link") == "" || len(hint) != 2 {
		t.Fatalf("the 103 reached the client with %v; want only Link and a sealed session", hint)
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "https://mcp.example.com" || res.Header.Get("X-Request-Id") == "" {
		t.Fatalf("final headers %v; want the proxy's CORS answer and request ID after the 103", res.Header)
	}
}
