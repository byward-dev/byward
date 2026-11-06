package mcpsession

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/token"
)

const (
	upstreamURL     = "http://upstream:9000/mcp"
	upstreamSession = "upstream-session-1"
	alice           = "tid:alice"
	bob             = "tid:bob"
	lifetime        = 30 * 24 * time.Hour
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// keyDir writes sealing keys named ids into a new directory, as an operator would.
func keyDir(t *testing.T, ids ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, id := range ids {
		addKey(t, dir, id)
	}
	return dir
}

func addKey(t *testing.T, dir, id string) {
	t.Helper()
	k := make([]byte, token.KeySize)
	_, _ = rand.Read(k)
	if err := os.WriteFile(filepath.Join(dir, id), []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func box(t *testing.T, dir, purpose string, now *time.Time) *token.Box {
	t.Helper()
	ring, err := token.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := token.NewBox(ring, purpose, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// upstream records the session header it receives and answers every request with its session ID,
// as a legacy-era server does on initialize.
type upstream struct {
	calls int
	got   []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.calls++
	u.got = append(u.got, r.Header.Get(Header))
	w.Header().Set(Header, upstreamSession)
	w.WriteHeader(http.StatusOK)
}

// testUser stands in for Guard: the user is the X-Test-User header.
func testUser(r *http.Request) (string, bool) {
	u := r.Header.Get("X-Test-User")
	return u, u != ""
}

// proxy is one replica: Bind around an upstream, with its audit and operator logs.
type proxy struct {
	h          http.Handler
	audit, log *bytes.Buffer
}

func newProxy(b *token.Box, upstreamID string, now *time.Time, life time.Duration, up http.Handler) proxy {
	p := proxy{audit: &bytes.Buffer{}, log: &bytes.Buffer{}}
	p.h = Bind(Config{Box: b, Upstream: upstreamID, Lifetime: life, Now: func() time.Time { return *now }, User: testUser,
		Audit: audit.New(logging.New(p.audit, "json"), nil, func() time.Time { return *now }),
		Log:   slog.New(slog.NewJSONHandler(p.log, nil))}, up)
	return p
}

func (p proxy) do(t *testing.T, method, user, session string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/mcp", nil)
	if user != "" {
		r.Header.Set("X-Test-User", user)
	}
	if session != "" {
		r.Header.Set(Header, session)
	}
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	return w
}

// initialize returns the session ID the client is given.
func (p proxy) initialize(t *testing.T, user string) string {
	t.Helper()
	w := p.do(t, http.MethodPost, user, "")
	id := w.Header().Get(Header)
	if w.Code != http.StatusOK || id == "" {
		t.Fatalf("initialize: %d, session %q", w.Code, id)
	}
	return id
}

// env is one replica on a fresh key directory and clock; up is the recording upstream unless the
// test passes its own handler.
type env struct {
	dir string
	now time.Time
	box *token.Box
	up  *upstream
	p   proxy
}

func newEnv(t *testing.T, handler http.Handler) *env {
	t.Helper()
	e := &env{dir: keyDir(t, "k1"), now: t0, up: &upstream{}}
	e.box = box(t, e.dir, "mcp-session", &e.now)
	if handler == nil {
		handler = e.up
	}
	e.p = newProxy(e.box, upstreamURL, &e.now, lifetime, handler)
	return e
}

func TestTheClientGetsASealedSessionIDNeverTheUpstreams(t *testing.T) {
	e := newEnv(t, nil)
	id := e.p.initialize(t, alice)
	if !strings.HasPrefix(id, Prefix) || strings.Contains(id, upstreamSession) {
		t.Fatalf("client session ID %q: want a %s value that does not contain the upstream's", id, Prefix)
	}
	for _, c := range id {
		if c < 0x21 || c > 0x7e {
			t.Fatalf("session ID %q has %q: MCP requires visible ASCII (0x21–0x7E)", id, c)
		}
	}
}

// Informational responses (here 103 Early Hints) come before the final one, and net/http keeps the
// headers set before them. Either way the client gets the session ID sealed once: its next request
// reaches the upstream with the upstream's own ID.
func TestTheSessionIDIsSealedOnceAroundAnInformationalResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before bool // the upstream sets the session header before the 103 (and net/http keeps it)
	}{
		{"session header after the 103", false},
		{"session header only before the 103", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = append(got, r.Header.Get(Header))
				if tc.before {
					w.Header().Set(Header, upstreamSession)
				}
				w.Header().Set("Link", "</style.css>; rel=preload")
				w.WriteHeader(http.StatusEarlyHints)
				if !tc.before {
					w.Header().Set(Header, upstreamSession)
				}
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewServer(e.p.h)
			t.Cleanup(srv.Close)
			var early []string // the session header of each informational response the client saw
			trace := &httptrace.ClientTrace{Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
				early = append(early, h.Get(Header))
				return nil
			}}
			post := func(session string) *http.Response {
				r, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodPost, srv.URL+"/mcp", nil)
				r.Header.Set("X-Test-User", alice)
				if session != "" {
					r.Header.Set(Header, session)
				}
				res, err := http.DefaultClient.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_ = res.Body.Close()
				return res
			}
			res := post("")
			for _, h := range early {
				if strings.Contains(h, upstreamSession) {
					t.Fatalf("the 103 carried the upstream's session ID %q to the client", h)
				}
			}
			if tc.before && (len(early) != 1 || !strings.HasPrefix(early[0], Prefix)) {
				t.Fatalf("informational session headers %q: want one sealed value", early)
			}
			id := res.Header.Get(Header)
			if res.StatusCode != http.StatusOK || !strings.HasPrefix(id, Prefix) || strings.Contains(id, upstreamSession) {
				t.Fatalf("final response %d with session %q: want a sealed %s value", res.StatusCode, id, Prefix)
			}
			if res := post(id); res.StatusCode != http.StatusOK || got[len(got)-1] != upstreamSession {
				t.Fatalf("next request: %d, upstream got %q; want its own %q", res.StatusCode, got[len(got)-1], upstreamSession)
			}
		})
	}
}

// Every legacy-era request carries the session: POST, the GET stream and DELETE (ADR-0004 §2).
func TestTheOwnersSessionReachesTheUpstreamUnsealed(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			e := newEnv(t, nil)
			id := e.p.initialize(t, alice)
			if w := e.p.do(t, method, alice, id); w.Code != http.StatusOK {
				t.Fatalf("%s with the owner's session: %d", method, w.Code)
			}
			if got := e.up.got[len(e.up.got)-1]; got != upstreamSession {
				t.Fatalf("upstream got session %q, want its own %q", got, upstreamSession)
			}
		})
	}
}

func TestASessionIsAcceptedUntilItsLifetimeEnds(t *testing.T) {
	e := newEnv(t, nil)
	id := e.p.initialize(t, alice)
	e.now = e.now.Add(lifetime - time.Second)
	if w := e.p.do(t, http.MethodPost, alice, id); w.Code != http.StatusOK {
		t.Fatalf("a second before the lifetime ends: %d, want 200", w.Code)
	}
}

// sealedFor seals a binding the proxy would never issue itself, with box b.
func sealedFor(t *testing.T, b *token.Box, now time.Time, bind binding) string {
	t.Helper()
	plain, _ := json.Marshal(bind)
	s, err := b.Seal(plain, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return Prefix + s
}

// A session ID that is not the caller's never reaches the upstream: 404, so the client starts a
// new session (MCP 2025-11-25 Session Management rules 3 and 4), and an audit record.
func TestASessionThatIsNotTheCallersGets404AndNeverReachesTheUpstream(t *testing.T) {
	cases := []struct {
		name    string
		id      func(t *testing.T, e *env) string
		advance time.Duration // clock moves after the ID is made
		reason  string
	}{
		{"another user's session", func(t *testing.T, e *env) string { return e.p.initialize(t, bob) }, 0, reasonOtherUser},
		{"another upstream's session", func(t *testing.T, e *env) string {
			return newProxy(e.box, "http://other:9000/mcp", &e.now, lifetime, &upstream{}).initialize(t, alice)
		}, 0, reasonOtherUpstream},
		{"tampered", func(t *testing.T, e *env) string {
			id := []byte(e.p.initialize(t, alice))
			id[len(id)-3] ^= 1
			return string(id)
		}, 0, reasonInvalid},
		{"the upstream's own ID", func(*testing.T, *env) string { return upstreamSession }, 0, reasonInvalid},
		{"sealed for another purpose", func(t *testing.T, e *env) string {
			return sealedFor(t, box(t, e.dir, "consent", &e.now), e.now, binding{Session: upstreamSession, User: alice, Upstream: upstreamURL})
		}, 0, reasonInvalid},
		{"sealed without a session", func(t *testing.T, e *env) string {
			return sealedFor(t, e.box, e.now, binding{User: alice, Upstream: upstreamURL})
		}, 0, reasonInvalid},
		{"expired", func(t *testing.T, e *env) string { return e.p.initialize(t, alice) }, lifetime + time.Second, reasonInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			id := tc.id(t, e)
			e.now = e.now.Add(tc.advance)
			calls := e.up.calls
			w := e.p.do(t, http.MethodPost, alice, id)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status %d, want 404", w.Code)
			}
			if e.up.calls != calls {
				t.Fatal("the request reached the upstream")
			}
			var rec map[string]any
			for _, line := range strings.Split(strings.TrimSpace(e.p.audit.String()), "\n") {
				if strings.Contains(line, `"event":"session_rejected"`) {
					_ = json.Unmarshal([]byte(line), &rec)
				}
			}
			if rec["outcome"] != "failure" || rec["reason"] != tc.reason || rec["user_key"] != alice {
				t.Fatalf("audit %s: want session_rejected, failure, reason %q, user %s", e.p.audit.String(), tc.reason, alice)
			}
		})
	}
}

// If the binding cannot be sealed, the client gets no session ID at all, never the upstream's.
func TestAFailedSealNeverPassesTheUpstreamsSessionOn(t *testing.T) {
	e := newEnv(t, nil)
	p := newProxy(e.box, upstreamURL, &e.now, 0, e.up) // a box refuses to seal what expires at once
	w := p.do(t, http.MethodPost, alice, "")
	if got := w.Header().Values(Header); len(got) != 0 {
		t.Fatalf("client got session %q after a failed seal, want none", got)
	}
	if !strings.Contains(p.log.String(), "sealing the MCP session ID failed") {
		t.Fatalf("operator log %q: want the failure logged", p.log.String())
	}
}

func TestRequestsWithoutASessionPassThrough(t *testing.T) {
	var got []string
	e := newEnv(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Values(Header) }))
	w := e.p.do(t, http.MethodPost, alice, "")
	if w.Code != http.StatusOK || len(got) != 0 || w.Header().Get(Header) != "" {
		t.Fatalf("status %d, upstream saw %q, client got %q; want it passed through untouched", w.Code, got, w.Header().Get(Header))
	}
}

func TestTwoSessionHeadersAreRefused(t *testing.T) {
	e := newEnv(t, nil)
	id := e.p.initialize(t, alice)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("X-Test-User", alice)
	r.Header.Add(Header, id)
	r.Header.Add(Header, id)
	w := httptest.NewRecorder()
	calls := e.up.calls
	e.p.h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || e.up.calls != calls {
		t.Fatalf("status %d, upstream calls +%d; want 400 and no upstream call", w.Code, e.up.calls-calls)
	}
}

// The binding is stateless (ADR-0007 §3): another replica with the same keys accepts the session,
// also after the signing key rotated.
func TestASessionWorksOnAnotherReplicaAndAfterAKeyRotation(t *testing.T) {
	dir := keyDir(t, "2026-11-01")
	now := t0
	id := newProxy(box(t, dir, "mcp-session", &now), upstreamURL, &now, lifetime, &upstream{}).initialize(t, alice)
	addKey(t, dir, "2026-11-06") // sorts last: the new signing key
	up := &upstream{}
	other := newProxy(box(t, dir, "mcp-session", &now), upstreamURL, &now, lifetime, up)
	if w := other.do(t, http.MethodPost, alice, id); w.Code != http.StatusOK || up.got[0] != upstreamSession {
		t.Fatalf("on another replica after a rotation: %d, upstream got %q", w.Code, up.got)
	}
}

// Responses stream: the wrapper must let the relay flush through it.
func TestStreamingResponsesCanFlushThroughTheBinding(t *testing.T) {
	var flushErr error
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(Header, upstreamSession)
		_, _ = w.Write([]byte("event: message\n\n"))
		flushErr = http.NewResponseController(w).Flush()
	}))
	w := e.p.do(t, http.MethodGet, alice, "")
	if flushErr != nil || !w.Flushed || !strings.HasPrefix(w.Header().Get(Header), Prefix) {
		t.Fatalf("flush error %v, flushed %v, session %q", flushErr, w.Flushed, w.Header().Get(Header))
	}
}

func TestAnUnauthenticatedRequestNeverReachesTheUpstream(t *testing.T) {
	e := newEnv(t, nil)
	if w := e.p.do(t, http.MethodPost, "", ""); w.Code != http.StatusUnauthorized || e.up.calls != 0 {
		t.Fatalf("status %d, upstream calls %d", w.Code, e.up.calls)
	}
}
