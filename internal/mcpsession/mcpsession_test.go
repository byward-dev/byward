package mcpsession

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// proxy is one replica: Bind around up, with the user taken from the X-Test-User header the test
// sets in place of Guard.
type proxy struct {
	h     http.Handler
	audit *bytes.Buffer
}

func newProxy(b Box, upstreamID string, now *time.Time, up http.Handler) proxy {
	var buf bytes.Buffer
	log := slog.New(slog.DiscardHandler)
	h := Bind(Config{Box: b, Upstream: upstreamID, Lifetime: 30 * 24 * time.Hour, Now: func() time.Time { return *now },
		User: func(r *http.Request) (string, bool) {
			u := r.Header.Get("X-Test-User")
			return u, u != ""
		},
		Audit: audit.New(logging.New(&buf, "json"), nil, func() time.Time { return *now }), Log: log}, up)
	return proxy{h: h, audit: &buf}
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

func TestTheClientGetsASealedSessionIDNeverTheUpstreams(t *testing.T) {
	now := t0
	p := newProxy(box(t, keyDir(t, "k1"), "mcp-session", &now), upstreamURL, &now, &upstream{})
	id := p.initialize(t, alice)
	if !strings.HasPrefix(id, Prefix) || strings.Contains(id, upstreamSession) {
		t.Fatalf("client session ID %q: want a %s value that does not contain the upstream's", id, Prefix)
	}
	for _, c := range id {
		if c < 0x21 || c > 0x7e {
			t.Fatalf("session ID %q has %q: MCP requires visible ASCII (0x21–0x7E)", id, c)
		}
	}
}

// Every legacy-era request carries the session: POST, the GET stream and DELETE (ADR-0004 §2).
func TestTheOwnersSessionReachesTheUpstreamUnsealed(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			now := t0
			up := &upstream{}
			p := newProxy(box(t, keyDir(t, "k1"), "mcp-session", &now), upstreamURL, &now, up)
			id := p.initialize(t, alice)
			if w := p.do(t, method, alice, id); w.Code != http.StatusOK {
				t.Fatalf("%s with the owner's session: %d", method, w.Code)
			}
			if got := up.got[len(up.got)-1]; got != upstreamSession {
				t.Fatalf("upstream got session %q, want its own %q", got, upstreamSession)
			}
		})
	}
}

// A session ID that is not the caller's never reaches the upstream: 404, so the client starts a
// new session (MCP 2025-11-25 Session Management rules 3 and 4), and an audit record.
func TestASessionThatIsNotTheCallersGets404AndNeverReachesTheUpstream(t *testing.T) {
	cases := []struct {
		name   string
		id     func(t *testing.T, e *env) string
		reason string
	}{
		{"another user's session", func(t *testing.T, e *env) string { return e.p.initialize(t, bob) }, reasonOtherUser},
		{"another upstream's session", func(t *testing.T, e *env) string {
			return newProxy(e.box, "http://other:9000/mcp", &e.now, &upstream{}).initialize(t, alice)
		}, reasonOtherUpstream},
		{"tampered", func(t *testing.T, e *env) string {
			id := []byte(e.p.initialize(t, alice))
			id[len(id)-3] ^= 1
			return string(id)
		}, reasonInvalid},
		{"the upstream's own ID", func(*testing.T, *env) string { return upstreamSession }, reasonInvalid},
		{"sealed for another purpose", func(t *testing.T, e *env) string {
			other := box(t, e.dir, "consent", &e.now)
			plain, _ := json.Marshal(binding{Session: upstreamSession, User: alice, Upstream: upstreamURL})
			s, err := other.Seal(plain, e.now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			return Prefix + s
		}, reasonInvalid},
		{"expired", func(t *testing.T, e *env) string {
			id := e.p.initialize(t, alice)
			e.now = e.now.Add(30*24*time.Hour + time.Second)
			return id
		}, reasonInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			id := tc.id(t, e)
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

type env struct {
	dir string
	now time.Time
	box *token.Box
	up  *upstream
	p   proxy
}

func newEnv(t *testing.T) *env {
	e := &env{dir: keyDir(t, "k1"), now: t0, up: &upstream{}}
	e.box = box(t, e.dir, "mcp-session", &e.now)
	e.p = newProxy(e.box, upstreamURL, &e.now, e.up)
	return e
}

func TestRequestsWithoutASessionPassThrough(t *testing.T) {
	now := t0
	var got []string
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Values(Header) })
	p := newProxy(box(t, keyDir(t, "k1"), "mcp-session", &now), upstreamURL, &now, up)
	w := p.do(t, http.MethodPost, alice, "")
	if w.Code != http.StatusOK || len(got) != 0 || w.Header().Get(Header) != "" {
		t.Fatalf("status %d, upstream saw %q, client got %q; want it passed through untouched", w.Code, got, w.Header().Get(Header))
	}
}

func TestTwoSessionHeadersAreRefused(t *testing.T) {
	e := newEnv(t)
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
	id := newProxy(box(t, dir, "mcp-session", &now), upstreamURL, &now, &upstream{}).initialize(t, alice)
	addKey(t, dir, "2026-11-06") // sorts last: the new signing key
	up := &upstream{}
	other := newProxy(box(t, dir, "mcp-session", &now), upstreamURL, &now, up)
	if w := other.do(t, http.MethodPost, alice, id); w.Code != http.StatusOK || up.got[0] != upstreamSession {
		t.Fatalf("on another replica after a rotation: %d, upstream got %q", w.Code, up.got)
	}
}

// Responses stream: the wrapper must let the relay flush through it.
func TestStreamingResponsesCanFlushThroughTheBinding(t *testing.T) {
	now := t0
	var flushErr error
	up := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(Header, upstreamSession)
		_, _ = w.Write([]byte("event: message\n\n"))
		flushErr = http.NewResponseController(w).Flush()
	})
	p := newProxy(box(t, keyDir(t, "k1"), "mcp-session", &now), upstreamURL, &now, up)
	w := p.do(t, http.MethodGet, alice, "")
	if flushErr != nil || !w.Flushed || !strings.HasPrefix(w.Header().Get(Header), Prefix) {
		t.Fatalf("flush error %v, flushed %v, session %q", flushErr, w.Flushed, w.Header().Get(Header))
	}
}

func TestAnUnauthenticatedRequestNeverReachesTheUpstream(t *testing.T) {
	e := newEnv(t)
	if w := e.p.do(t, http.MethodPost, "", ""); w.Code != http.StatusUnauthorized || e.up.calls != 0 {
		t.Fatalf("status %d, upstream calls %d", w.Code, e.up.calls)
	}
}
