//go:build linux || darwin

package stdio

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeBin is the fake stdio upstream (internal/testutil/fakestdio), built once for the package.
var fakeBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fakestdio-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakeBin = filepath.Join(dir, "fakestdio")
	build := exec.Command("go", "build", "-o", fakeBin, "../../testutil/fakestdio") //nolint:gosec // G204: fixed go command; fakeBin is our temp path
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build fake upstream: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// guard bounds every wait on a real process, so a hang fails the test instead of the run.
const guard = 10 * time.Second

var (
	alice = Identity{Subject: "tid-1:oid-alice", Issuer: "https://idp.example/tid-1/v2.0"}
	bob   = Identity{Subject: "tid-1:oid-bob", Issuer: "https://idp.example/tid-1/v2.0"}
	carol = Identity{Subject: "tid-1:oid-carol", Issuer: "https://idp.example/tid-1/v2.0"}
)

// proxyEnv is the proxy's own environment as the tests see it: two allowlisted variables and
// two that must never reach an upstream process.
var proxyEnv = map[string]string{
	"PATH":                  "/usr/bin:/bin",
	"LANG":                  "C.UTF-8",
	"BYWARD_SIGNING_KEY":    "proxy-secret",
	"AWS_SECRET_ACCESS_KEY": "cloud-secret",
}

func lookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

type harness struct {
	m   *Manager
	log *recorder
	clk *fakeClock
}

// newHarness returns a Manager for the fake upstream; edit adjusts the config first. Processes
// left at the end of the test are killed.
func newHarness(t *testing.T, edit func(*Config)) *harness {
	t.Helper()
	h := &harness{log: &recorder{mu: &sync.Mutex{}, recs: &[]record{}}, clk: newFakeClock()}
	cfg := Config{
		Name: "fake", Command: []string{fakeBin}, Log: slog.New(h.log), Clock: h.clk,
		LookupEnv: lookup(proxyEnv), TempDir: t.TempDir(),
	}
	if edit != nil {
		edit(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.m = m
	t.Cleanup(func() { h.killAll(t) })
	return h
}

func (h *harness) killAll(t *testing.T) {
	h.m.mu.Lock()
	var ps []*Process
	for e := range h.m.live { // not procs: an evicted process leaves procs before it has exited
		if e.p != nil {
			ps = append(ps, e.p)
		}
	}
	h.m.mu.Unlock()
	for _, p := range ps {
		_ = syscall.Kill(-p.pid, syscall.SIGKILL)
		waitDone(t, p)
	}
}

// get returns the process for key with its lease already released, so it is idle.
func (h *harness) get(t *testing.T, key string, id Identity) *Process {
	t.Helper()
	p, release := h.lease(t, key, id)
	release()
	return p
}

// lease returns the process for key and its lease.
func (h *harness) lease(t *testing.T, key string, id Identity) (*Process, func()) {
	t.Helper()
	p, release, err := h.m.Get(context.Background(), key, id)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	return p, release
}

// call sends msg and returns the next stdout message.
func call(t *testing.T, p *Process, msg string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), guard)
	defer cancel()
	if err := p.Send(ctx, []byte(msg)); err != nil {
		t.Fatalf("Send(%q): %v", msg, err)
	}
	select {
	case got, ok := <-p.Messages():
		if !ok {
			t.Fatalf("stdout closed after %q", msg)
		}
		return string(got)
	case <-time.After(guard):
		t.Fatalf("no reply to %q", msg)
		return ""
	}
}

func waitDone(t *testing.T, p *Process) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(guard):
		t.Fatalf("process %d did not exit", p.pid)
	}
}

func isDone(p *Process) bool {
	select {
	case <-p.Done():
		return true
	default:
		return false
	}
}

// record is one captured log record, attributes flattened (including those added by With).
type record struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// recorder is a slog.Handler that keeps records for assertions; it stands in for the proxy's
// logging package.
type recorder struct {
	mu    *sync.Mutex
	recs  *[]record
	attrs []slog.Attr
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	m := map[string]any{}
	for _, a := range r.attrs {
		m[a.Key] = a.Value.Any()
	}
	rec.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.Any(); return true })
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.recs = append(*r.recs, record{level: rec.Level, msg: rec.Message, attrs: m})
	return nil
}

func (r *recorder) WithAttrs(as []slog.Attr) slog.Handler {
	c := *r
	c.attrs = append(append([]slog.Attr{}, r.attrs...), as...)
	return &c
}

func (r *recorder) WithGroup(string) slog.Handler { return r }

// with returns the records with message msg.
func (r *recorder) with(msg string) []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []record
	for _, rec := range *r.recs {
		if rec.msg == msg {
			out = append(out, rec)
		}
	}
	return out
}

// fakeClock fires timers only when Advance moves past them. Callbacks run on the caller of
// Advance, without the clock's lock held, so they may create timers.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c      *fakeClock
	at     time.Time
	f      func()
	active bool
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), f: f, active: true}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.at, t.active = t.c.now.Add(d), true
	return was
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.active = false
	return was
}

// Advance moves time forward by d, firing due timers in order, including ones they create.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if t.active && !t.at.After(target) && (next == nil || t.at.Before(next.at)) {
				next = t
			}
		}
		if next == nil {
			break
		}
		c.now, next.active = next.at, false
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = target
	c.mu.Unlock()
}
