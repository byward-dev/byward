//go:build linux || darwin

package stdio

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
)

// stdioCell is what one lifecycle cell of the stdio bridge pins.
type stdioCell struct {
	status int      // the request line's status
	body   string   // in what the client was written ("" checks nothing)
	errTyp string   // the request line's error_type: why a started stream was cut off, or ""
	closes bool     // the answer closes its connection
	warns  []string // every WARN or ERROR line, by message, in any order, but a crash's
	alive  bool     // the cell's process outlives the request, with its MCP session (legacy) or userConn (modern)
	crash  bool     // the cell's process is killed: its exit is logged once, as unexpected, at WARN, and nothing stops it

}

// stdioRig is one bridge serving through logging.Middleware, as the server does, so a cell sees the
// request line.
type stdioRig struct {
	*bridgeHarness
	h         http.Handler
	modernEra bool          // the cell's requests are of the modern era: a process outlives them as a userConn, not an MCP session
	bound     time.Duration // how long check waits for the bridge to return: guard, or 100 times a real-time bound the cell sets
}

// newStdioRig serves the fake upstream in its legacy JSON-RPC mode, with flags.
func newStdioRig(t *testing.T, edit func(*Config), flags ...string) *stdioRig {
	t.Helper()
	return newRig(t, edit, false, append([]string{"-mcp"}, flags...)...)
}

// newModernRig serves the fake upstream as flags make it, to modern-era requests: "-modern" last,
// or a legacy server that the probe finds legacy.
func newModernRig(t *testing.T, edit func(*Config), flags ...string) *stdioRig {
	t.Helper()
	return newRig(t, edit, true, flags...)
}

func newRig(t *testing.T, edit func(*Config), modern bool, flags ...string) *stdioRig {
	t.Helper()
	b := newBridge(t, func(c *Config) {
		c.Command = append([]string{fakeBin}, flags...)
		if edit != nil {
			edit(c)
		}
	})
	return &stdioRig{bridgeHarness: b, h: logging.Middleware(slog.New(b.log), b.bridge), modernEra: modern, bound: guard}
}

// start serves a request as alice in the background on a writer read while it is written; the
// channel closes when the bridge has returned.
func (r *stdioRig) start(ctx context.Context, method, sid string, body io.Reader, header ...string) (*brokenWriter, <-chan struct{}) {
	req := httptest.NewRequestWithContext(ctx, method, "/", body)
	req.Header.Set("Accept", "application/json, text/event-stream")
	setHeaders(req.Header, "alice", sid, header...)
	w := &brokenWriter{header: http.Header{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.h.ServeHTTP(w, req)
	}()
	return w, done
}

// process is the one live process the cell started.
func (r *stdioRig) process(t *testing.T) *Process {
	t.Helper()
	var p *Process
	eventually(t, "the cell's process", func() bool {
		r.m.mu.Lock()
		defer r.m.mu.Unlock()
		p = nil
		for e := range r.m.live {
			if e.p != nil {
				p = e.p
			}
		}
		return p != nil && len(r.m.live) == 1
	})
	return p
}

// signal sends sig to the process the cell started.
func (r *stdioRig) signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(r.process(t).pid, sig); err != nil {
		t.Fatal(err)
	}
}

// held is what the bridge and its Manager hold: processes, MCP sessions, and what requests in
// flight hold of them.
type held struct {
	live, sessions, users, leases, streams, inFlight int
}

func (r *stdioRig) held() held {
	var h held
	r.m.mu.Lock()
	h.live = len(r.m.live)
	for _, e := range r.m.procs {
		h.leases += e.leases
		h.streams += e.streams
	}
	r.m.mu.Unlock()
	r.bridge.mu.Lock()
	sessions := make([]*session, 0, len(r.bridge.sessions))
	for _, s := range r.bridge.sessions {
		sessions = append(sessions, s)
	}
	users := make([]*userConn, 0, len(r.bridge.users))
	for _, c := range r.bridge.users {
		users = append(users, c)
	}
	r.bridge.mu.Unlock()
	h.sessions, h.users = len(sessions), len(users)
	for _, c := range users {
		c.mu.Lock()
		h.inFlight += len(c.byID) + len(c.byToken)
		c.mu.Unlock()
	}
	for _, s := range sessions {
		s.mu.Lock()
		h.inFlight += len(s.posts) + len(s.byID)
		if s.getStream != nil {
			h.inFlight++
		}
		s.mu.Unlock()
	}
	return h
}

// check waits for the bridge to return, then fails t unless the cell went as want says: the client
// got want.body, the request line and the warnings are want's, and nothing is left held but the
// process and its MCP session or userConn, if they outlive the request.
func (r *stdioRig) check(t *testing.T, w *brokenWriter, done <-chan struct{}, want stdioCell) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(r.bound):
		t.Fatal("the bridge never returned")
	}
	if !strings.Contains(w.written(), want.body) {
		t.Errorf("the client got %q; want %q in it", w.written(), want.body)
	}
	if closes := w.header.Get("Connection") == "close"; closes != want.closes {
		t.Errorf("Connection %q; want closing %v", w.header.Get("Connection"), want.closes)
	}
	lines := r.log.with("request")
	if len(lines) != 1 {
		t.Fatalf("%d request lines; want 1: %v", len(lines), lines)
	}
	errTyp, _ := lines[0].attrs["error_type"].(string)
	if status, _ := lines[0].attrs["status"].(int64); int(status) != want.status || errTyp != want.errTyp {
		t.Errorf("request line status %v error_type %q; want %d %q", lines[0].attrs["status"], errTyp, want.status, want.errTyp)
	}
	n := 0
	if want.alive {
		n = 1
	}
	baseline := held{live: n, sessions: n}
	if r.modernEra {
		baseline = held{live: n, users: n}
	}
	var got held
	deadline := time.Now().Add(guard) // what a request held is let go of by goroutines after it returns
	// A stopping process is sent SIGTERM, then SIGKILL, a KillGrace apart; a few graces take any
	// process there, and stay far below IdleTimeout, so no live process's idle timer fires.
	for graces := 0; ; {
		if got = r.held(); got == baseline || !time.Now().Before(deadline) {
			break
		}
		if graces < 4 && r.stopping() {
			r.clk.Advance(DefaultKillGrace)
			graces++
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got != baseline {
		t.Errorf("held %+v once the request ended; want %+v, nothing in flight", got, baseline)
	}
	wantWarns := slices.Sorted(slices.Values(want.warns))
	warns := func() []string {
		var out []string
		for _, rec := range r.log.warnings() {
			if want.crash && rec.msg == exited && len(r.log.with(exited)) == 1 {
				continue // crashLogged checks it
			}
			out = append(out, rec.msg)
		}
		slices.Sort(out)
		return out
	}
	logged := warns() // a process's exit is logged once it has been reaped, after it has left the Manager
	for deadline := time.Now().Add(guard); !slices.Equal(logged, wantWarns) && time.Now().Before(deadline); logged = warns() {
		time.Sleep(10 * time.Millisecond)
	}
	if !slices.Equal(logged, wantWarns) {
		t.Errorf("logged at WARN or above %q; want %q", logged, wantWarns)
	}
	if want.crash {
		r.crashLogged(t)
	}
}

// crashLogged fails t unless the killed process's exit was logged once, as unexpected, and no stop:
// a crashed process is reaped before the stdout_closed stop's grace (process.go) runs out.
func (r *stdioRig) crashLogged(t *testing.T) {
	t.Helper()
	eventually(t, "the process's exit to be logged", func() bool {
		return len(r.log.with(exited))+len(r.log.with("upstream process exited")) == 1
	})
	r.log.wantLoggedAsCrash(t)
}

// stopping reports whether a process byward is stopping has not exited yet.
func (r *stdioRig) stopping() bool {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	for e := range r.m.live {
		if p := e.p; p != nil {
			p.mu.Lock()
			s := p.stopping && !p.exited
			p.mu.Unlock()
			if s {
				return true
			}
		}
	}
	return false
}

// end ends ctx's request as e does. A shutdown drains the bridge first, as the server does
// (server/run.go).
func (r *stdioRig) end(e lifecycle.Ending, stop func()) {
	if e == lifecycle.Shutdown {
		r.bridge.Drain()
	}
	stop()
}

// endedAs is the ContextEndings entry for e; the relay's notStarted (relay/lifecycle_test.go) looks
// one up too.
func endedAs(e lifecycle.Ending) lifecycle.Ended {
	for _, c := range lifecycle.ContextEndings {
		if c.Ending == e {
			return c
		}
	}
	panic("no context ending " + e.String())
}

// endedCell is what a request that ends as e before it is answered pins: its answer, no warning.
func endedCell(e lifecycle.Ending, alive bool) stdioCell {
	c := endedAs(e)
	return stdioCell{status: c.Status, body: c.Body, closes: c.Closes, alive: alive}
}

// cutCell is what a stream that its request's end cuts off pins.
func cutCell(e lifecycle.Ending, alive bool) stdioCell {
	return stdioCell{status: http.StatusOK, errTyp: string(endedAs(e).Cut), alive: alive}
}

const (
	exited       = "upstream process exited unexpectedly"
	initFailed   = "initialize failed: no MCP session"
	cannotStart  = "cannot start the upstream process"
	sessionGone  = "session not found"
	unavailable  = "upstream unavailable"
	processEnded = `"code":-32603`
)

// bigInitialize and bigRequest are larger than any pipe buffer, and smaller than what fakestdio
// reads as one line, so a Send to a process that reads nothing waits with stdin full.
var (
	bigInitialize = strings.Replace(initialize, `"params":{`, `"params":{"pad":"`+strings.Repeat("a", 512<<10)+`",`, 1)
	bigRequest    = `{"jsonrpc":"2.0","id":2,"method":"echo","params":{"pad":"` + strings.Repeat("a", 512<<10) + `"}}`
)

// inFlight starts a request whose body the bridge is still reading: the client has sent its first
// byte and holds the rest.
func (r *stdioRig) inFlight(t *testing.T, ctx context.Context, sid, body string, header ...string) (*brokenWriter, <-chan struct{}, *io.PipeWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	w, done := r.start(ctx, http.MethodPost, sid, pr, header...)
	read := make(chan struct{})
	go func() {
		defer close(read)
		_, _ = io.WriteString(pw, body[:1]) // returns once the bridge has read it, or the pipe is closed
	}()
	select {
	case <-read:
	case <-done:
		_ = pw.Close()
		t.Fatalf("the bridge answered %q before it read the request body", w.written())
	case <-time.After(guard):
		_ = pw.Close()
		t.Fatal("the bridge never read the request body")
	}
	return w, done, pw
}

// bodyCut is a cell whose request ends while the bridge reads its body, and whose MCP client's
// connection then fails the read, as the server's does.
func (r *stdioRig) bodyCut(t *testing.T, end lifecycle.Ending, sid, body string, want stdioCell, header ...string) {
	t.Helper()
	ctx, stop := endedAs(end).Start(context.Background())
	w, done, pw := r.inFlight(t, ctx, sid, body, header...)
	r.end(end, stop)
	pw.CloseWithError(errors.New("connection reset by peer"))
	r.check(t, w, done, want)
}

// stdinFull is a cell whose request is being written to a process that reads none of it (stopped,
// or never reading), its stdin full, when the request ends as end; then resume lets the process go
// on. kill ends the process instead of the request.
func (r *stdioRig) stdinFull(t *testing.T, end lifecycle.Ending, sid, body string, before, resume func(), want stdioCell, header ...string) {
	t.Helper()
	ctx, stop := context.Background(), func() {}
	if end != lifecycle.UpstreamGone {
		ctx, stop = endedAs(end).Start(ctx)
	}
	before()
	w, done := r.start(ctx, http.MethodPost, sid, strings.NewReader(body), header...)
	waitUntilStdinIsNotWritable(t, r.process(t))
	if end == lifecycle.UpstreamGone {
		r.signal(t, syscall.SIGKILL)
	} else {
		r.end(end, stop)
	}
	resume()
	r.check(t, w, done, want)
}

// unreachable are the reasons every stdio transport shares.
const (
	completesWasSent = "a request that completes was sent to the upstream process"
	no1xx            = "the bridge never writes an interim (1xx) response"
	noTrailer        = "the bridge never sets a trailer"
	noUpgrade        = "the bridge reads no Upgrade and hijacks nothing, so such a request is an ordinary one, whose endings are the other columns'"
	noWriteBound     = "the only bound on a started stream is writeTimeout, 30 s of real time through SetWriteDeadline (sse.go), which the fake clock does not reach; a write that fails is the client-gone cell (TestAStdioStreamEndedByItsRequestIsRecordedAsCutOff, keep-alive row), and sse_test.go pins the deadline"
	noAnswerBound    = "nothing bounds the wait for the process's answer: a held lease stops the idle timer (Process.hold), and a request lease is never evicted; the client leaving or a shutdown ends the wait"
	noBodyBound      = "the bridge sets no bound on reading or sending a request: Send waits on its request alone, and the server's ReadTimeout bounds a stalled body"
)

// unreachableColumns marks the columns no stdio transport has.
func unreachableColumns(m map[lifecycle.Cell]lifecycle.Case) {
	for _, e := range lifecycle.Endings {
		m[lifecycle.Cell{Ending: e, State: lifecycle.After1xx}] = lifecycle.Unreachable(no1xx)
		m[lifecycle.Cell{Ending: e, State: lifecycle.TrailerPending}] = lifecycle.Unreachable(noTrailer)
		m[lifecycle.Cell{Ending: e, State: lifecycle.UpgradeRequested}] = lifecycle.Unreachable(noUpgrade)
	}
	m[lifecycle.Cell{Ending: lifecycle.Completes, State: lifecycle.NotStarted}] = lifecycle.Unreachable(completesWasSent)
}

func at(end lifecycle.Ending, state lifecycle.State) lifecycle.Cell {
	return lifecycle.Cell{Ending: end, State: state}
}

// The stdio bridge's lifecycle matrix (#672): for a legacy initialize, a request to its MCP session
// and the session's GET stream, and for a modern request and listen, every way the request ends
// crossed with every state its work can be in pins what the MCP client gets, the request line and
// the warnings, and that the request leaves nothing held: no lease, stream or entry in flight, and
// the process, with its MCP session or userConn, alive only if the cell says so.
func TestTheStdioBridgeLifecycleMatrix(t *testing.T) {
	t.Run("legacy initialize", func(t *testing.T) { lifecycle.Run(t, legacyInitializeMatrix()) })
	t.Run("legacy request", func(t *testing.T) { lifecycle.Run(t, legacyRequestMatrix()) })
	t.Run("legacy GET", func(t *testing.T) { lifecycle.Run(t, legacyGETMatrix()) })
	t.Run("modern request", func(t *testing.T) { lifecycle.Run(t, modernRequestMatrix()) })
	t.Run("modern listen", func(t *testing.T) { lifecycle.Run(t, modernListenMatrix()) })
}

func legacyInitializeMatrix() map[lifecycle.Cell]lifecycle.Case {
	m := map[lifecycle.Cell]lifecycle.Case{}
	unreachableColumns(m)
	for _, end := range []lifecycle.Ending{lifecycle.ClientGone, lifecycle.Shutdown} {
		m[at(end, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil)
			ctx, stop := endedAs(end).Start(context.Background())
			stop()
			w, done := r.start(ctx, http.MethodPost, "", strings.NewReader(initialize))
			r.check(t, w, done, endedCell(end, false))
		})
		m[at(end, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("its body is read", func(t *testing.T) {
				r := newStdioRig(t, nil)
				r.bodyCut(t, end, "", initialize, endedCell(end, false))
			})
			t.Run("it is sent", func(t *testing.T) { // the process stops: initialize_failed
				r := newStdioRig(t, nil, "-init=block")
				r.stdinFull(t, end, "", bigInitialize, func() {}, func() {}, endedCell(end, false))
			})
		})
		m[at(end, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil, "-init=hold")
			ctx, stop := endedAs(end).Start(context.Background())
			w, done := r.start(ctx, http.MethodPost, "", strings.NewReader(initialize))
			r.saidOnStderr(t, "holding initialize")
			r.end(end, stop)
			r.check(t, w, done, endedCell(end, false))
		})
		m[at(end, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil, "-init=lognhold")
			ctx, stop := endedAs(end).Start(context.Background())
			w, done := r.start(ctx, http.MethodPost, "", strings.NewReader(initialize))
			eventually(t, "the notification", func() bool { return strings.Contains(w.written(), "notifications/message") })
			r.end(end, stop)
			r.check(t, w, done, cutCell(end, false))
		})
	}
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		r.m.start = func(*exec.Cmd) error { return errors.New("exec: no such file") }
		w, done := r.start(context.Background(), http.MethodPost, "", strings.NewReader(initialize))
		r.check(t, w, done, stdioCell{status: http.StatusBadGateway, body: unavailable, warns: []string{cannotStart}})
	})
	m[at(lifecycle.Timeout, lifecycle.NotStarted)] = lifecycle.NotRun("SpawnTimeout is 30 s of real time around the spawn, which the start hook cannot see; TestStartThatOverrunsTheSpawnTimeoutKillsTheProcessAndLeavesNothingBehind pins it at the Manager")
	m[at(lifecycle.Completes, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		w, done, pw := r.inFlight(t, context.Background(), "", initialize)
		_, _ = io.WriteString(pw, initialize[1:])
		_ = pw.Close()
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"protocolVersion"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil, "-init=block")
		r.stdinFull(t, lifecycle.UpstreamGone, "", bigInitialize, func() {}, func() {},
			stdioCell{status: http.StatusBadGateway, body: unavailable, warns: []string{initFailed}, crash: true})
	})
	m[at(lifecycle.Timeout, lifecycle.BodyInFlight)] = lifecycle.Unreachable(noBodyBound)
	m[at(lifecycle.Completes, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil, "-init=hold")
		w, done := r.start(context.Background(), http.MethodPost, "", strings.NewReader(initialize))
		r.saidOnStderr(t, "holding initialize")
		r.signal(t, syscall.SIGUSR1)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"protocolVersion"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil, "-init=hold")
		w, done := r.start(context.Background(), http.MethodPost, "", strings.NewReader(initialize))
		r.saidOnStderr(t, "holding initialize")
		r.signal(t, syscall.SIGKILL)
		r.check(t, w, done, stdioCell{status: http.StatusBadGateway, body: unavailable, warns: []string{initFailed}, crash: true})
	})
	m[at(lifecycle.Timeout, lifecycle.AwaitingHeaders)] = lifecycle.Unreachable(noAnswerBound)
	m[at(lifecycle.Completes, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil, "-init=lognhold")
		w, done := r.start(context.Background(), http.MethodPost, "", strings.NewReader(initialize))
		eventually(t, "the notification", func() bool { return strings.Contains(w.written(), "notifications/message") })
		r.signal(t, syscall.SIGUSR1)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"protocolVersion"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil, "-init=lognhold")
		w, done := r.start(context.Background(), http.MethodPost, "", strings.NewReader(initialize))
		eventually(t, "the notification", func() bool { return strings.Contains(w.written(), "notifications/message") })
		r.signal(t, syscall.SIGKILL)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: processEnded, warns: []string{initFailed}, crash: true})
	})
	m[at(lifecycle.Timeout, lifecycle.Streaming)] = lifecycle.NotRun(noWriteBound)
	return m
}

// session starts the rig's MCP session, its initialize served past the matrix, and returns its ID;
// the request line it logged is set aside, so a cell sees only its own.
func (r *stdioRig) session(t *testing.T) string {
	t.Helper()
	sid := r.initialize(t, "alice")
	r.log.mu.Lock()
	*r.log.recs = (*r.log.recs)[:0]
	r.log.mu.Unlock()
	return sid
}

// sessionGoneCell is a session request whose process has gone: 404, the client starts a new one.
var sessionGoneCell = stdioCell{status: http.StatusNotFound, body: sessionGone, crash: true}

// crashed kills the session's process and waits for its MCP session to end.
func (r *stdioRig) crashed(t *testing.T) {
	t.Helper()
	r.signal(t, syscall.SIGKILL)
	eventually(t, "the MCP session to end", func() bool { return r.held().sessions == 0 })
}

func legacyRequestMatrix() map[lifecycle.Cell]lifecycle.Case {
	m := map[lifecycle.Cell]lifecycle.Case{}
	unreachableColumns(m)
	const toolsList = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	for _, end := range []lifecycle.Ending{lifecycle.ClientGone, lifecycle.Shutdown} {
		m[at(end, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil)
			sid := r.session(t)
			ctx, stop := endedAs(end).Start(context.Background())
			stop()
			w, done := r.start(ctx, http.MethodPost, sid, strings.NewReader(toolsList))
			r.check(t, w, done, endedCell(end, true))
		})
		m[at(end, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("its body is read", func(t *testing.T) {
				r := newStdioRig(t, nil)
				sid := r.session(t)
				r.bodyCut(t, end, sid, toolsList, endedCell(end, true))
			})
			t.Run("it is sent", func(t *testing.T) { // a message cut short stops the process: partial_write
				r := newStdioRig(t, nil)
				sid := r.session(t)
				r.stdinFull(t, end, sid, bigRequest, func() { r.signal(t, syscall.SIGSTOP) }, func() { r.signal(t, syscall.SIGCONT) }, endedCell(end, false))
			})
		})
		m[at(end, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil)
			sid := r.session(t)
			ctx, stop := endedAs(end).Start(context.Background())
			w, done := r.start(ctx, http.MethodPost, sid, strings.NewReader(holdBody))
			r.saidOnStderr(t, "holding")
			eventually(t, "the stream to start", w.hasStarted)
			r.end(end, stop)
			r.check(t, w, done, cutCell(end, true))
		})
	}
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		r.crashed(t)
		w, done := r.start(context.Background(), http.MethodPost, sid, strings.NewReader(toolsList))
		r.check(t, w, done, sessionGoneCell)
	})
	m[at(lifecycle.Timeout, lifecycle.NotStarted)] = lifecycle.Unreachable("a request to an MCP session never starts a process, and its lease of the session's has no bound")
	m[at(lifecycle.Completes, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		w, done, pw := r.inFlight(t, context.Background(), sid, toolsList)
		_, _ = io.WriteString(pw, toolsList[1:])
		_ = pw.Close()
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"id":2`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		r.stdinFull(t, lifecycle.UpstreamGone, sid, bigRequest, func() { r.signal(t, syscall.SIGSTOP) }, func() {}, sessionGoneCell)
	})
	m[at(lifecycle.Timeout, lifecycle.BodyInFlight)] = lifecycle.Unreachable(noBodyBound)
	for _, end := range lifecycle.Endings {
		m[at(end, lifecycle.AwaitingHeaders)] = lifecycle.Unreachable("the bridge sends a request's stream headers as soon as the request is sent (bridge.go request), so it is streaming once its body is")
	}
	m[at(lifecycle.Completes, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		w, done := r.start(context.Background(), http.MethodPost, sid, strings.NewReader(holdBody))
		r.saidOnStderr(t, "holding")
		eventually(t, "the stream to start", w.hasStarted)
		release := r.serve(context.Background(), http.MethodPost, "alice", sid, `{"jsonrpc":"2.0","id":3,"method":"release"}`)
		if release.Code != http.StatusOK {
			t.Fatalf("release: status %d", release.Code)
		}
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"released"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		w, done := r.start(context.Background(), http.MethodPost, sid, strings.NewReader(holdBody))
		r.saidOnStderr(t, "holding")
		eventually(t, "the stream to start", w.hasStarted)
		r.signal(t, syscall.SIGKILL)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: processEnded, crash: true})
	})
	m[at(lifecycle.Timeout, lifecycle.Streaming)] = lifecycle.NotRun(noWriteBound)
	return m
}

func legacyGETMatrix() map[lifecycle.Cell]lifecycle.Case {
	m := map[lifecycle.Cell]lifecycle.Case{}
	unreachableColumns(m)
	for _, end := range lifecycle.Endings {
		m[at(end, lifecycle.BodyInFlight)] = lifecycle.Unreachable("a GET has no body")
		m[at(end, lifecycle.AwaitingHeaders)] = lifecycle.Unreachable("a GET's stream starts as soon as its MCP session is leased (bridge.go get)")
	}
	for _, end := range []lifecycle.Ending{lifecycle.ClientGone, lifecycle.Shutdown} {
		m[at(end, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil)
			sid := r.session(t)
			ctx, stop := endedAs(end).Start(context.Background())
			stop()
			w, done := r.start(ctx, http.MethodGet, sid, http.NoBody)
			r.check(t, w, done, endedCell(end, true))
		})
		m[at(end, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
			r := newStdioRig(t, nil)
			sid := r.session(t)
			ctx, stop := endedAs(end).Start(context.Background())
			w, done := r.start(ctx, http.MethodGet, sid, http.NoBody)
			eventually(t, "the stream to start", w.hasStarted)
			r.end(end, stop)
			r.check(t, w, done, cutCell(end, true))
		})
	}
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		r.crashed(t)
		w, done := r.start(context.Background(), http.MethodGet, sid, http.NoBody)
		r.check(t, w, done, sessionGoneCell)
	})
	m[at(lifecycle.Timeout, lifecycle.NotStarted)] = lifecycle.Unreachable("a GET never starts a process, and its lease of its MCP session's has no bound")
	m[at(lifecycle.Completes, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) { // the client ends its MCP session
		r := newStdioRig(t, nil)
		sid := r.session(t)
		w, done := r.start(context.Background(), http.MethodGet, sid, http.NoBody)
		eventually(t, "the stream to start", w.hasStarted)
		r.endSession(t, sid)
		r.check(t, w, done, stdioCell{status: http.StatusOK})
	})
	// The crash is logged by the process (exited); the GET carries no answer to cut, so it ends as
	// a DELETE's does, with no error_type.
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		w, done := r.start(context.Background(), http.MethodGet, sid, http.NoBody)
		eventually(t, "the stream to start", w.hasStarted)
		r.signal(t, syscall.SIGKILL)
		r.check(t, w, done, stdioCell{status: http.StatusOK, crash: true})
	})
	// A quiet GET stream's process is evicted for a new MCP session past StreamIdleTimeout, under
	// the per-user cap: the GET ends, not cut, and the new session takes the process's place.
	m[at(lifecycle.Timeout, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newStdioRig(t, func(c *Config) {
			c.MaxPerUser = 1
			c.StreamIdleTimeout = streamIdle
		})
		sid := r.session(t)
		w, done := r.start(context.Background(), http.MethodGet, sid, http.NoBody)
		eventually(t, "the stream to start", w.hasStarted)
		r.clk.Advance(streamIdle)
		if next := r.post(t, "alice", "", initialize); next.StatusCode != http.StatusOK {
			t.Fatalf("a new MCP session past the stream idle timeout: status %d", next.StatusCode)
		}
		r.check(t, w, done, stdioCell{status: http.StatusOK, alive: true})
	})
	return m
}

// modernStart serves body as alice's modern-era request in the background, with the headers a
// compliant client sends.
func (r *stdioRig) modernStart(ctx context.Context, body string) (*brokenWriter, <-chan struct{}) {
	return r.start(ctx, http.MethodPost, "", strings.NewReader(body), modernHeaders(body)...)
}

// warm starts alice's process with a first modern request, served past the matrix; its log is set
// aside, as session's is, so a cell sees only its own.
func (r *stdioRig) warm(t *testing.T) {
	t.Helper()
	res := r.modern(t, "alice", modernBody(`0`, "echo", "", ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first modern request: status %d", res.StatusCode)
	}
	readEvents(t, res)
	r.log.mu.Lock()
	*r.log.recs = (*r.log.recs)[:0]
	r.log.mu.Unlock()
}

// cancelledUpstream waits until the upstream has seen the cell's request cancelled.
func (r *stdioRig) cancelledUpstream(t *testing.T) {
	t.Helper()
	if ids := r.awaitUpstreamCancellation(t); len(ids) != 1 {
		t.Errorf("upstream cancellations %q; want the cell's request alone", ids)
	}
}

func modernRequestMatrix() map[lifecycle.Cell]lifecycle.Case {
	m := map[lifecycle.Cell]lifecycle.Case{}
	unreachableColumns(m)
	echo := modernBody(`1`, "echo", "", `"tag":"lifecycle"`)
	hold := modernBody(`"h"`, "hold", `"progressToken":"p"`, "") // its token is routed (byToken) while it is held
	bigEcho := modernBody(`1`, "echo", "", `"pad":"`+strings.Repeat("a", 512<<10)+`"`)
	for _, end := range []lifecycle.Ending{lifecycle.ClientGone, lifecycle.Shutdown} {
		m[at(end, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("its process not yet started", func(t *testing.T) {
				r := newModernRig(t, nil, "-modern")
				ctx, stop := endedAs(end).Start(context.Background())
				stop()
				w, done := r.modernStart(ctx, echo)
				r.check(t, w, done, endedCell(end, false))
			})
			t.Run("the upstream already known legacy", func(t *testing.T) { // not legacyFallback's 400 (modernPost's cached verdict)
				r := newModernRig(t, nil, "-mcp")
				if res := r.modern(t, "alice", echo); res.StatusCode != http.StatusBadRequest {
					t.Fatalf("the first modern request to a legacy upstream: status %d, want 400", res.StatusCode)
				}
				eventually(t, "the legacy process to stop", func() bool { return r.held() == held{} })
				r.log.mu.Lock() // set aside, as session's is, so the cell sees only its own
				*r.log.recs = (*r.log.recs)[:0]
				r.log.mu.Unlock()
				ctx, stop := endedAs(end).Start(context.Background())
				stop()
				w, done := r.modernStart(ctx, echo)
				r.check(t, w, done, endedCell(end, false))
			})
		})
		m[at(end, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("its body is read", func(t *testing.T) {
				r := newModernRig(t, nil, "-modern")
				r.bodyCut(t, end, "", echo, endedCell(end, false), modernHeaders(echo)...)
			})
			t.Run("it is sent", func(t *testing.T) { // a message cut short stops the shared process: partial_write
				r := newModernRig(t, nil, "-modern")
				r.warm(t)
				r.stdinFull(t, end, "", bigEcho, func() { r.signal(t, syscall.SIGSTOP) }, func() { r.signal(t, syscall.SIGCONT) }, endedCell(end, false), modernHeaders(bigEcho)...)
			})
		})
		m[at(end, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("the upstream proves modern", func(t *testing.T) {
				r := newModernRig(t, nil, "-holddiscover", "-modern")
				ctx, stop := endedAs(end).Start(context.Background())
				w, done := r.modernStart(ctx, echo)
				r.saidOnStderr(t, "holding discover")
				r.end(end, stop)
				r.signal(t, syscall.SIGUSR1)
				r.check(t, w, done, endedCell(end, true))
			})
			t.Run("the upstream proves legacy", func(t *testing.T) { // not legacyFallback's 400; its process stops: not_modern
				r := newModernRig(t, nil, "-mcp", "-invaliddiscover", "-holddiscover")
				ctx, stop := endedAs(end).Start(context.Background())
				w, done := r.modernStart(ctx, echo)
				r.saidOnStderr(t, "holding discover")
				r.end(end, stop)
				r.signal(t, syscall.SIGUSR1)
				r.check(t, w, done, endedCell(end, false))
			})
		})
		m[at(end, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) { // cancelled upstream too
			r := newModernRig(t, nil, "-modern")
			ctx, stop := endedAs(end).Start(context.Background())
			w, done := r.modernStart(ctx, hold)
			eventually(t, "the stream to start", w.hasStarted)
			r.end(end, stop)
			r.check(t, w, done, cutCell(end, true))
			r.cancelledUpstream(t)
		})
	}
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		r.m.start = func(*exec.Cmd) error { return errors.New("exec: no such file") }
		w, done := r.modernStart(context.Background(), echo)
		r.check(t, w, done, stdioCell{status: http.StatusBadGateway, body: unavailable, warns: []string{cannotStart}})
	})
	m[at(lifecycle.Timeout, lifecycle.NotStarted)] = lifecycle.NotRun("SpawnTimeout is 30 s of real time around the spawn, which the start hook cannot see; TestStartThatOverrunsTheSpawnTimeoutKillsTheProcessAndLeavesNothingBehind pins it at the Manager")
	m[at(lifecycle.Completes, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		w, done, pw := r.inFlight(t, context.Background(), "", echo, modernHeaders(echo)...)
		_, _ = io.WriteString(pw, echo[1:])
		_ = pw.Close()
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"lifecycle"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		r.warm(t)
		r.stdinFull(t, lifecycle.UpstreamGone, "", bigEcho, func() { r.signal(t, syscall.SIGSTOP) }, func() {},
			stdioCell{status: http.StatusBadGateway, body: unavailable, warns: []string{relayFailed}, crash: true}, modernHeaders(bigEcho)...)
	})
	m[at(lifecycle.Timeout, lifecycle.BodyInFlight)] = lifecycle.Unreachable(noBodyBound)
	m[at(lifecycle.Completes, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-holddiscover", "-modern")
		w, done := r.modernStart(context.Background(), echo)
		r.saidOnStderr(t, "holding discover")
		r.signal(t, syscall.SIGUSR1)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"lifecycle"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-exitondiscover", "-modern")
		w, done := r.modernStart(context.Background(), echo)
		r.check(t, w, done, stdioCell{status: http.StatusBadGateway, body: unavailable, warns: []string{relayFailed}, crash: true})
	})
	// The probe's own bound, a field tests shorten, in real time: an upstream that never answers it
	// is taken for a legacy one. Waited on as an event, for up to 100 times it (r.bound). The
	// bound also covers sending the probe (modern.go discover): one that runs out before the send is
	// no verdict, a 502, so it is 500 ms, not the 50 ms a stalled machine could spend before it.
	m[at(lifecycle.Timeout, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-mcp", "-silentdiscover")
		r.bridge.probeTimeout = 500 * time.Millisecond
		r.bound = 100 * r.bridge.probeTimeout
		w, done := r.modernStart(context.Background(), echo)
		r.check(t, w, done, stdioCell{status: http.StatusBadRequest, body: "speaks MCP 2025-11-25"})
	})
	m[at(lifecycle.Completes, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		w, done := r.modernStart(context.Background(), hold)
		eventually(t, "the stream to start", w.hasStarted)
		readEvents(t, r.modern(t, "alice", modernBody(`"r"`, "release", "", "")))
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"released"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		w, done := r.modernStart(context.Background(), hold)
		eventually(t, "the stream to start", w.hasStarted)
		r.signal(t, syscall.SIGKILL)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: processEnded, crash: true})
	})
	m[at(lifecycle.Timeout, lifecycle.Streaming)] = lifecycle.NotRun(noWriteBound)
	return m
}

func modernListenMatrix() map[lifecycle.Cell]lifecycle.Case {
	m := map[lifecycle.Cell]lifecycle.Case{}
	unreachableColumns(m)
	const sameAsRequest = "a listen takes the modern request's path until it is sent (modern.go post, up to c.request): the modern request's cell pins it"
	for _, end := range lifecycle.Endings {
		for _, s := range []lifecycle.State{lifecycle.NotStarted, lifecycle.BodyInFlight, lifecycle.AwaitingHeaders} {
			if c := at(end, s); c != at(lifecycle.Completes, lifecycle.NotStarted) {
				m[c] = lifecycle.NotRun(sameAsRequest)
			}
		}
	}
	open := func(t *testing.T, r *stdioRig, ctx context.Context) (*brokenWriter, <-chan struct{}) {
		t.Helper()
		w, done := r.modernStart(ctx, listenBody)
		eventually(t, "the acknowledgement", w.acknowledged)
		return w, done
	}
	m[at(lifecycle.Completes, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) { // the upstream ends it
		r := newModernRig(t, nil, "-modern")
		w, done := open(t, r, context.Background())
		readEvents(t, r.modern(t, "alice", modernBody(`"e"`, "endlistens", "", "")))
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: completeResult, alive: true})
	})
	m[at(lifecycle.ClientGone, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		ctx, stop := endedAs(lifecycle.ClientGone).Start(context.Background())
		w, done := open(t, r, ctx)
		stop()
		r.check(t, w, done, cutCell(lifecycle.ClientGone, true))
		r.cancelledUpstream(t)
	})
	// The server ends the subscription: it says so with a completion result (2026-07-28
	// subscriptions), so the stream ends whole, not cut. Drain and the request's shutdown cause
	// each lead there; TestDrainCompletesAndCancelsUpstreamEachOpenListen… and
	// TestAListenEndedByTheProxyShuttingDown… pin each path.
	m[at(lifecycle.Shutdown, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		ctx, stop := endedAs(lifecycle.Shutdown).Start(context.Background())
		w, done := open(t, r, ctx)
		r.end(lifecycle.Shutdown, stop)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: completeResult, alive: true})
		r.cancelledUpstream(t)
	})
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, nil, "-modern")
		w, done := open(t, r, context.Background())
		r.signal(t, syscall.SIGKILL)
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: processEnded, crash: true})
	})
	// A quiet listen's process is evicted past StreamIdleTimeout for another user's, under the
	// process cap: the server ends the subscription, with its completion result.
	m[at(lifecycle.Timeout, lifecycle.Streaming)] = lifecycle.Pinned(func(t *testing.T) {
		r := newModernRig(t, func(c *Config) {
			c.MaxProcesses = 1
			c.StreamIdleTimeout = streamIdle
		}, "-modern")
		w, done := open(t, r, context.Background())
		r.clk.Advance(streamIdle)
		readEvents(t, r.modern(t, "bob", modernBody(`1`, "echo", "", "")))
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: completeResult, alive: true})
	})
	return m
}
