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
	alive  bool     // the cell's process and its MCP session outlive the request
	// crash is a cell whose process is killed. Its exit is logged as unexpected, at WARN, unless
	// its stdout's end reached the bridge first: then it is logged as a stop for stdout_closed, at
	// INFO (crashLogged).
	crash bool
}

// stdioRig is one bridge serving through logging.Middleware, as the server does, so a cell sees the
// request line.
type stdioRig struct {
	*bridgeHarness
	h http.Handler
}

func newStdioRig(t *testing.T, edit func(*Config), flags ...string) *stdioRig {
	t.Helper()
	b := newBridge(t, func(c *Config) {
		c.Command = append([]string{fakeBin, "-mcp"}, flags...)
		if edit != nil {
			edit(c)
		}
	})
	return &stdioRig{bridgeHarness: b, h: logging.Middleware(slog.New(b.log), b.bridge)}
}

// start serves a request as alice in the background on a writer read while it is written; the
// channel closes when the bridge has returned.
func (r *stdioRig) start(ctx context.Context, method, sid string, body io.Reader) (*brokenWriter, <-chan struct{}) {
	req := httptest.NewRequestWithContext(ctx, method, "/", body)
	req.Header.Set("Accept", "application/json, text/event-stream")
	setHeaders(req.Header, "alice", sid)
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
	live, sessions, leases, streams, inFlight int
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
	r.bridge.mu.Unlock()
	h.sessions = len(sessions)
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
// process and its MCP session, if they outlive the request.
func (r *stdioRig) check(t *testing.T, w *brokenWriter, done <-chan struct{}, want stdioCell) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(guard):
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
	var got held
	deadline := time.Now().Add(guard) // what a request held is let go of by goroutines after it returns
	for got = r.held(); got != (held{live: n, sessions: n}) && time.Now().Before(deadline); got = r.held() {
		if r.stopping() { // a stopping process is sent SIGTERM, then SIGKILL, a KillGrace apart
			r.clk.Advance(DefaultKillGrace)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got != (held{live: n, sessions: n}) {
		t.Errorf("held %+v once the request ended; want %d process and MCP session, nothing in flight", got, n)
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

// crashLogged fails t unless the killed process's exit was logged once: as an unexpected exit,
// or, when its stdout's end reached the bridge before the exit was reaped, as a stop for
// stdout_closed and an expected exit. Which one is a race today: the cells are KnownResidual("#672")
// (crashRace) until the fix logs both as unexpected.
func (r *stdioRig) crashLogged(t *testing.T) {
	t.Helper()
	eventually(t, "the process's exit to be logged", func() bool {
		return len(r.log.with(exited))+len(r.log.with("upstream process exited")) == 1
	})
	if len(r.log.with(exited)) == 1 {
		return
	}
	if stops := r.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "stdout_closed" {
		t.Errorf("the killed process's exit was logged as expected, with stops %v; want it logged as unexpected, or stopped for stdout_closed", stops)
	}
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

// endedAs is the ContextEndings entry for e.
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
	cannotRead   = "cannot read the request body"
)

// bigInitialize and bigRequest are larger than any pipe buffer, and smaller than what fakestdio
// reads as one line, so a Send to a process that reads nothing waits with stdin full.
var (
	bigInitialize = strings.Replace(initialize, `"params":{`, `"params":{"pad":"`+strings.Repeat("a", 512<<10)+`",`, 1)
	bigRequest    = `{"jsonrpc":"2.0","id":2,"method":"echo","params":{"pad":"` + strings.Repeat("a", 512<<10) + `"}}`
)

// inFlight starts a request whose body the bridge is still reading: the client has sent its first
// byte and holds the rest.
func (r *stdioRig) inFlight(ctx context.Context, sid, body string) (*brokenWriter, <-chan struct{}, *io.PipeWriter) {
	pr, pw := io.Pipe()
	w, done := r.start(ctx, http.MethodPost, sid, pr)
	_, _ = io.WriteString(pw, body[:1]) // returns once the bridge has read it
	return w, done, pw
}

// bodyCut is a cell whose request ends while the bridge reads its body, and whose MCP client's
// connection then fails the read, as the server's does.
func (r *stdioRig) bodyCut(t *testing.T, end lifecycle.Ending, sid, body string, want stdioCell) {
	t.Helper()
	ctx, stop := endedAs(end).Start(context.Background())
	w, done, pw := r.inFlight(ctx, sid, body)
	r.end(end, stop)
	pw.CloseWithError(errors.New("connection reset by peer"))
	r.check(t, w, done, want)
}

// stdinFull is a cell whose request is being written to a process that reads none of it (stopped,
// or never reading), its stdin full, when the request ends as end; then resume lets the process go
// on. kill ends the process instead of the request.
func (r *stdioRig) stdinFull(t *testing.T, end lifecycle.Ending, sid, body string, before, resume func(), want stdioCell) {
	t.Helper()
	ctx, stop := context.Background(), func() {}
	if end != lifecycle.UpstreamGone {
		ctx, stop = endedAs(end).Start(ctx)
	}
	before()
	w, done := r.start(ctx, http.MethodPost, sid, strings.NewReader(body))
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
	crashRace        = "a killed process's exit is logged as unexpected, at WARN, only if it is reaped before the bridge reads its stdout's end; else the bridge stops it for stdout_closed and its exit is logged at INFO (process.go wait), so an operator loses a crash's warning; the cell accepts either until the fix makes it strict"
	bodyReadBug      = "a request whose MCP client goes away, or the proxy shuts down, while the bridge reads its body is answered 400 \"cannot read the request body\" (bridge.go post), not by how it ended (shutdown.AnswerIfEnded): 499, or 503 and close"
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

// The stdio bridge's lifecycle matrix (#672), legacy era: for an initialize, a request to its MCP
// session and the session's GET stream, every way the request ends crossed with every state its
// work can be in pins what the MCP client gets, the request line and the warnings, and that the
// request leaves nothing held: no lease, stream or entry in flight, and the process and MCP
// session alive only if the cell says so.
func TestTheStdioBridgeLifecycleMatrix(t *testing.T) {
	t.Run("legacy initialize", func(t *testing.T) { lifecycle.Run(t, legacyInitializeMatrix()) })
	t.Run("legacy request", func(t *testing.T) { lifecycle.Run(t, legacyRequestMatrix()) })
	t.Run("legacy GET", func(t *testing.T) { lifecycle.Run(t, legacyGETMatrix()) })
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
		m[at(end, lifecycle.BodyInFlight)] = lifecycle.KnownResidual("#672", bodyReadBug, func(t *testing.T) {
			t.Run("its body is read", func(t *testing.T) {
				r := newStdioRig(t, nil)
				r.bodyCut(t, end, "", initialize, stdioCell{status: http.StatusBadRequest, body: cannotRead})
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
		w, done, pw := r.inFlight(context.Background(), "", initialize)
		_, _ = io.WriteString(pw, initialize[1:])
		_ = pw.Close()
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"protocolVersion"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.BodyInFlight)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
	m[at(lifecycle.UpstreamGone, lifecycle.AwaitingHeaders)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
		m[at(end, lifecycle.BodyInFlight)] = lifecycle.KnownResidual("#672", bodyReadBug, func(t *testing.T) {
			t.Run("its body is read", func(t *testing.T) {
				r := newStdioRig(t, nil)
				sid := r.session(t)
				r.bodyCut(t, end, sid, toolsList, stdioCell{status: http.StatusBadRequest, body: cannotRead, alive: true})
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
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
		w, done, pw := r.inFlight(context.Background(), sid, toolsList)
		_, _ = io.WriteString(pw, toolsList[1:])
		_ = pw.Close()
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"id":2`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.BodyInFlight)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
		release := r.serve(context.Background(), http.MethodPost, "alice", sid, `{"jsonrpc":"2.0","id":3,"method":"release"}`)
		if release.Code != http.StatusOK {
			t.Fatalf("release: status %d", release.Code)
		}
		r.check(t, w, done, stdioCell{status: http.StatusOK, body: `"released"`, alive: true})
	})
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
		r := newStdioRig(t, nil)
		sid := r.session(t)
		w, done := r.start(context.Background(), http.MethodPost, sid, strings.NewReader(holdBody))
		r.saidOnStderr(t, "holding")
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
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
	m[at(lifecycle.UpstreamGone, lifecycle.Streaming)] = lifecycle.KnownResidual("#672", crashRace, func(t *testing.T) {
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
