package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/shutdown"
	"github.com/byward-dev/byward/internal/testutil/closedport"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// after1xxTimeout is the header timeout of the timeout × after-1xx cell. A 1xx does not reset the
// transport's header timer, so the relayed 1xx must reach the client inside it; headerTimeout's
// 50 ms lets a stalled machine fire the timer first.
const after1xxTimeout = 500 * time.Millisecond

// boundFor is how long a cell waits for an event: 100 times its header timeout (headerTimeout for a
// cell without one), so a loaded machine running -race -count=50 does not flake, nothing asserts how
// short a wait was, and a package of failing cells still names each before the test binary's timeout.
func boundFor(timeout time.Duration) time.Duration { return 100 * max(timeout, headerTimeout) }

// toolsList is the request every cell sends: one a header timeout answers with a JSON-RPC error.
const toolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

// relayCell is what one cell of the relay's matrix pins.
type relayCell struct {
	status int    // the status the client gets; 0 when it gets no response
	body   string // a substring of the body the client reads in full; "" to not check
	cut    bool   // the client's read of the body fails: the response was cut off
	logged int    // the request line's status
	errTyp string // the request line's error_type; "" for none
	warn   string // the one warning or error the relay logs; "" for none
	drop   bool   // the upstream request ends before the upstream answers it
}

// relayRig is one cell's proxy, upstream and client.
type relayRig struct {
	srv      *httptest.Server
	logs     *safeBuffer
	shutDown func()
	reached  chan struct{} // the upstream has the work in the cell's state
	finish   chan struct{} // the upstream completes the work
	abort    chan struct{} // the upstream goes away
	dropped  chan struct{} // the upstream request ended before the upstream answered it
}

// safeBuffer is a log the server's handler goroutines write while the test reads it after Close.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newRelayRig starts an upstream that drives the request to state, then holds it until the cell's
// ending; and a proxy in front of it, logged as the server logs it, whose requests the proxy's
// shutdown ends. timeout is the relay's header timeout, 0 for none.
func newRelayRig(t *testing.T, state lifecycle.State, timeout time.Duration) *relayRig {
	t.Helper()
	r := &relayRig{logs: &safeBuffer{}, reached: make(chan struct{}), finish: make(chan struct{}),
		abort: make(chan struct{}), dropped: make(chan struct{}, 1)}
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	release := make(chan struct{})
	up.Live = true
	up.Handler = func(w http.ResponseWriter, req *http.Request) {
		rc := http.NewResponseController(w)
		switch state {
		case lifecycle.BodyInFlight:
			buf := make([]byte, 1)
			if _, err := req.Body.Read(buf); err != nil {
				return
			}
		default:
			_, _ = io.ReadAll(req.Body)
		}
		switch state {
		case lifecycle.After1xx:
			w.Header().Set("Link", "</style.css>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
		case lifecycle.Streaming:
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "data: a\n\n")
			_ = rc.Flush()
		case lifecycle.TrailerPending:
			w.Header().Set("Trailer", "X-Checksum")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "body")
			_ = rc.Flush()
		case lifecycle.UpgradeRequested:
			if req.Header.Get("Upgrade") != "" || req.Header.Get("Connection") != "" {
				w.WriteHeader(http.StatusTeapot) // the upgrade reached the upstream
				return
			}
		}
		// While the request body is in flight the upstream keeps reading it, as one would; Go's server
		// sees its connection close (and ends the request's context) only once the body is read.
		bodyDone := make(chan struct{})
		if state == lifecycle.BodyInFlight {
			go func() { _, _ = io.Copy(io.Discard, req.Body); close(bodyDone) }()
		}
		close(r.reached)
		select {
		case <-r.finish:
			switch state {
			case lifecycle.BodyInFlight:
				<-bodyDone
				_, _ = io.WriteString(w, "ok")
			case lifecycle.Streaming:
				_, _ = io.WriteString(w, "data: b\n\n")
			case lifecycle.TrailerPending:
				w.Header().Set("X-Checksum", "sum")
			default:
				_, _ = io.WriteString(w, "ok")
			}
		case <-r.abort:
			if state == lifecycle.UpgradeRequested { // the upstream switches protocols anyway
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.WriteHeader(http.StatusSwitchingProtocols)
				return
			}
			panic(http.ErrAbortHandler) // the upstream's connection breaks off
		case <-req.Context().Done():
			r.dropped <- struct{}{}
		case <-release:
		}
	}
	u, err := url.Parse(up.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var opts []Option
	if timeout > 0 {
		opts = append(opts, WithResponseHeaderTimeout(timeout))
	}
	log := logging.New(r.logs, "json")
	r.srv = httptest.NewUnstartedServer(logging.Middleware(log, New(log, u, opts...)))
	base, shutDown := shutdown.WithCancel(t.Context())
	t.Cleanup(shutDown)
	r.shutDown = shutDown
	r.srv.Config.BaseContext = func(net.Listener) context.Context { return base }
	r.srv.Start()
	t.Cleanup(r.srv.Close)
	// Cleanups run last first: releasing a held upstream before the proxy's Close lets the relay's
	// handler return, so a handler that never returns fails its cell instead of hanging the package.
	t.Cleanup(func() { close(release) })
	return r
}

// clientResult is what the MCP client got.
type clientResult struct {
	status  int
	body    string
	cut     bool
	trailer http.Header
}

// runRelayCell drives one cell: the client sends toolsList, the upstream takes the work to state,
// the cell's ending happens, and the test checks what the client got, the log, and that the
// upstream request is ended (or answered).
func runRelayCell(t *testing.T, state lifecycle.State, end lifecycle.Ending, want relayCell) {
	t.Helper()
	timeout := time.Duration(0)
	if end == lifecycle.Timeout {
		timeout = headerTimeout // real time: the transport's own bound, waited on as an event
		if state == lifecycle.After1xx {
			timeout = after1xxTimeout
		}
	}
	bound := boundFor(timeout)
	r := newRelayRig(t, state, timeout)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var body io.Reader = strings.NewReader(toolsList)
	var rest *lifecycle.CutBody
	if state == lifecycle.BodyInFlight {
		rest = lifecycle.NewCutBody(toolsList)
		body = rest
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.srv.URL+"/mcp", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if state == lifecycle.UpgradeRequested {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
	}
	// The client has the state too: the interim response, or the response's headers.
	atClient := make(chan struct{})
	switch state {
	case lifecycle.After1xx:
		var once sync.Once
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			Got1xxResponse: func(int, textproto.MIMEHeader) error { once.Do(func() { close(atClient) }); return nil },
		}))
	case lifecycle.Streaming, lifecycle.TrailerPending:
	default:
		close(atClient)
	}
	got := make(chan clientResult, 1)
	go func() {
		res, err := r.srv.Client().Do(req)
		if err == nil && (state == lifecycle.Streaming || state == lifecycle.TrailerPending) {
			close(atClient)
		}
		if err != nil {
			got <- clientResult{}
			return
		}
		defer func() { _ = res.Body.Close() }()
		b, err := io.ReadAll(res.Body)
		got <- clientResult{res.StatusCode, string(b), err != nil, res.Trailer}
	}()
	for what, ch := range map[string]chan struct{}{"the upstream": r.reached, "the client": atClient} {
		select {
		case <-ch:
		case <-time.After(bound):
			t.Fatalf("%s never had the work %s", what, state)
		}
	}
	switch end {
	case lifecycle.Completes:
		if rest != nil {
			rest.Finish()
		}
		close(r.finish)
	case lifecycle.ClientGone:
		cancel()
	case lifecycle.UpstreamGone:
		close(r.abort)
	case lifecycle.Shutdown:
		r.shutDown()
	}
	if rest != nil && end != lifecycle.Completes {
		rest.Stop() // the client stops sending: it gave up, or the proxy has answered
	}
	var res clientResult
	select {
	case res = <-got:
	case <-time.After(bound):
		t.Fatal("the client got no answer")
	}
	if rest != nil {
		rest.Stop()
	}
	closed := make(chan struct{})
	go func() { r.srv.Close(); close(closed) }() // waits for the handler, so its slot and log are done
	select {
	case <-closed:
	case <-time.After(bound):
		t.Fatal("the relay's handler never returned: its slot is still held")
	}
	if res.status != want.status || res.cut != want.cut || !strings.Contains(res.body, want.body) {
		t.Errorf("the client got %d %q (cut %v); want %d with %q (cut %v)", res.status, res.body, res.cut, want.status, want.body, want.cut)
	}
	if len(res.trailer) != 0 {
		t.Errorf("the client got trailers %v; the relay drops an upstream's trailers", res.trailer)
	}
	checkRelayLog(t, r.logs.String(), want)
	if want.drop {
		select {
		case <-r.dropped:
		case <-time.After(bound):
			t.Error("the upstream request was not ended")
		}
	}
}

// checkRelayLog checks the request line and the relay's warnings against want.
func checkRelayLog(t *testing.T, log string, want relayCell) {
	t.Helper()
	var lines, warns int
	for _, rec := range logsink.Records[map[string]any](t, log) {
		msg, _ := rec["msg"].(string)
		switch {
		case msg == "request":
			lines++
			status, _ := rec["status"].(float64)
			errTyp, _ := rec["error_type"].(string)
			if int(status) != want.logged || errTyp != want.errTyp {
				t.Errorf("request line status %v error_type %q; want %d %q", rec["status"], errTyp, want.logged, want.errTyp)
			}
		case rec["level"] == "WARN" || rec["level"] == "ERROR":
			warns++
			if want.warn == "" {
				t.Errorf("logged %s %q; want no warning", rec["level"], msg)
			} else if !strings.Contains(msg, want.warn) {
				t.Errorf("logged %s %q; want only %q", rec["level"], msg, want.warn)
			}
		}
	}
	if lines != 1 {
		t.Errorf("%d request lines; want 1:\n%s", lines, log)
	}
	if want.warn != "" && warns != 1 {
		t.Errorf("%d warnings; want one %q:\n%s", warns, want.warn, log)
	}
}

// notStarted serves one request whose context already ended, or whose upstream refuses the dial,
// before the relay sends anything upstream.
func notStarted(t *testing.T, end lifecycle.Ending, want relayCell) {
	t.Helper()
	target := "http://" + closedport.Addr(t) + "/mcp"
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	logs := &safeBuffer{}
	log := logging.New(logs, "json")
	h := logging.Middleware(log, New(log, u))
	ctx := t.Context()
	for _, e := range lifecycle.ContextEndings {
		if e.Ending == end {
			var stop func()
			ctx, stop = e.Start(ctx)
			stop()
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(toolsList)))
	if w.Code != want.status || !strings.Contains(w.Body.String(), want.body) {
		t.Errorf("answered %d %q; want %d with %q", w.Code, w.Body, want.status, want.body)
	}
	checkRelayLog(t, logs.String(), want)
}

// The relay's lifecycle matrix (#672): every way a request ends, crossed with every state its
// work can be in, pins what the MCP client gets, the request line and the relay's own log, and
// that the upstream request is ended and the handler returns (its in-flight slot freed). The
// timeout row runs on the transport's own header timeout, in real time (50 ms), waited on as an
// event; the relay has no injectable clock for one row.
func TestTheRelayLifecycleMatrix(t *testing.T) {
	const (
		unavailable = "upstream unavailable"
		upErr       = "upstream error"
		shutting    = "the proxy is shutting down"
		timedOut    = "upstream did not answer in time"
	)
	afterBody := "the header timeout starts once the request is written (timeout.go), so none applies while its body is in flight; the server's ReadTimeout bounds a stalled upload"
	noStreamBound := "the header timeout ends with the response's headers; nothing bounds a streamed body, by design (TestHeaderTimeoutDoesNotLimitAStreamedBody)"
	stripped := "the relay strips the client's upgrade before the request leaves (relay.go Rewrite), so it is an ordinary request, whose endings are the other columns'"
	at := func(end lifecycle.Ending, state lifecycle.State) lifecycle.Cell {
		return lifecycle.Cell{Ending: end, State: state}
	}
	// Each pinned cell is named once, by its key, so a row cannot run one cell under another's name.
	pinned := map[lifecycle.Cell]relayCell{
		at(lifecycle.ClientGone, lifecycle.NotStarted):   {status: 499, logged: 499},
		at(lifecycle.UpstreamGone, lifecycle.NotStarted): {status: http.StatusBadGateway, body: unavailable, logged: 502, warn: upErr},
		at(lifecycle.Shutdown, lifecycle.NotStarted):     {status: http.StatusServiceUnavailable, body: shutting, logged: 503},

		at(lifecycle.Completes, lifecycle.BodyInFlight):    {status: 200, body: "ok", logged: 200},
		at(lifecycle.ClientGone, lifecycle.BodyInFlight):   {logged: 499, drop: true},
		at(lifecycle.UpstreamGone, lifecycle.BodyInFlight): {status: 502, body: unavailable, logged: 502, warn: upErr},
		at(lifecycle.Shutdown, lifecycle.BodyInFlight):     {status: 503, body: shutting, logged: 503, drop: true},

		at(lifecycle.Completes, lifecycle.AwaitingHeaders):    {status: 200, body: "ok", logged: 200},
		at(lifecycle.ClientGone, lifecycle.AwaitingHeaders):   {logged: 499, drop: true},
		at(lifecycle.UpstreamGone, lifecycle.AwaitingHeaders): {status: 502, body: unavailable, logged: 502, warn: upErr},
		at(lifecycle.Timeout, lifecycle.AwaitingHeaders):      {status: 200, body: `"upstreamTimeout":true`, logged: 200, warn: timedOut, drop: true},
		at(lifecycle.Shutdown, lifecycle.AwaitingHeaders):     {status: 503, body: shutting, logged: 503, drop: true},

		at(lifecycle.Completes, lifecycle.After1xx):    {status: 200, body: "ok", logged: 200},
		at(lifecycle.ClientGone, lifecycle.After1xx):   {logged: 499, drop: true},
		at(lifecycle.UpstreamGone, lifecycle.After1xx): {status: 502, body: unavailable, logged: 502, warn: upErr},
		at(lifecycle.Timeout, lifecycle.After1xx):      {status: 200, body: `"upstreamTimeout":true`, logged: 200, warn: timedOut, drop: true},
		at(lifecycle.Shutdown, lifecycle.After1xx):     {status: 503, body: shutting, logged: 503, drop: true},

		at(lifecycle.Completes, lifecycle.Streaming):    {status: 200, body: "data: a\n\ndata: b\n\n", logged: 200},
		at(lifecycle.ClientGone, lifecycle.Streaming):   {status: 200, cut: true, logged: 200, errTyp: string(logging.ClientClosed), drop: true},
		at(lifecycle.UpstreamGone, lifecycle.Streaming): {status: 200, cut: true, logged: 200, errTyp: string(logging.UpstreamAborted), warn: upErr},
		at(lifecycle.Shutdown, lifecycle.Streaming):     {status: 200, cut: true, logged: 200, errTyp: string(logging.ShutDown), drop: true},

		at(lifecycle.Completes, lifecycle.TrailerPending):    {status: 200, body: "body", logged: 200},
		at(lifecycle.ClientGone, lifecycle.TrailerPending):   {status: 200, cut: true, logged: 200, errTyp: string(logging.ClientClosed), drop: true},
		at(lifecycle.UpstreamGone, lifecycle.TrailerPending): {status: 200, cut: true, logged: 200, errTyp: string(logging.UpstreamAborted), warn: upErr},
		at(lifecycle.Shutdown, lifecycle.TrailerPending):     {status: 200, cut: true, logged: 200, errTyp: string(logging.ShutDown), drop: true},

		at(lifecycle.Completes, lifecycle.UpgradeRequested):    {status: 200, body: "ok", logged: 200},
		at(lifecycle.UpstreamGone, lifecycle.UpgradeRequested): {status: 502, logged: 502, warn: upErr},
	}
	m := map[lifecycle.Cell]lifecycle.Case{
		at(lifecycle.Completes, lifecycle.NotStarted): lifecycle.Unreachable("a request that completes was sent to the upstream"),
		at(lifecycle.Timeout, lifecycle.NotStarted):   lifecycle.NotRun("the dial bound is the transport's 10 s; a refused dial is the upstream-gone cell"),

		at(lifecycle.Timeout, lifecycle.BodyInFlight): lifecycle.Unreachable(afterBody),

		at(lifecycle.Timeout, lifecycle.Streaming): lifecycle.Unreachable(noStreamBound),

		at(lifecycle.Timeout, lifecycle.TrailerPending): lifecycle.Unreachable(noStreamBound),

		at(lifecycle.ClientGone, lifecycle.UpgradeRequested): lifecycle.Unreachable(stripped),
		at(lifecycle.Timeout, lifecycle.UpgradeRequested):    lifecycle.Unreachable(stripped),
		at(lifecycle.Shutdown, lifecycle.UpgradeRequested):   lifecycle.Unreachable(stripped),
	}
	for c, want := range pinned {
		m[c] = lifecycle.Pinned(func(t *testing.T) {
			if c.State == lifecycle.NotStarted {
				notStarted(t, c.Ending, want)
				return
			}
			runRelayCell(t, c.State, c.Ending, want)
		})
	}
	lifecycle.Run(t, m)
}
