//go:build linux || darwin

package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// modernBody is a 2026-07-28 request: id and method, extra _meta fields (JSON, may be empty), and
// extra params fields (JSON, may be empty).
func modernBody(id, method, meta, params string) string {
	m := `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}`
	if meta != "" {
		m += "," + meta
	}
	p := `"_meta":{` + m + `}`
	if params != "" {
		p += "," + params
	}
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":{` + p + `}}`
}

// modernHeaders are the request metadata headers a compliant client sends for body: the protocol
// version, the method, and Mcp-Name where the method mirrors params.name or params.uri.
func modernHeaders(body string) []string {
	var m struct {
		Method string
		Params struct{ Name, URI *string }
	}
	_ = json.Unmarshal([]byte(body), &m)
	h := []string{"MCP-Protocol-Version", "2026-07-28", "Mcp-Method", m.Method}
	switch {
	case (m.Method == "tools/call" || m.Method == "prompts/get") && m.Params.Name != nil:
		h = append(h, "Mcp-Name", *m.Params.Name)
	case m.Method == "resources/read" && m.Params.URI != nil:
		h = append(h, "Mcp-Name", *m.Params.URI)
	}
	return h
}

// modern posts a 2026-07-28 request as user, with the headers a compliant client sends.
func (b *bridgeHarness) modern(t *testing.T, user, body string) *http.Response {
	t.Helper()
	return b.modernCtx(t, context.Background(), user, body)
}

func (b *bridgeHarness) modernCtx(t *testing.T, ctx context.Context, user, body string) *http.Response {
	t.Helper()
	return b.do(t, ctx, http.MethodPost, user, "", body, modernHeaders(body)...)
}

func newModernBridge(t *testing.T, edit func(*Config)) *bridgeHarness {
	t.Helper()
	return newBridge(t, func(c *Config) {
		c.Command = []string{fakeBin, "-modern"}
		if edit != nil {
			edit(c)
		}
	})
}

// lastResult is the JSON-RPC result of the last event, with its id.
func lastResult(t *testing.T, events []string) (id string, result json.RawMessage) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no events")
	}
	var m struct {
		ID     json.RawMessage
		Result json.RawMessage
	}
	if err := json.Unmarshal([]byte(events[len(events)-1]), &m); err != nil {
		t.Fatalf("last event %q: %v", events[len(events)-1], err)
	}
	return string(m.ID), m.Result
}

// fetch posts body as alice and returns the SSE data lines; it never calls t.Fatal, so goroutines
// may use it.
func (b *bridgeHarness) fetch(body string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), guard)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.srv.URL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set(userHeader, "alice")
	req.Header.Set("Accept", "application/json, text/event-stream")
	h := modernHeaders(body)
	for i := 0; i+1 < len(h); i += 2 {
		if h[i+1] != "" {
			req.Header.Set(h[i], h[i+1])
		}
	}
	res, err := b.srv.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", res.StatusCode)
	}
	var events []string
	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			events = append(events, d)
		}
	}
	return events, sc.Err()
}

// waitEnded waits, bounded by guard, until c's process has ended and its cleanup has run.
func waitEnded(t *testing.T, c *userConn) {
	t.Helper()
	select {
	case <-c.ended:
	case <-time.After(guard):
		t.Fatal("the userConn of a stopped process never ended")
	}
}

// stops counts the "stopping upstream process" records with reason.
func (b *bridgeHarness) stops(reason string) int {
	n := 0
	for _, r := range b.log.with("stopping upstream process") {
		if r.attrs["reason"] == reason {
			n++
		}
	}
	return n
}

func TestModernRequestsOfAUserShareOneUpstreamProcessUnderTheirOwnIDs(t *testing.T) {
	b := newModernBridge(t, nil)
	for i, id := range []string{`1`, `"a"`, `1`} {
		got := readEvents(t, b.modern(t, "alice", modernBody(id, "echo", "", fmt.Sprintf(`"n":%d`, i))))
		gotID, res := lastResult(t, got)
		if gotID != id || !strings.Contains(string(res), fmt.Sprintf(`"n":%d`, i)) {
			t.Fatalf("request %d: id %s, result %s; want the client's own id and its echo", i, gotID, res)
		}
	}
	if b.m.Len() != 1 {
		t.Fatalf("Len = %d after three requests by one user, want 1", b.m.Len())
	}
	readEvents(t, b.modern(t, "bob", modernBody(`1`, "echo", "", "")))
	if b.m.Len() != 2 {
		t.Fatalf("Len = %d with two users, want one process each", b.m.Len())
	}
}

func TestConcurrentClientsOfOneUserGetOnlyTheirOwnResponsesAndProgress(t *testing.T) {
	// Every client uses the same id and the same progress token: only the proxy's rewriting keeps
	// them apart on the shared process. The first requests also race the probe.
	b := newModernBridge(t, nil)
	const clients, rounds = 8, 5
	errs := make(chan error, clients*rounds)
	var wg sync.WaitGroup
	for c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				tag := fmt.Sprintf("client-%d-round-%d", c, r)
				events, err := b.fetch(modernBody(`1`, "progress", `"progressToken":"p"`, `"tag":"`+tag+`"`))
				switch {
				case err != nil:
					errs <- fmt.Errorf("%s: %w", tag, err)
				case len(events) != 4:
					errs <- fmt.Errorf("%s: %d events, want 3 progress and a result: %q", tag, len(events), events)
				default:
					for _, e := range events[:3] {
						if !strings.Contains(e, `"progressToken":"p"`) || !strings.Contains(e, `"message":"`+tag+`"`) {
							errs <- fmt.Errorf("%s got another stream's progress, or a proxy token: %s", tag, e)
						}
					}
					if last := events[3]; !strings.Contains(last, `"id":1`) || !strings.Contains(last, tag) {
						errs <- fmt.Errorf("%s got the result %s", tag, last)
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if b.m.Len() != 1 {
		t.Fatalf("Len = %d, want one process for the user", b.m.Len())
	}
	if _, n := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`9`, "discovers", "", "")))); string(n) != "1" {
		t.Fatalf("the upstream was probed %s times, want once", n)
	}
}

func TestProgressWrittenJustBeforeTheResultIsNeverLost(t *testing.T) {
	b := newModernBridge(t, nil)
	for i := range 20 {
		events := readEvents(t, b.modern(t, "alice", modernBody(`1`, "burst", `"progressToken":7`, `"n":10`)))
		if len(events) != 11 || !strings.Contains(events[10], `"result":"done"`) {
			t.Fatalf("round %d: %d events, want 10 progress then the result: %q", i, len(events), events)
		}
	}
}

func TestModernRequestsToALegacyOnlyUpstreamGetTheFallback400AfterOneProbe(t *testing.T) {
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} }) // answers no server/discover
	fallback := func(what string) {
		t.Helper()
		res := b.modern(t, "alice", modernBody(`1`, "tools/list", "", ""))
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "start a session with initialize") {
			t.Fatalf("%s: status %d, body %s; want the 400 dual-era clients fall back on", what, res.StatusCode, body)
		}
	}
	fallback("first request")
	eventually(t, "the probed process to be stopped", func() bool { return b.m.Len() == 0 })
	fallback("second request")
	if n := b.stops("not_modern"); n != 1 {
		t.Fatalf("%d probe processes were stopped, want 1: the verdict was not kept", n)
	}
	if s := b.initialize(t, "alice"); s == "" { // the legacy era still works on the same upstream
		t.Fatal("no MCP session")
	}
}

func TestLegacyVerdictExpiresAndTheUpstreamIsProbedAgain(t *testing.T) {
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} })
	b.modern(t, "alice", modernBody(`1`, "tools/list", "", ""))
	eventually(t, "the probed process to be stopped", func() bool { return b.m.Len() == 0 })
	b.clk.Advance(legacyVerdictTTL)
	b.modern(t, "alice", modernBody(`2`, "tools/list", "", ""))
	eventually(t, "a second probe", func() bool { return b.stops("not_modern") == 2 })
}

func TestUpstreamThatNeverAnswersTheProbeIsLegacy(t *testing.T) {
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp", "-silentdiscover"} })
	b.bridge.probeTimeout = 50 * time.Millisecond
	res := b.modern(t, "alice", modernBody(`1`, "tools/list", "", ""))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want the fallback 400", res.StatusCode)
	}
	eventually(t, "the probed process to be stopped", func() bool { return b.stops("not_modern") == 1 })
}

func TestAmbiguousModernRequestsAreRefusedBeforeAnyProcessStarts(t *testing.T) {
	// Which messages are ambiguous is locate's business (rewrite_test.go); this checks the wiring.
	b := newModernBridge(t, nil)
	for name, body := range map[string]string{
		"id repeated":                                  `{"jsonrpc":"2.0","id":1,"id":2,"method":"echo","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"id in another case":                           `{"jsonrpc":"2.0","ID":1,"method":"echo","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"object progressToken":                         modernBody(`1`, "echo", `"progressToken":{"a":1}`, ""),
		"method also in another case":                  `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","METHOD":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"method also in another case, initialize last": `{"jsonrpc":"2.0","id":1,"method":"tools/call","METHOD":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"method repeated, initialize last":             `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"method repeated":                              `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			res := b.post(t, "alice", "", body)
			raw, _ := io.ReadAll(res.Body)
			// The ambiguity refusal, not the fallback: that would send the client to initialize.
			if res.StatusCode != http.StatusBadRequest || rpcErrorCode(t, raw) != codeInvalidRequest || !strings.Contains(string(raw), "ambiguous") {
				t.Fatalf("status %d, body %s; want 400 -32600 naming the ambiguity", res.StatusCode, raw)
			}
		})
	}
	if b.m.Len() != 0 {
		t.Fatalf("Len = %d, want no process for refused requests", b.m.Len())
	}
}

func TestRequestIDsAndProgressTokensMustBeStringsOrIntegers(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"string id and token":  {modernBody(`"a"`, "x", `"progressToken":"t"`, ""), true},
		"integer id and token": {modernBody(`1`, "x", `"progressToken":-2`, ""), true},
		"no token":             {modernBody(`1`, "x", "", ""), true},
		"fractional token":     {modernBody(`1`, "x", `"progressToken":1.5`, ""), false},
		"boolean token":        {modernBody(`1`, "x", `"progressToken":true`, ""), false},
		"null token":           {modernBody(`1`, "x", `"progressToken":null`, ""), false},
		"no id":                {`{"jsonrpc":"2.0","method":"x","params":{}}`, false},
		"fractional id":        {modernBody(`1.5`, "x", "", ""), false},
		"boolean id":           {modernBody(`true`, "x", "", ""), false},
		"null id":              {modernBody(`null`, "x", "", ""), false},
	} {
		meta, err := readMeta([]byte(tc.body))
		if err == nil {
			err = meta.checkRequest([]byte(tc.body))
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want accepted %v", name, err, tc.ok)
		}
	}
}

func TestAnExitedProcessesRequestGetsItsQueuedAnswerBeforeAnyExitError(t *testing.T) {
	q := &modernRequest{id: []byte(`7`), final: make(chan []byte, 1)}
	if got := string(exitAnswer(q)); !strings.Contains(got, "upstream process exited") || !strings.Contains(got, `"id":7`) {
		t.Fatalf("with no answer queued: %s, want the exit error under the client's id", got)
	}
	q.final <- []byte(`{"jsonrpc":"2.0","id":7,"result":"answered"}`)
	if got := string(exitAnswer(q)); got != `{"jsonrpc":"2.0","id":7,"result":"answered"}` {
		t.Fatalf("with an answer queued: %s, want the answer", got)
	}
}

func TestProxyIDsNeverRepeatAcrossTheUsersUpstreamProcesses(t *testing.T) {
	// A respawned upstream process gets a new userConn; its ids must not restart where the
	// previous one's began.
	b := newModernBridge(t, nil)
	key := "user:" + alice.user()
	conn := func() *userConn {
		t.Helper()
		readEvents(t, b.modern(t, "alice", modernBody(`1`, "echo", "", "")))
		b.bridge.mu.Lock()
		defer b.bridge.mu.Unlock()
		return b.bridge.users[key]
	}
	first := conn()
	a := first.register([]byte(`1`), []byte(`"t"`), false, false)
	first.p.stop("test")
	waitEnded(t, first)
	second := conn()
	if second == first {
		t.Fatal("no new userConn after the respawn, so this test proves nothing")
	}
	if c := second.register([]byte(`1`), []byte(`"t"`), false, false); a.proxyID == c.proxyID || a.proxyTok == c.proxyTok {
		t.Fatalf("ids %s/%s repeat after the respawn", c.proxyID, c.proxyTok)
	}
}

func TestARespawnedProcessGetsItsOwnUserConn(t *testing.T) {
	// The map still holds the userConn of the user's previous process: requests for the new process
	// must not go to it, or no pump would read the new process's output.
	b := newModernBridge(t, nil)
	key := "user:" + alice.user()
	stale := &userConn{p: &Process{}, ended: make(chan struct{})}
	close(stale.ended)
	b.bridge.mu.Lock()
	b.bridge.users[key] = stale
	b.bridge.mu.Unlock()
	if id, res := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`5`, "echo", "", `"n":5`)))); id != `5` || !strings.Contains(string(res), `"n":5`) {
		t.Fatalf("the request got id %s, result %s; want its own echo, not an exit error", id, res)
	}
	b.bridge.mu.Lock()
	defer b.bridge.mu.Unlock()
	if b.bridge.users[key] == stale {
		t.Fatal("the stale userConn served the new process")
	}
}

func TestReadMetaTellsTheEraFromTheProtocolVersion(t *testing.T) {
	for body, modern := range map[string]bool{
		modernBody(`1`, "x", "", ""): true,
		`{"id":1,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2027-01-01"}}}`: true,
		`{"id":1,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`: false,
		`{"id":1,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":20260728}}}`:     false,
		`{"id":1,"params":{}}`: false,
		`{"id":1}`:             false,
	} {
		meta, err := readMeta([]byte(body))
		if err != nil || meta.modern() != modern {
			t.Errorf("readMeta(%s) = modern %v, %v; want %v", body, meta.modern(), err, modern)
		}
	}
}

// upstreamCancellations is the request ids notifications/cancelled has named to the upstream so far.
func (b *bridgeHarness) upstreamCancellations(t *testing.T) []string {
	t.Helper()
	_, got := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`"c"`, "cancelled", "", ""))))
	var ids []string
	if err := json.Unmarshal(got, &ids); err != nil {
		t.Fatalf("cancelled: %s", got)
	}
	return ids
}

// awaitUpstreamCancellation waits until the upstream has seen a cancellation and returns them all.
func (b *bridgeHarness) awaitUpstreamCancellation(t *testing.T) []string {
	t.Helper()
	var ids []string
	eventually(t, "the upstream to see a cancellation", func() bool { ids = b.upstreamCancellations(t); return len(ids) > 0 })
	return ids
}

func TestClosingTheStreamCancelsTheRequestOnTheUpstream(t *testing.T) {
	b := newModernBridge(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	res := b.modernCtx(t, ctx, "alice", modernBody(`"mine"`, "hold", "", ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	cancel()
	if ids := b.awaitUpstreamCancellation(t); len(ids) != 1 || ids[0] == "mine" {
		t.Fatalf("upstream saw cancellations %q; want one, under the proxy's id, not the client's", ids)
	}
}

func TestAClientsCancellationNeverReachesTheUpstream(t *testing.T) {
	// Over HTTP a request is cancelled by closing its stream. A cancellation sent as a message
	// names an id that, on the shared process, could be another client's.
	b := newModernBridge(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	held := eventsOf(t, b.modernCtx(t, ctx, "alice", modernBody(`"mine"`, "hold", "", "")))
	for _, id := range []string{`"mine"`, `"byw-1"`, `"byw-2"`} {
		notif := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + id +
			`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		if res := b.post(t, "alice", "", notif); res.StatusCode != http.StatusAccepted {
			t.Fatalf("cancellation of %s: status %d, want 202", id, res.StatusCode)
		}
	}
	if ids := b.upstreamCancellations(t); len(ids) != 0 {
		t.Fatalf("upstream saw cancellations %q, want none", ids)
	}
	cancel()
	held.all()
}

func TestLogMessagesReachARequestOnlyWhenItIsTheOnlyOneAskingForThem(t *testing.T) {
	logLevel := `"io.modelcontextprotocol/logLevel":"info"`
	for name, tc := range map[string]struct {
		heldAsks  bool // the other request in flight asked for log messages too
		delivered bool
	}{
		"the only one asking, beside one that did not": {heldAsks: false, delivered: true},
		"one of two asking":                            {heldAsks: true, delivered: false},
	} {
		t.Run(name, func(t *testing.T) {
			b := newModernBridge(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			heldMeta := ""
			if tc.heldAsks {
				heldMeta = logLevel
			}
			held := eventsOf(t, b.modernCtx(t, ctx, "alice", modernBody(`1`, "hold", heldMeta, "")))
			events := readEvents(t, b.modern(t, "alice", modernBody(`2`, "log", logLevel, `"tag":"x"`)))
			if got := len(events) == 2 && strings.Contains(events[0], "notifications/message"); got != tc.delivered {
				t.Fatalf("events %q; want the log message delivered: %v", events, tc.delivered)
			}
			if !tc.delivered {
				if recs := b.log.with("upstream notification dropped"); len(recs) != 1 || recs[0].attrs["reason"] != "log_unrouted" {
					t.Fatalf("drop records %v, want one for log_unrouted", recs)
				}
			}
			cancel()
			if got := held.all(); len(got) != 0 {
				t.Fatalf("the held request got %q", got)
			}
		})
	}
}

func TestUpstreamRequestsInTheModernEraAreAnsweredWithAnError(t *testing.T) {
	b := newModernBridge(t, nil)
	_, res := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`1`, "ask", "", ""))))
	if !strings.Contains(string(res), `"code":-32603`) {
		t.Fatalf("the upstream's request got %s, want a -32603 error", res)
	}
}

func TestUnroutableUpstreamMessagesAreDroppedAndLogged(t *testing.T) {
	for name, tc := range map[string]struct{ method, msg, reason string }{
		"notification for no request":                           {"stray", "upstream notification dropped", "notification_unrouted"},
		"progress for no request":                               {"strayprogress", "upstream notification dropped", "progress_unrouted"},
		"response for no waiting request":                       {"strayresponse", "upstream response for no waiting request", "response_unrouted"},
		"notification for no subscription":                      {"strayscribe", "upstream notification dropped", "subscription_unrouted"},
		"cancellation of no request":                            {"straycancel", "upstream notification dropped", "cancel_unrouted"},
		"cancellation of a request, not a subscription":         {"cancelself", "upstream notification dropped", "cancel_unrouted"},
		"subscription notification for a request, not a listen": {"scribeself", "upstream notification dropped", "subscription_unrouted"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newModernBridge(t, nil)
			if events := readEvents(t, b.modern(t, "alice", modernBody(`1`, tc.method, "", ""))); len(events) != 1 {
				t.Fatalf("events %q, want only the result", events)
			}
			if recs := b.log.with(tc.msg); len(recs) != 1 || recs[0].attrs["reason"] != tc.reason {
				t.Fatalf("records %v, want one %q with reason %s", recs, tc.msg, tc.reason)
			}
		})
	}
}

func TestFullModernStreamDropsTheNotification(t *testing.T) {
	h := newHarness(t, nil)
	c := &userConn{p: h.get(t, "s1", alice), log: h.m.log}
	q := &modernRequest{out: make(chan []byte, 1)}
	q.out <- []byte(`{}`)
	c.deliver(q, []byte(`{"jsonrpc":"2.0","method":"notifications/progress"}`), "notifications/progress")
	if recs := h.log.with("upstream notification dropped"); len(recs) != 1 || recs[0].attrs["reason"] != "stream_full" {
		t.Fatalf("records %v, want one for stream_full", recs)
	}
}

func TestUpstreamProcessCrashFailsInFlightModernRequestsUnderTheirIDsAndTheNextRequestRespawnsIt(t *testing.T) {
	b := newModernBridge(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	held := eventsOf(t, b.modernCtx(t, ctx, "alice", modernBody(`"h"`, "hold", "", "")))
	readEvents(t, b.modern(t, "alice", modernBody(`2`, "crash", "", "")))
	if got := held.all(); len(got) != 1 || !strings.Contains(got[0], "upstream process exited") || !strings.Contains(got[0], `"id":"h"`) {
		t.Fatalf("held request got %q, want -32603 under its own id", got)
	}
	eventually(t, "the crashed process to be gone", func() bool { return b.m.Len() == 0 })
	if id, _ := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`3`, "echo", "", "")))); id != `3` {
		t.Fatalf("the next request got id %s", id)
	}
}

func TestAnAnswerWrittenJustBeforeTheProcessExitsStillReachesTheClient(t *testing.T) {
	b := newModernBridge(t, nil)
	for i := range 10 {
		_, res := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`1`, "answerexit", "", ""))))
		if string(res) != `"answered"` {
			t.Fatalf("round %d: result %s, want the upstream's answer, not an exit error", i, res)
		}
		eventually(t, "the process to exit", func() bool { return b.m.Len() == 0 })
	}
}

func TestAnEndedProcessesPumpNeverRemovesItsSuccessor(t *testing.T) {
	// A crash, then a respawn before the old pump has finished: the old pump must leave the new
	// userConn in place, or a second pump could read the new process's output.
	b := newModernBridge(t, nil)
	readEvents(t, b.modern(t, "alice", modernBody(`1`, "echo", "", "")))
	key := "user:" + alice.user()
	b.bridge.mu.Lock()
	old := b.bridge.users[key]
	successor := &userConn{}
	b.bridge.users[key] = successor
	b.bridge.mu.Unlock()
	old.p.stop("test")
	waitEnded(t, old) // closed only after the old pump's cleanup has run
	b.bridge.mu.Lock()
	defer b.bridge.mu.Unlock()
	if b.bridge.users[key] != successor {
		t.Fatal("the ended process's pump removed its successor")
	}
}

func TestUserAtTheirCapWithEveryProcessInUseGets503ForAModernRequest(t *testing.T) {
	// The cap refuses before any probe, so a legacy fake serves the MCP session that holds the slot.
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"}; c.MaxPerUser = 1 })
	s := b.initialize(t, "alice")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.listen(t, ctx, s) // the legacy MCP session's process is in use
	res := b.modern(t, "alice", modernBody(`1`, "echo", "", ""))
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") != busyRetryAfter {
		t.Fatalf("status %d, Retry-After %q; want 503 and %s", res.StatusCode, res.Header.Get("Retry-After"), busyRetryAfter)
	}
	if recs := b.log.with("stdio process cap full: every process is in use"); len(recs) != 1 || recs[0].attrs["reason"] != "process_cap" {
		t.Fatalf("records %v", recs)
	}
}

func TestModernNotificationsNeedNoHeadersAndAre202AndClientResponsesAre400(t *testing.T) {
	b := newModernBridge(t, nil)
	// Sent with no MCP headers: 2026-07-28 defines none for notification POSTs.
	notif := `{"jsonrpc":"2.0","method":"notifications/x","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	if res := b.post(t, "alice", "", notif); res.StatusCode != http.StatusAccepted {
		t.Fatalf("notification: status %d, want 202", res.StatusCode)
	}
	resp := `{"jsonrpc":"2.0","id":1,"result":{},"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	if res := b.post(t, "alice", "", resp); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("client response: status %d, want 400", res.StatusCode)
	}
}

func TestCheckHeadersRequiresTheHeadersToMirrorTheBody(t *testing.T) {
	// The bridge is the server here: the upstream never sees headers (ADR-0004 §3, amended).
	call := modernBody(`1`, "tools/call", "", `"name":"weather"`)
	read := modernBody(`2`, "resources/read", "", `"uri":"file:///a"`)
	prompt := modernBody(`3`, "prompts/get", "", `"name":"greet"`)
	meteo := modernBody(`4`, "tools/call", "", `"name":"météo"`)
	for name, tc := range map[string]struct {
		body   string
		header [][2]string // added in order, so a name may repeat
		ok     bool
	}{
		"tools/call mirrored":                                      {call, hdr("tools/call", "weather"), true},
		"resources/read mirrors the uri":                           {read, hdr("resources/read", "file:///a"), true},
		"prompts/get mirrored":                                     {prompt, hdr("prompts/get", "greet"), true},
		"Base64 sentinel":                                          {call, hdr("tools/call", "=?base64?d2VhdGhlcg==?="), true},
		"Base64 sentinel of non-ASCII":                             {meteo, hdr("tools/call", "=?base64?bcOpdMOpbw==?="), true},
		"no params.name, no Mcp-Name":                              {modernBody(`5`, "tools/call", "", ""), hdr("tools/call", ""), true},
		"other method, any params.name":                            {modernBody(`6`, "echo", "", `"name":{"x":1}`), hdr("echo", ""), true},
		"params.name also in another case":                         {modernBody(`7`, "tools/call", "", `"name":"weather","NAME":"evil"`), hdr("tools/call", "weather"), false},
		"params.name also in another case, header names the other": {modernBody(`7`, "tools/call", "", `"name":"weather","NAME":"evil"`), hdr("tools/call", "evil"), false}, // refused whichever value a resolver would pick
		"version missing":                                          {call, without(hdr("tools/call", "weather"), "MCP-Protocol-Version"), false},
		"version not the body's":                                   {call, with(hdr("tools/call", "weather"), "MCP-Protocol-Version", "2027-01-01"), false},
		"version repeated":                                         {call, append(hdr("tools/call", "weather"), [2]string{"MCP-Protocol-Version", "2026-07-28"}), false},
		"method missing":                                           {call, without(hdr("tools/call", "weather"), "Mcp-Method"), false},
		"method not the body's":                                    {call, with(hdr("tools/call", "weather"), "Mcp-Method", "tools/list"), false},
		"method in another case":                                   {call, with(hdr("tools/call", "weather"), "Mcp-Method", "Tools/Call"), false},
		"name missing":                                             {call, hdr("tools/call", ""), false},
		"name not the body's":                                      {call, hdr("tools/call", "news"), false},
		"name repeated":                                            {call, append(hdr("tools/call", "weather"), [2]string{"Mcp-Name", "news"}), false},
		"prompts/get name missing":                                 {prompt, hdr("prompts/get", ""), false},
		"prompts/get name not the body's":                          {prompt, hdr("prompts/get", "farewell"), false},
		"uri not the body's":                                       {read, hdr("resources/read", "file:///b"), false},
		"Base64 sentinel of another name":                          {call, hdr("tools/call", "=?base64?bmV3cw==?="), false},
		"malformed Base64 sentinel":                                {call, hdr("tools/call", "=?base64?!!?="), false},
		"sentinel without its ?=":                                  {call, hdr("tools/call", "=?base64?d2VhdGhlcg=="), false},
		"params.name not a string":                                 {modernBody(`7`, "tools/call", "", `"name":7`), hdr("tools/call", "7"), false},
		"sentinel for Mcp-Method":                                  {call, with(hdr("tools/call", "weather"), "Mcp-Method", "=?base64?dG9vbHMvY2FsbA==?="), false},
		"sentinel for the version":                                 {call, with(hdr("tools/call", "weather"), "MCP-Protocol-Version", "=?base64?MjAyNi0wNy0yOA==?="), false},
		"raw non-ASCII Mcp-Name":                                   {meteo, hdr("tools/call", "météo"), false},
	} {
		h := http.Header{}
		for _, kv := range tc.header {
			h.Add(kv[0], kv[1])
		}
		var env envelope
		if err := json.Unmarshal([]byte(tc.body), &env); err != nil {
			t.Fatalf("%s: the body does not parse: %v", name, err)
		}
		meta, err := readMeta([]byte(tc.body))
		if err != nil {
			t.Fatalf("%s: readMeta: %v; only checkHeaders may decide a case", name, err)
		}
		if err := checkHeaders(h, env.Method, meta.version, []byte(tc.body)); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want accepted %v", name, err, tc.ok)
		}
	}
}

// hdr is the headers of a request for method; name, when not empty, is its Mcp-Name.
func hdr(method, name string) [][2]string {
	h := [][2]string{{"MCP-Protocol-Version", "2026-07-28"}, {"Mcp-Method", method}}
	if name != "" {
		h = append(h, [2]string{"Mcp-Name", name})
	}
	return h
}

func with(h [][2]string, name, value string) [][2]string {
	out := append([][2]string(nil), h...)
	for i := range out {
		if out[i][0] == name {
			out[i][1] = value
		}
	}
	return out
}

func without(h [][2]string, name string) [][2]string {
	var out [][2]string
	for _, kv := range h {
		if kv[0] != name {
			out = append(out, kv)
		}
	}
	return out
}

func TestModernRequestWithMirroredHeadersIsServed(t *testing.T) {
	b := newModernBridge(t, nil)
	call := modernBody(`1`, "tools/call", "", `"name":"weather"`)
	if res := b.modern(t, "alice", call); res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
}

func TestModernRequestWhoseHeadersDoNotMirrorTheBodyIsRefusedBeforeAnyProcessStarts(t *testing.T) {
	b := newModernBridge(t, nil)
	call := modernBody(`1`, "tools/call", "", `"name":"weather"`)
	res := b.do(t, context.Background(), http.MethodPost, "alice", "", call,
		"MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "news")
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || rpcErrorCode(t, raw) != -32020 || !strings.Contains(string(raw), `"id":1`) { // HeaderMismatch, a spec value
		t.Fatalf("status %d, body %s; want 400 with HeaderMismatch (-32020) under the request's id", res.StatusCode, raw)
	}
	if b.m.Len() != 0 {
		t.Fatal("a process started for a request refused on its headers")
	}
}

func TestUpstreamResponsesThatAreUnusualButRoutableAlwaysAnswerTheClient(t *testing.T) {
	b := newModernBridge(t, nil)
	if got := readEvents(t, b.modern(t, "alice", modernBody(`1`, "dupresult", "", ""))); len(got) != 1 || got[0] != `{"jsonrpc":"2.0","id":1,"result":{"a":1,"a":2}}` {
		t.Fatalf("a result with a repeated key: %q, want it relayed under the client's id", got)
	}
	got := readEvents(t, b.modern(t, "alice", modernBody(`2`, "dupid", "", "")))
	if len(got) != 1 || !strings.Contains(got[0], `"id":2`) || !strings.Contains(got[0], "ambiguous response") || strings.Contains(got[0], "byw-") {
		t.Fatalf("a response with its id repeated: %q, want an error under the client's id, never the proxy's", got)
	}
}

// listenModern opens a subscriptions/listen stream as alice under the client id id and returns
// its events after the acknowledgement, which it checks.
func (b *bridgeHarness) listenModern(t *testing.T, ctx context.Context, id string) *events {
	t.Helper()
	ev := eventsOf(t, b.modernCtx(t, ctx, "alice", modernBody(id, "subscriptions/listen", "", `"notifications":{"toolsListChanged":true}`)))
	if got, _ := ev.next(); !strings.Contains(got, "notifications/subscriptions/acknowledged") || !strings.Contains(got, `"io.modelcontextprotocol/subscriptionId":`+id) {
		t.Fatalf("first event %s, want the acknowledgement under the client's own id", got)
	}
	return ev
}

func TestSubscriptionNotificationsReachOnlyTheirOwnListenStreamUnderTheClientsID(t *testing.T) {
	// Two clients of one user both listen under the id "L": the proxy's ids keep them apart.
	b := newModernBridge(t, nil)
	first, second := b.listenModern(t, context.Background(), `"L"`), b.listenModern(t, context.Background(), `"L"`)
	if _, n := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`1`, "notify", "", "")))); string(n) != "2" {
		t.Fatalf("notified %s listens, want 2", n)
	}
	readEvents(t, b.modern(t, "alice", modernBody(`2`, "endlistens", "", ""))) // ends both streams in order
	for name, ev := range map[string]*events{"first": first, "second": second} {
		got := ev.all()
		if len(got) != 2 || !strings.Contains(got[0], "notifications/tools/list_changed") ||
			!strings.Contains(got[0], `"io.modelcontextprotocol/subscriptionId":"L"`) || !strings.Contains(got[1], `"resultType":"complete"`) {
			t.Fatalf("%s stream got %q, want exactly its own list_changed then its completion", name, got)
		}
	}
}

func TestAListensFinalAnswerReachesItsStreamUnderTheClientsIDOnly(t *testing.T) {
	for name, tc := range map[string]struct {
		method string
		want   []string
	}{
		"graceful end naming its own subscription": {"endlistens", []string{`"resultType":"complete"`, `"io.modelcontextprotocol/subscriptionId":"L"`}},
		"graceful end naming another id":           {"endforeign", []string{`"resultType":"complete"`, `"io.modelcontextprotocol/subscriptionId":"L"`}},
		// An error answer has no result._meta to rewrite; it is still the upstream's own answer.
		"the upstream refuses the listen":        {"refuselisten", []string{`"code":-32602`}},
		"the end's subscription id is ambiguous": {"endrepeated", []string{`"code":-32603`}},
	} {
		t.Run(name, func(t *testing.T) {
			b := newModernBridge(t, nil)
			ev := b.listenModern(t, context.Background(), `"L"`)
			readEvents(t, b.modern(t, "alice", modernBody(`1`, tc.method, "", "")))
			got := ev.all()
			ok := len(got) == 1 && strings.Contains(got[0], `"id":"L"`) && !strings.Contains(got[0], "byw-")
			for _, w := range tc.want {
				ok = ok && strings.Contains(got[0], w)
			}
			if !ok {
				t.Fatalf("events %q, want one answer under the client's id with %q and no proxy id", got, tc.want)
			}
		})
	}
}

// teardownNotices is how many list_changed fakestdio's teardown writes before its cancellation.
const teardownNotices = 10

func TestAnUpstreamCancellingASubscriptionDeliversWhatCameBeforeThenClosesTheListenStream(t *testing.T) {
	// Over HTTP the server ends a subscription by closing its stream; notifications/cancelled is
	// stdio's, so it is not forwarded. What the upstream sent before it still is.
	b := newModernBridge(t, nil)
	ev := b.listenModern(t, context.Background(), `"L"`)
	readEvents(t, b.modern(t, "alice", modernBody(`1`, "teardown", "", "")))
	got := ev.all()
	ok := len(got) == teardownNotices
	for i := 0; ok && i < len(got); i++ {
		ok = strings.Contains(got[i], "notifications/tools/list_changed") && strings.Contains(got[i], fmt.Sprintf(`"n":%d`, i))
	}
	if !ok {
		t.Fatalf("events %q, want the %d list_changed sent before the teardown in order, then the stream closed", got, teardownNotices)
	}
	if ids := b.upstreamCancellations(t); len(ids) != 0 {
		t.Fatalf("the upstream saw cancellations %q for a subscription it ended itself", ids)
	}
}

func TestClosingAListenStreamCancelsTheSubscriptionOnTheUpstream(t *testing.T) {
	b := newModernBridge(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	b.listenModern(t, ctx, `"L"`)
	_, res := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`1`, "listens", "", ""))))
	var open []string
	if err := json.Unmarshal(res, &open); err != nil || len(open) != 1 {
		t.Fatalf("the upstream's open listens are %s (%v), want one", res, err)
	}
	cancel()
	if ids := b.awaitUpstreamCancellation(t); len(ids) != 1 || ids[0] != open[0] {
		t.Fatalf("upstream saw cancellations %q, want exactly the listen's id as it received it, %q", ids, open[0])
	}
}

// The bridge reads the headers it checks after the body (the protocol version and the mirrored
// method and name) from the header section only: a request trailer is never read as one, so it can
// neither refuse a good request nor stand in for a header the request left out.
func TestARequestTrailerIsNeverReadAsAHeader(t *testing.T) {
	body := modernBody(`1`, "tools/call", "", `"name":"weather"`)
	for _, tc := range []struct {
		name    string
		omit    string      // a mirrored header the request leaves out
		trailer http.Header // sent after the body
		want    int
		wantIn  string // in the response body
	}{
		{"a trailer contradicting the headers", "", http.Header{"Mcp-Name": {"news"}, "Mcp-Protocol-Version": {"1999-01-01"}}, http.StatusOK, `"id":1`},
		{"a trailer standing in for a missing header", "Mcp-Name", http.Header{"Mcp-Name": {"weather"}}, http.StatusBadRequest, "header Mcp-Name missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newModernBridge(t, nil)
			req, err := http.NewRequest(http.MethodPost, b.srv.URL, io.NopCloser(strings.NewReader(body))) // no length: chunked, with trailers
			if err != nil {
				t.Fatal(err)
			}
			h := modernHeaders(body)
			for i := 0; i+1 < len(h); i += 2 {
				if h[i] != tc.omit {
					req.Header.Set(h[i], h[i+1])
				}
			}
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set(userHeader, "alice")
			req.Trailer = tc.trailer
			res, err := b.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = res.Body.Close() })
			if raw, _ := io.ReadAll(res.Body); res.StatusCode != tc.want || !strings.Contains(string(raw), tc.wantIn) {
				t.Fatalf("status %d, body %s; want %d with %q, the trailer unread", res.StatusCode, raw, tc.want, tc.wantIn)
			}
		})
	}
}
