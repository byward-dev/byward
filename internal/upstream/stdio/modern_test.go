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
		got := readEvents(t, b.post(t, "alice", "", modernBody(id, "echo", "", fmt.Sprintf(`"n":%d`, i))))
		gotID, res := lastResult(t, got)
		if gotID != id || !strings.Contains(string(res), fmt.Sprintf(`"n":%d`, i)) {
			t.Fatalf("request %d: id %s, result %s; want the client's own id and its echo", i, gotID, res)
		}
	}
	if b.m.Len() != 1 {
		t.Fatalf("Len = %d after three requests by one user, want 1", b.m.Len())
	}
	readEvents(t, b.post(t, "bob", "", modernBody(`1`, "echo", "", "")))
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
	if _, n := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`9`, "discovers", "", "")))); string(n) != "1" {
		t.Fatalf("the upstream was probed %s times, want once", n)
	}
}

func TestProgressWrittenJustBeforeTheResultIsNeverLost(t *testing.T) {
	b := newModernBridge(t, nil)
	for i := range 20 {
		events := readEvents(t, b.post(t, "alice", "", modernBody(`1`, "burst", `"progressToken":7`, `"n":10`)))
		if len(events) != 11 || !strings.Contains(events[10], `"result":"done"`) {
			t.Fatalf("round %d: %d events, want 10 progress then the result: %q", i, len(events), events)
		}
	}
}

func TestModernRequestsToALegacyOnlyUpstreamGetTheFallback400AfterOneProbe(t *testing.T) {
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} }) // answers no server/discover
	fallback := func(what string) {
		t.Helper()
		res := b.post(t, "alice", "", modernBody(`1`, "tools/list", "", ""))
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
	b.post(t, "alice", "", modernBody(`1`, "tools/list", "", ""))
	eventually(t, "the probed process to be stopped", func() bool { return b.m.Len() == 0 })
	b.clk.Advance(legacyVerdictTTL)
	b.post(t, "alice", "", modernBody(`2`, "tools/list", "", ""))
	eventually(t, "a second probe", func() bool { return b.stops("not_modern") == 2 })
}

func TestUpstreamThatNeverAnswersTheProbeIsLegacy(t *testing.T) {
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp", "-silentdiscover"} })
	b.bridge.probeTimeout = 50 * time.Millisecond
	res := b.post(t, "alice", "", modernBody(`1`, "tools/list", "", ""))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want the fallback 400", res.StatusCode)
	}
	eventually(t, "the probed process to be stopped", func() bool { return b.stops("not_modern") == 1 })
}

func TestAmbiguousModernRequestsAreRefusedBeforeAnyProcessStarts(t *testing.T) {
	// Which messages are ambiguous is locate's business (rewrite_test.go); this checks the wiring.
	b := newModernBridge(t, nil)
	for name, body := range map[string]string{
		"duplicate id":         `{"jsonrpc":"2.0","id":1,"id":2,"method":"echo","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"id in another case":   `{"jsonrpc":"2.0","ID":1,"method":"echo","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"object progressToken": modernBody(`1`, "echo", `"progressToken":{"a":1}`, ""),
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

func TestProxyIDsNeverRepeatAcrossTheUsersProcesses(t *testing.T) {
	// A respawned process gets a new userConn; its ids must not restart where the old one's began.
	b := newModernBridge(t, nil)
	first, second := &userConn{ids: &b.bridge.next, byID: map[string]*modernRequest{}, byToken: map[string]*modernRequest{}},
		&userConn{ids: &b.bridge.next, byID: map[string]*modernRequest{}, byToken: map[string]*modernRequest{}}
	a, c := first.register([]byte(`1`), []byte(`"t"`), false), second.register([]byte(`1`), []byte(`"t"`), false)
	if a.proxyID == c.proxyID || a.proxyTok == c.proxyTok {
		t.Fatalf("ids %s/%s and %s/%s repeat across userConns", a.proxyID, a.proxyTok, c.proxyID, c.proxyTok)
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
	if id, _ := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`5`, "echo", "", "")))); id != `5` {
		t.Fatalf("the request got id %s, want its own answer", id)
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

func TestClosingTheStreamCancelsTheRequestOnTheUpstream(t *testing.T) {
	b := newModernBridge(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	res := b.do(t, ctx, http.MethodPost, "alice", "", modernBody(`"mine"`, "hold", "", ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	cancel()
	var got json.RawMessage
	eventually(t, "the upstream to see the cancellation", func() bool {
		_, got = lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`2`, "cancelled", "", ""))))
		return string(got) != "[]" && string(got) != "null"
	})
	var ids []string
	if err := json.Unmarshal(got, &ids); err != nil || len(ids) != 1 || ids[0] == "mine" {
		t.Fatalf("upstream saw cancellations %s; want one, under the proxy's id, not the client's", got)
	}
}

func TestAClientsCancellationNeverReachesTheUpstream(t *testing.T) {
	// Over HTTP a request is cancelled by closing its stream. A cancellation sent as a message
	// names an id that, on the shared process, could be another client's.
	b := newModernBridge(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	held := eventsOf(t, b.do(t, ctx, http.MethodPost, "alice", "", modernBody(`"mine"`, "hold", "", "")))
	for _, id := range []string{`"mine"`, `"byw-1"`, `"byw-2"`} {
		notif := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + id +
			`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		if res := b.post(t, "alice", "", notif); res.StatusCode != http.StatusAccepted {
			t.Fatalf("cancellation of %s: status %d, want 202", id, res.StatusCode)
		}
	}
	_, got := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`2`, "cancelled", "", ""))))
	var ids []string
	if err := json.Unmarshal(got, &ids); err != nil || len(ids) != 0 {
		t.Fatalf("upstream saw cancellations %s, want none", got)
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
			held := eventsOf(t, b.do(t, ctx, http.MethodPost, "alice", "", modernBody(`1`, "hold", heldMeta, "")))
			events := readEvents(t, b.post(t, "alice", "", modernBody(`2`, "log", logLevel, `"tag":"x"`)))
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
	_, res := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`1`, "ask", "", ""))))
	if !strings.Contains(string(res), `"code":-32603`) {
		t.Fatalf("the upstream's request got %s, want a -32603 error", res)
	}
}

func TestUnroutableUpstreamMessagesAreDroppedAndLogged(t *testing.T) {
	for name, tc := range map[string]struct{ method, msg, reason string }{
		"notification for no request":     {"stray", "upstream notification dropped", "notification_unrouted"},
		"progress for no request":         {"strayprogress", "upstream notification dropped", "progress_unrouted"},
		"response for no waiting request": {"strayresponse", "upstream response for no waiting request", "response_unrouted"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newModernBridge(t, nil)
			if events := readEvents(t, b.post(t, "alice", "", modernBody(`1`, tc.method, "", ""))); len(events) != 1 {
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
	held := eventsOf(t, b.do(t, ctx, http.MethodPost, "alice", "", modernBody(`"h"`, "hold", "", "")))
	readEvents(t, b.post(t, "alice", "", modernBody(`2`, "crash", "", "")))
	if got := held.all(); len(got) != 1 || !strings.Contains(got[0], "upstream process exited") || !strings.Contains(got[0], `"id":"h"`) {
		t.Fatalf("held request got %q, want -32603 under its own id", got)
	}
	eventually(t, "the crashed process to be gone", func() bool { return b.m.Len() == 0 })
	if id, _ := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`3`, "echo", "", "")))); id != `3` {
		t.Fatalf("the next request got id %s", id)
	}
}

func TestAnAnswerWrittenJustBeforeTheProcessExitsStillReachesTheClient(t *testing.T) {
	b := newModernBridge(t, nil)
	for i := range 10 {
		_, res := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`1`, "answerexit", "", ""))))
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
	readEvents(t, b.post(t, "alice", "", modernBody(`1`, "echo", "", "")))
	key := "user:" + alice.user()
	b.bridge.mu.Lock()
	old := b.bridge.users[key]
	successor := &userConn{}
	b.bridge.users[key] = successor
	b.bridge.mu.Unlock()
	old.p.stop("test")
	<-old.ended // closed only after the old pump's cleanup has run
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
	res := b.post(t, "alice", "", modernBody(`1`, "echo", "", ""))
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") != busyRetryAfter {
		t.Fatalf("status %d, Retry-After %q; want 503 and %s", res.StatusCode, res.Header.Get("Retry-After"), busyRetryAfter)
	}
	if recs := b.log.with("stdio process cap full: every process is in use"); len(recs) != 1 || recs[0].attrs["reason"] != "process_cap" {
		t.Fatalf("records %v", recs)
	}
}

func TestModernNotificationsAre202AndClientResponsesAre400(t *testing.T) {
	b := newModernBridge(t, nil)
	notif := `{"jsonrpc":"2.0","method":"notifications/x","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	if res := b.post(t, "alice", "", notif); res.StatusCode != http.StatusAccepted {
		t.Fatalf("notification: status %d, want 202", res.StatusCode)
	}
	resp := `{"jsonrpc":"2.0","id":1,"result":{},"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	if res := b.post(t, "alice", "", resp); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("client response: status %d, want 400", res.StatusCode)
	}
}
