//go:build linux || darwin

package stdio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
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

// result is the JSON-RPC result of the last event, with its id.
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
	// them apart on the shared process.
	b := newModernBridge(t, nil)
	readEvents(t, b.post(t, "alice", "", modernBody(`0`, "echo", "", ""))) // probe once, up front
	const clients, rounds = 8, 5
	var wg sync.WaitGroup
	for c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				tag := fmt.Sprintf("client-%d-round-%d", c, r)
				res := b.do(t, context.Background(), http.MethodPost, "alice", "",
					modernBody(`1`, "progress", `"progressToken":"p"`, `"tag":"`+tag+`"`))
				events := eventsOf(t, res).all()
				if len(events) != 4 {
					t.Errorf("%s: %d events, want 3 progress and a result: %q", tag, len(events), events)
					return
				}
				for _, e := range events[:3] {
					if !strings.Contains(e, `"progressToken":"p"`) || !strings.Contains(e, `"message":"`+tag+`"`) {
						t.Errorf("%s got another stream's progress, or a proxy token: %s", tag, e)
					}
				}
				if id, result := lastResult(t, events); id != `1` || !strings.Contains(string(result), tag) {
					t.Errorf("%s got result %s with id %s", tag, result, id)
				}
			}
		}()
	}
	wg.Wait()
	if b.m.Len() != 1 {
		t.Fatalf("Len = %d, want one process for the user", b.m.Len())
	}
}

func TestLegacyOnlyUpstreamAnswersModernRequestsWithTheFallback400(t *testing.T) {
	b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} }) // no server/discover
	for i := range 2 {
		res := b.post(t, "alice", "", modernBody(`1`, "tools/list", "", ""))
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusBadRequest || rpcErrorCode(t, body) != codeInvalidRequest {
			t.Fatalf("request %d: status %d, body %s; want the non-modern 400 dual-era clients fall back on", i, res.StatusCode, body)
		}
		if i == 0 {
			eventually(t, "the probed process to be stopped", func() bool { return b.m.Len() == 0 })
		} else if b.m.Len() != 0 {
			t.Fatal("the verdict was not kept: a second probe process started")
		}
	}
	// The legacy era still works on the same upstream.
	if s := b.initialize(t, "alice"); s == "" {
		t.Fatal("no MCP session")
	}
}

func TestAmbiguousModernRequestsAreRefusedBeforeAnyProcessStarts(t *testing.T) {
	b := newModernBridge(t, nil)
	for name, body := range map[string]string{
		"duplicate id":             `{"jsonrpc":"2.0","id":1,"id":2,"method":"echo","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"duplicate progressToken":  modernBody(`1`, "echo", `"progressToken":"a","progressToken":"b"`, ""),
		"object progressToken":     modernBody(`1`, "echo", `"progressToken":{"a":1}`, ""),
		"fractional progressToken": modernBody(`1`, "echo", `"progressToken":1.5`, ""),
		"duplicate _meta":          `{"jsonrpc":"2.0","id":1,"method":"echo","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"_meta":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			res := b.post(t, "alice", "", body)
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusBadRequest || rpcErrorCode(t, raw) != codeInvalidRequest {
				t.Fatalf("status %d, body %s; want 400 -32600", res.StatusCode, raw)
			}
		})
	}
	if b.m.Len() != 0 {
		t.Fatalf("Len = %d, want no process for refused requests", b.m.Len())
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
		return string(got) != "[]"
	})
	var ids []string
	if err := json.Unmarshal(got, &ids); err != nil || len(ids) != 1 || !strings.HasPrefix(ids[0], "byw-") {
		t.Fatalf("upstream saw cancellations %s; want one, for the proxy's id of the held request", got)
	}
}

func TestLogMessagesReachARequestOnlyWhenItIsTheOneThatAskedForThem(t *testing.T) {
	logLevel := `"io.modelcontextprotocol/logLevel":"info"`
	t.Run("one asking", func(t *testing.T) {
		b := newModernBridge(t, nil)
		events := readEvents(t, b.post(t, "alice", "", modernBody(`1`, "log", logLevel, `"tag":"x"`)))
		if len(events) != 2 || !strings.Contains(events[0], "notifications/message") {
			t.Fatalf("events %q, want the log message then the result", events)
		}
	})
	t.Run("two asking", func(t *testing.T) {
		b := newModernBridge(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		held := eventsOf(t, b.do(t, ctx, http.MethodPost, "alice", "", modernBody(`1`, "hold", logLevel, "")))
		events := readEvents(t, b.post(t, "alice", "", modernBody(`2`, "log", logLevel, `"tag":"x"`)))
		if len(events) != 1 {
			t.Fatalf("events %q: with two requests asking, the uncorrelated log message must reach neither", events)
		}
		cancel()
		if got := held.all(); len(got) != 0 {
			t.Fatalf("the held request got %q", got)
		}
		if len(b.log.with("upstream notification dropped")) != 1 {
			t.Fatal("the dropped log message was not logged")
		}
	})
}

func TestUpstreamRequestsInTheModernEraAreAnsweredWithAnError(t *testing.T) {
	b := newModernBridge(t, nil)
	_, res := lastResult(t, readEvents(t, b.post(t, "alice", "", modernBody(`1`, "ask", "", ""))))
	if !strings.Contains(string(res), `"code":-32603`) {
		t.Fatalf("the upstream's request got %s, want a -32603 error", res)
	}
}

func TestUnrelatedUpstreamNotificationsAreDroppedAndLogged(t *testing.T) {
	b := newModernBridge(t, nil)
	if events := readEvents(t, b.post(t, "alice", "", modernBody(`1`, "stray", "", ""))); len(events) != 1 {
		t.Fatalf("events %q, want only the result", events)
	}
	if recs := b.log.with("upstream notification dropped"); len(recs) != 1 || recs[0].attrs["reason"] != "notification_unrouted" {
		t.Fatalf("drop records %v", recs)
	}
}

func TestModernCrashFailsInFlightRequestsAndTheNextRequestRespawns(t *testing.T) {
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
