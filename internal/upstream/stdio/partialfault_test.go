//go:build linux || darwin

package stdio

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A partial write is a fault of the process, not a stop byward chose: a live subscriptions/listen
// on the same process ends with the fault answer, never the completion result a chosen end gets
// (2026-07-28 subscriptions), so the MCP client does not take a broken write for a clean end
// (#573). The process stops reading stdin ("block"); a request far larger than any pipe then
// writes part of itself before its deadline cuts it, which stops the process for a partial write;
// once the kill grace has passed, the process exits and the listen ends. The partial write's
// place among the faults is pinned with the others in
// TestAnIdleTimeoutStopOrShutdownCountsAsBywardsChoiceButAFaultNeverDoes; this is what a client
// sees of it.
func TestAPartialWriteEndsALiveListenOnItsProcessWithTheFaultAnswer(t *testing.T) {
	b := newModernBridge(t, nil)
	listen := b.listenModern(t, context.Background(), `"L"`)
	if _, res := lastResult(t, readEvents(t, b.modern(t, "alice", modernBody(`1`, "block", "", "")))); string(res) != `"blocking"` {
		t.Fatalf("block = %s; want the process to say it stopped reading", res)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second) // long enough to read the body and start the write
	defer cancel()
	// Four times what a pipe holds (16 pages by default on Linux, whatever the page size; 64 KiB at
	// most on darwin), so the write is always cut part-way, and the body small enough to read and
	// start writing well within the deadline, even under -race.
	pipe := 16 * os.Getpagesize()
	if runtime.GOOS == "darwin" {
		pipe = 64 << 10
	}
	big := modernBody(`2`, "echo", "", `"pad":"`+strings.Repeat("a", 4*pipe)+`"`)
	w := b.serve(ctx, http.MethodPost, "alice", "", big, modernHeaders(big)...)
	if got := b.stops("partial_write"); got != 1 {
		t.Fatalf("%d partial_write stops (stops %v; the cut request got %d %q); want the cut write to stop the process once",
			got, b.log.with("stopping upstream process"), w.Code, w.Body)
	}
	b.clk.Advance(DefaultKillGrace) // SIGTERM: the process exits, and its stdout closes
	got := listen.all()
	const fault = `{"jsonrpc":"2.0","id":"L","error":{"code":-32603,"message":"upstream process exited"}}`
	if len(got) != 1 || !sameJSON(t, []byte(got[0]), fault) {
		t.Fatalf("the live listen got %q; want only the fault answer %s, never a completion", got, fault)
	}
}
