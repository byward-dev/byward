//go:build linux || darwin

package stdio

import (
	"context"
	"errors"
	"testing"
)

// A write that fails for a reason other than the request's end means the process can no longer
// take messages: ErrExited, which the bridge answers 404 "session not found". Nothing was written,
// so framing is intact and the process is not stopped for it.
func TestSendToAProcessThatClosedItsStdinIsErrExitedAndDoesNotStopIt(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	if got := call(t, p, "closestdin"); got != "closed" {
		t.Fatalf("got %q, want closed", got)
	}
	// Wrapped, so it came from the failed write, not from Send's check for a process already stopping.
	if err := p.Send(context.Background(), []byte("ping")); !errors.Is(err, ErrExited) || err == ErrExited {
		t.Fatalf("Send to a process that closed its stdin = %v, want ErrExited wrapping the write's error", err)
	}
	if stops := h.log.with("stopping upstream process"); len(stops) != 0 {
		t.Fatalf("stop records = %v, want none: nothing reached stdin", stops)
	}
}
