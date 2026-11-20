//go:build linux || darwin

package stdio

import (
	"context"
	"testing"
	"time"
)

// A notification gets no reply, so only the Send itself can count as traffic: the -mcp fake
// answers no notification, unlike the echo fake, whose reply would restart the timer.
func TestASendThatGetsNoReplyRestartsTheIdleTimer(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} })
	p := h.get(t, "s1", alice)

	h.clk.Advance(DefaultIdleTimeout - time.Minute)
	if err := p.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	h.clk.Advance(DefaultIdleTimeout - time.Minute)
	if stops := h.log.with("stopping upstream process"); len(stops) != 0 {
		t.Fatalf("stop records = %v, want none: the Send was traffic within the idle timeout", stops)
	}
	h.clk.Advance(time.Minute) // timer callbacks run inside Advance: the stop is logged by now
	waitDone(t, p)
	if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "idle" {
		t.Fatalf("stop records = %v, want one with reason=idle, a full idle timeout after the Send", stops)
	}
}
