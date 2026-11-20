//go:build linux || darwin

package stdio

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Only the Send itself can count as traffic here: the -mcp fake answers no notification, unlike the
// echo fake, whose reply would restart the timer. A Send that writes nothing is not traffic.
func TestASendRestartsTheIdleTimerOnlyIfItWritesItsMessage(t *testing.T) {
	note := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name    string
		ctx     context.Context
		msg     []byte
		wantErr error
		traffic bool
	}{
		{name: "a message that gets no reply restarts it", ctx: context.Background(), msg: note, traffic: true},
		{name: "a request that has already ended writes nothing and leaves it", ctx: cancelled, msg: note, wantErr: context.Canceled},
		{name: "an invalid message writes nothing and leaves it", ctx: context.Background(), msg: []byte("two\nlines"), wantErr: ErrInvalidMessage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} })
			p := h.get(t, "s1", alice)

			h.clk.Advance(DefaultIdleTimeout - time.Minute)
			if err := p.Send(tc.ctx, tc.msg); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Send = %v, want %v", err, tc.wantErr)
			}
			h.clk.Advance(time.Minute) // the idle timeout since the process was last used
			if tc.traffic {
				if stops := h.log.with("stopping upstream process"); len(stops) != 0 {
					t.Fatalf("stop records = %v, want none: the Send was traffic within the idle timeout", stops)
				}
				h.clk.Advance(DefaultIdleTimeout - time.Minute) // the idle timeout since the Send
			}
			// timer callbacks run inside Advance: the stop is logged by now
			if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "idle" {
				t.Fatalf("stop records = %v, want one with reason=idle", stops)
			}
			waitDone(t, p)
		})
	}
}
