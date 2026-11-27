package lifecycle

import (
	"io"
	"testing"
	"time"
)

// A CutBody is started once its first byte is read, and then reads to its whole body, a reset or
// its end, as Finish, Cut or Stop says.
func TestACutBodyStartsOnItsFirstByteAndEndsAsItIsTold(t *testing.T) {
	for name, tc := range map[string]struct {
		end      func(*CutBody)
		want     string
		wantFail bool
	}{
		"finished": {(*CutBody).Finish, "body", false},
		"cut":      {(*CutBody).Cut, "b", true},
		"stopped":  {(*CutBody).Stop, "b", false},
	} {
		t.Run(name, func(t *testing.T) {
			b := NewCutBody("body")
			select {
			case <-b.Started():
				t.Fatal("started before anything read it")
			case <-time.After(10 * time.Millisecond):
			}
			first := make([]byte, 1)
			if _, err := io.ReadFull(b, first); err != nil {
				t.Fatal(err)
			}
			select {
			case <-b.Started():
			case <-time.After(5 * time.Second):
				t.Fatal("not started once its first byte was read")
			}
			tc.end(b)
			type read struct {
				rest []byte
				err  error
			}
			got := make(chan read, 1)
			go func() { rest, err := io.ReadAll(b); got <- read{rest, err} }()
			var r read
			select {
			case r = <-got:
			case <-time.After(5 * time.Second):
				t.Fatal("the rest of the body never ended")
			}
			rest, err := r.rest, r.err
			if got := string(first) + string(rest); got != tc.want || (err != nil) != tc.wantFail {
				t.Errorf("read %q, error %v; want %q, failing %v", got, err, tc.want, tc.wantFail)
			}
		})
	}
}
