package logsink

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Records decodes each JSON line into the caller's type, in order, skipping blank lines.
func TestRecordsDecodesEachLineInOrder(t *testing.T) {
	type rec struct{ Msg string }
	got := Records[rec](t, "{\"msg\":\"a\"}\n\n{\"msg\":\"b\",\"extra\":1}\n")
	if want := []rec{{"a"}, {"b"}}; !slices.Equal(got, want) {
		t.Fatalf("records %v, want %v", got, want)
	}
}

// A line that is not JSON fails the test, naming the line.
func TestRecordsFailsOnALineThatIsNotJSON(t *testing.T) {
	ft := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Records[map[string]any](ft, "{\"msg\":\"a\"}\nnot json\n")
	}()
	<-done
	if ft.msg == "" || !strings.HasSuffix(ft.msg, ": not json") {
		t.Fatalf("Fatalf message %q, want one naming the line", ft.msg)
	}
}

// fatalRecorder records Fatalf and stops the goroutine, as testing.T does.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (f *fatalRecorder) Helper() {}

func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}
