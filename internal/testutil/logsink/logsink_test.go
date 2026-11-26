package logsink

import (
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/recordtb"
)

// Records decodes each JSON line into the caller's type, in order, skipping empty and blank lines.
func TestRecordsDecodesEachLineInOrder(t *testing.T) {
	type rec struct{ Msg string }
	got := Records[rec](t, "{\"msg\":\"a\"}\n\n \t\n{\"msg\":\"b\",\"extra\":1}\n")
	if want := []rec{{"a"}, {"b"}}; !slices.Equal(got, want) {
		t.Fatalf("records %v, want %v", got, want)
	}
}

// A line that is not JSON fails the test, naming the line.
func TestRecordsFailsOnALineThatIsNotJSON(t *testing.T) {
	rep := recordtb.Run(t, func(tb testing.TB) { Records[map[string]any](tb, "{\"msg\":\"a\"}\nnot json\n") })
	if len(rep.Fatals) != 1 || !strings.HasSuffix(rep.Fatals[0], ": not json") {
		t.Fatalf("fatals %q, want one naming the line", rep.Fatals)
	}
}
