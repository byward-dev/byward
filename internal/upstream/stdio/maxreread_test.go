package stdio

import (
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// No stderr line is redacted unread for its length: the redactor reads a line it reads more than
// once (one holding a , % or \, or not printable) up to logging.MaxReread, which must be at least
// the longest line this package logs (#657).
func TestNoStderrLineIsRedactedUnreadForItsLength(t *testing.T) {
	if logging.MaxReread < MaxStderrLine {
		t.Fatalf("logging.MaxReread is %d bytes, below MaxStderrLine (%d): a stderr line with a comma would be redacted unread", logging.MaxReread, MaxStderrLine)
	}
}
