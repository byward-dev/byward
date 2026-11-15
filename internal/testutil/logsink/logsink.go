// Package logsink is a log destination that goroutines of the code under test write to while the
// test reads it.
package logsink

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// Buffer is a bytes.Buffer whose Write and String are safe to call from several goroutines.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p to the buffer.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Records decodes each non-empty line of log, a JSON log, into a T, in order; a line that is not
// JSON fails the test. Callers filter the records and pick the first or last match themselves.
func Records[T any](t testing.TB, log string) []T {
	t.Helper()
	var out []T
	for line := range strings.SplitSeq(log, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r T
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line is not JSON (%v): %s", err, line)
		}
		out = append(out, r)
	}
	return out
}
