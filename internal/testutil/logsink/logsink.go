// Package logsink is a log destination that goroutines of the code under test write to while the
// test reads it.
package logsink

import (
	"bytes"
	"sync"
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
