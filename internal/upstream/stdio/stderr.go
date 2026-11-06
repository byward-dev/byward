//go:build linux || darwin

package stdio

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"time"
)

// MaxStderrLine is the longest stderr line logged; the rest of a longer line is dropped
// (ADR-0021 §6).
const MaxStderrLine = 8 << 10

// Stderr rate limit per upstream process: a burst, then a steady rate. Lines over the limit are
// still read (the pipe is always drained) but only counted.
const (
	stderrBurst = 200
	stderrRate  = 20 // lines per second
)

// drainStderr reads r until EOF and logs each line as one record. It never stops reading early,
// so an upstream process cannot block on a full stderr pipe.
func drainStderr(r io.Reader, log *slog.Logger, now func() time.Time) {
	br := bufio.NewReaderSize(r, MaxStderrLine+1)
	lim := limiter{tokens: stderrBurst, last: now()}
	for {
		line, truncated, err := readLine(br)
		if len(line) > 0 {
			if lim.allow(now()) {
				lim.flush(log)
				log.Info("upstream stderr", "line", string(line), "truncated", truncated)
			} else {
				lim.suppressed++
			}
		}
		if err != nil {
			lim.flush(log)
			return
		}
	}
}

// readLine returns the next line without its line ending, cut to MaxStderrLine bytes.
func readLine(br *bufio.Reader) (line []byte, truncated bool, err error) {
	b, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		line, truncated = bytes.Clone(b[:MaxStderrLine]), true
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = br.ReadSlice('\n')
		}
		return line, truncated, err
	}
	return bytes.Clone(bytes.TrimRight(b, "\r\n")), false, err
}

// limiter is a token bucket; it is used by one goroutine only.
type limiter struct {
	tokens     float64
	last       time.Time
	suppressed int
}

func (l *limiter) allow(t time.Time) bool {
	l.tokens = min(stderrBurst, l.tokens+t.Sub(l.last).Seconds()*stderrRate)
	l.last = t
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func (l *limiter) flush(log *slog.Logger) {
	if l.suppressed > 0 {
		log.Warn("upstream stderr lines suppressed", "suppressed", l.suppressed)
		l.suppressed = 0
	}
}
