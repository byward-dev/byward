//go:build linux || darwin

package stdio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

// fillStdin writes to p's stdin until a write would block, so the pipe is full for a write of
// any size, whatever its capacity: chunks first, then single bytes, straight to the non-blocking
// fd, each phase ending only on EAGAIN, so no timer can end it early. The process must not be
// reading; a pipe that takes far more than any pipe holds means it is, and fails the test rather
// than filling forever. It returns how many bytes it wrote.
func fillStdin(t *testing.T, p *Process) int {
	t.Helper()
	rc, err := p.stdin.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	written, werr := 0, error(nil)
	err = rc.Write(func(fd uintptr) bool {
		for _, chunk := range [][]byte{bytes.Repeat([]byte("x"), 4096), []byte("x")} {
			for written <= 16<<20 {
				n, err := syscall.Write(int(fd), chunk)
				if n > 0 {
					written += n
				}
				if err == nil || errors.Is(err, syscall.EINTR) {
					continue
				}
				if !errors.Is(err, syscall.EAGAIN) {
					werr = err
					return true
				}
				break // this size no longer fits: on to the next, or full
			}
		}
		return true
	})
	switch {
	case err != nil || werr != nil:
		t.Fatalf("filling stdin: %v %v", err, werr)
	case written > 16<<20:
		t.Fatalf("filling stdin: %d bytes written and no write blocked; is the process reading?", written)
	}
	return written
}

// saidOnStderr waits until the upstream process has written line to its stderr; on a timeout it
// fails with every line it did write, which says why (a bad flag, a short read).
func saidOnStderr(t *testing.T, h *harness, line string) {
	t.Helper()
	var lines []any
	for end := time.Now().Add(guard); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		lines = lines[:0]
		for _, rec := range h.log.with("upstream stderr") {
			if rec.attrs["line"] == line {
				return
			}
			lines = append(lines, rec.attrs["line"])
		}
	}
	t.Fatalf("the upstream process never wrote %q to stderr; it wrote %q", line, lines)
}

// A Send whose message is written whole but whose newline write is cut by its request's end
// stops the process for a partial write: without its newline the message breaks framing (#563).
// The stdin pipe is filled until full, then the process frees exactly the message's size of it,
// so the message fits and the newline blocks until the request's deadline cuts it. The size is
// the kernel's page size, as a pipe counted in pages (Linux) frees space a page at a time: with
// 4K, 16K or 64K pages alike, one page freed is one message that fits, and nothing more. The test
// then reads what the pipe holds, to see the scenario happened: the message's last byte last, and
// no newline after it (a message cut part-way would end before its last byte).
func TestASendWhoseNewlineWriteIsCutStopsTheProcessForAPartialWrite(t *testing.T) {
	size := os.Getpagesize()
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, fmt.Sprintf("-readn=%d", size)} })
	p := h.get(t, "s1", alice)
	saidOnStderr(t, h, "waiting") // it listens for SIGUSR1, and reads nothing until it
	filled := fillStdin(t, p)
	if err := syscall.Kill(p.PID(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	saidOnStderr(t, h, fmt.Sprintf("read %d", size))
	msg := append(bytes.Repeat([]byte("m"), size-1), 'z')                 // its last byte marks it written whole
	ctx, cancel := context.WithTimeout(context.Background(), time.Second) // its deadline cuts the blocked newline
	defer cancel()
	if err := p.Send(ctx, msg); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send whose newline write was cut = %v; want context.DeadlineExceeded", err)
	}
	if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "partial_write" {
		t.Fatalf("stop records = %v; want one with reason=partial_write", stops)
	}
	// The pipe holds the fill less what was freed, then the whole message, and no newline.
	if err := syscall.Kill(p.PID(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	saidOnStderr(t, h, fmt.Sprintf("rest %d %q", filled-size+len(msg), "z"))
}
