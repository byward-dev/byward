//go:build linux || darwin

package stdio

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

var (
	// ErrExited is returned by Send once the upstream process has exited or is stopping.
	ErrExited = errors.New("stdio: upstream process exited")
	// ErrInvalidMessage is returned by Send for an empty message or one with an embedded newline,
	// which would break newline-delimited framing.
	ErrInvalidMessage = errors.New("stdio: message is empty or contains a newline")

	errMessageTooLarge = errors.New("stdio: upstream message over the size limit")
)

var newline = []byte{'\n'}

// Process is one upstream process: newline-delimited JSON-RPC in on stdin and out on stdout,
// relayed as bytes. Create it with Manager.Get.
type Process struct {
	pid      int
	log      *slog.Logger
	clock    Clock
	idleFor  time.Duration
	grace    time.Duration
	maxMsg   int
	stdin    *os.File
	messages chan []byte
	abandon  chan struct{} // closed when the stdout reader must give up delivering
	done     chan struct{}
	readers  sync.WaitGroup
	wmu      sync.Mutex // serialises writes to stdin

	mu       sync.Mutex
	idle     Timer
	held     int       // open leases; the idle timer does not run while any is held
	traffic  time.Time // the last stdin or stdout message, or the start
	evicted  bool      // stopped to make room under a process cap
	timers   []Timer
	stopping bool
	exited   bool

	stdinOnce, abandonOnce sync.Once
	waitErr                error
}

// processOptions are the per-upstream settings a Process needs.
type processOptions struct {
	log     *slog.Logger // already tagged with upstream, process and user key
	clock   Clock
	idleFor time.Duration
	grace   time.Duration
	maxMsg  int
}

// startProcess takes over a started cmd and our ends of its pipes: it arms the idle timer and
// starts the stdout reader, the stderr drain and the reaper. onExit runs once the process is gone.
func startProcess(cmd *exec.Cmd, stdin, stdout, stderr *os.File, sessionDir string, o processOptions, onExit func()) *Process {
	p := &Process{
		pid: cmd.Process.Pid, log: o.log, clock: o.clock, idleFor: o.idleFor, grace: o.grace, maxMsg: o.maxMsg,
		stdin: stdin, messages: make(chan []byte, 16), abandon: make(chan struct{}), done: make(chan struct{}),
		traffic: o.clock.Now(),
	}
	p.mu.Lock() // the timer may fire before the assignment completes; stop reads p.idle under p.mu
	p.idle = o.clock.AfterFunc(o.idleFor, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.held == 0 { // checked and stopped under one lock: a lease taken meanwhile keeps the process
			p.stopLocked("idle")
		}
	})
	p.mu.Unlock()
	p.readers.Add(2)
	go p.readStdout(stdout)
	go func() {
		defer p.readers.Done()
		drainStderr(stderr, o.log, o.clock.Now)
	}()
	go p.wait(cmd, stdout, stderr, sessionDir, onExit)
	o.log.Info("upstream process started")
	return p
}

// PID is the upstream process ID, which is also its process group ID.
func (p *Process) PID() int { return p.pid }

// Messages delivers each stdout line, without its line ending, exactly as the upstream wrote it.
// It is closed when stdout is closed.
func (p *Process) Messages() <-chan []byte { return p.messages }

// Done is closed after the process has exited, its process group is killed, its pipes are closed
// and its session directory is removed.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err is the exit error from the process once Done is closed.
func (p *Process) Err() error {
	<-p.done
	return p.waitErr
}

// Send writes msg and a newline to the process's stdin. ctx bounds the write; a write cut short
// breaks framing, so the process is then stopped.
func (p *Process) Send(ctx context.Context, msg []byte) error {
	if len(msg) == 0 || bytes.IndexByte(msg, '\n') >= 0 {
		return ErrInvalidMessage
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if p.isStopping() {
		return ErrExited
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cancelled := context.AfterFunc(ctx, func() { _ = p.stdin.SetWriteDeadline(time.Unix(1, 0)) })
	n, err := p.stdin.Write(msg) // then the newline: no copy of a message up to the body limit
	if err == nil {
		var m int
		m, err = p.stdin.Write(newline)
		n += m
	}
	if !cancelled() {
		_ = p.stdin.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		if n > 0 {
			p.stop("partial_write")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %v", ErrExited, err)
	}
	p.touch()
	return nil
}

func (p *Process) isStopping() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopping || p.exited
}

// touch records traffic and restarts the idle timer, unless the process is held.
func (p *Process) touch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.traffic = p.clock.Now()
	if !p.stopping && !p.exited && p.held == 0 {
		p.idle.Reset(p.idleFor)
	}
}

// lastTraffic is when the process last read or wrote a message, or started.
func (p *Process) lastTraffic() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.traffic
}

// evict stops the process to make room under a cap. Its streams end as ones the server chose to
// end (a subscriptions/listen gets a completion result), not as after a crash.
func (p *Process) evict(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.stopping && !p.exited {
		p.evicted = true
	}
	p.stopLocked(reason)
}

// wasEvicted reports whether evict stopped the process.
func (p *Process) wasEvicted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.evicted
}

// hold marks the process in use: an open request or stream, however quiet, keeps it from idling
// out (a subscription may see no traffic for longer than the idle timeout).
func (p *Process) hold() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held++
	if p.held == 1 && !p.stopping && !p.exited {
		p.idle.Stop()
	}
}

// unhold ends one hold; the idle timeout counts from the last one.
func (p *Process) unhold() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held--
	if p.held == 0 && !p.stopping && !p.exited {
		p.idle.Reset(p.idleFor)
	}
}

// stop shuts the process down as the MCP stdio transport says: close stdin, wait, then SIGTERM
// and finally SIGKILL to the whole process group, each after the grace period. It returns at
// once; Done reports the exit.
func (p *Process) stop(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked(reason)
}

// stopLocked is stop for callers holding p.mu. Only the first call does anything.
func (p *Process) stopLocked(reason string) {
	if p.stopping || p.exited {
		return
	}
	p.stopping = true
	p.idle.Stop()
	p.log.Info("stopping upstream process", "reason", reason)
	p.closeStdin()
	p.timers = append(p.timers, p.clock.AfterFunc(p.grace, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.exited {
			return
		}
		p.signalLocked(syscall.SIGTERM)
		p.timers = append(p.timers, p.clock.AfterFunc(p.grace, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.signalLocked(syscall.SIGKILL)
		}))
	}))
}

// sendDetached sends msg in the background, bounded by writeTimeout. Code that reads the
// process's output uses it: the upstream may be blocked writing to us, so a write from there
// could deadlock.
func (p *Process) sendDetached(msg []byte) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		defer cancel()
		_ = p.Send(ctx, msg)
	}()
}

// signalLocked signals the process group. It does nothing once the leader is reaped, so a
// reused PID is never signalled. Callers hold p.mu.
func (p *Process) signalLocked(sig syscall.Signal) {
	if !p.exited {
		_ = syscall.Kill(-p.pid, sig)
	}
}

func (p *Process) closeStdin() { p.stdinOnce.Do(func() { _ = p.stdin.Close() }) }

func (p *Process) giveUp() { p.abandonOnce.Do(func() { close(p.abandon) }) }

// readStdout delivers stdout lines until EOF. A line over the size limit stops the process; the
// rest of the output is drained so the process never blocks on a full pipe. A process that closes
// stdout but has not exited a grace period later is stopped: it can answer no one. The grace keeps
// a process that is exiting anyway logged as having exited by itself.
func (p *Process) readStdout(r io.Reader) {
	defer p.readers.Done()
	defer close(p.messages)
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		msg, err := readMessage(br, p.maxMsg)
		if errors.Is(err, errMessageTooLarge) {
			p.log.Warn("upstream message over the size limit", "reason", "message_too_large")
			p.stop("message_too_large")
			_, _ = io.Copy(io.Discard, br)
			return
		}
		if len(msg) > 0 {
			p.touch()
			select {
			case p.messages <- msg:
			case <-p.abandon:
				return
			}
		}
		if err != nil {
			p.mu.Lock() // before Messages closes, so whoever sees it closed sees the timer armed
			if !p.stopping && !p.exited {
				p.timers = append(p.timers, p.clock.AfterFunc(p.grace, func() { p.stop("stdout_closed") }))
			}
			p.mu.Unlock()
			return
		}
	}
}

// readMessage returns the next line without "\n" or "\r\n"; empty lines come back empty.
func readMessage(br *bufio.Reader, maxLen int) ([]byte, error) {
	var buf []byte
	for {
		b, err := br.ReadSlice('\n')
		if len(buf)+len(b) > maxLen+2 { // +2 for "\r\n"
			return nil, errMessageTooLarge
		}
		buf = append(buf, b...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		buf = bytes.TrimSuffix(buf, []byte("\n"))
		buf = bytes.TrimSuffix(buf, []byte("\r"))
		if len(buf) > maxLen {
			return nil, errMessageTooLarge
		}
		return buf, err
	}
}

// wait reaps the process, kills what is left of its group, waits for both pipes to close and
// cleans up. Pipes held open by a process outside the group are closed after the grace period.
func (p *Process) wait(cmd *exec.Cmd, stdout, stderr *os.File, sessionDir string, onExit func()) {
	err := cmd.Wait()
	p.mu.Lock()
	// Leftover group members. A PID is not reused while its process group exists, so this reaches
	// only our own processes, or nothing.
	_ = syscall.Kill(-p.pid, syscall.SIGKILL)
	p.exited = true
	stopping := p.stopping
	p.idle.Stop()
	for _, t := range p.timers {
		t.Stop()
	}
	p.mu.Unlock()
	p.closeStdin()

	readersDone := make(chan struct{})
	go func() { p.readers.Wait(); close(readersDone) }()
	fallback := p.clock.AfterFunc(p.grace, func() {
		p.log.Warn("upstream pipes force-closed", "reason", "pipes_open_after_exit")
		p.giveUp()
		_ = stdout.Close()
		_ = stderr.Close()
	})
	<-readersDone
	fallback.Stop()
	_ = stdout.Close()
	_ = stderr.Close()
	if sessionDir != "" {
		if rmErr := os.RemoveAll(sessionDir); rmErr != nil {
			p.log.Warn("cannot remove session directory", "error", rmErr)
		}
	}

	attrs := []any{}
	if ps := cmd.ProcessState; ps != nil {
		attrs = append(attrs, "exit_code", ps.ExitCode())
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			attrs = append(attrs, "signal", ws.Signal().String())
		}
	}
	if stopping {
		p.log.Info("upstream process exited", attrs...)
	} else {
		p.log.Warn("upstream process exited unexpectedly", attrs...)
	}
	p.waitErr = err
	onExit() // first, so a key is free again once Done is closed
	close(p.done)
}
