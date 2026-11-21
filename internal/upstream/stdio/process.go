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
	// ErrExited is returned by Send once the upstream process has exited or is stopping, or when a
	// write to it failed for a reason other than its context while that context is still live.
	// After a write that failed for a reason other than its context, Send stops the process after
	// the grace period, unless it exits first.
	ErrExited = errors.New("stdio: upstream process exited")
	// ErrInvalidMessage is returned by Send for an empty message or one with an embedded newline,
	// which would break newline-delimited framing.
	ErrInvalidMessage = errors.New("stdio: message is empty or contains a newline")

	errMessageTooLarge = errors.New("stdio: upstream message over the size limit")
)

var newline = []byte{'\n'}

// stopReason is why byward stopped a process: the reason its "stopping upstream process" line
// logs.
type stopReason string

// Stop reasons. The observability reference lists them, in this order, under "stdio upstream stop
// reasons"; a test keeps the two in step.
const (
	stopIdle               stopReason = "idle"
	stopEvictedUserCap     stopReason = "evicted_user_cap"
	stopEvictedUpstreamCap stopReason = "evicted_upstream_cap"
	stopClosed             stopReason = "closed"
	stopShutdown           stopReason = "shutdown"
	stopInitializeFailed   stopReason = "initialize_failed"
	stopNotModern          stopReason = "not_modern"
	stopPartialWrite       stopReason = "partial_write"
	stopStdinClosed        stopReason = "stdin_closed"
	stopMessageTooLarge    stopReason = "message_too_large"
	stopStdoutClosed       stopReason = "stdout_closed"
)

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
	reaped   func()    // processOptions.reaped
	chosen   bool      // stopped by byward's choice (idle, a cap, a session's end, shutdown), not a fault
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
	// reaped, if set, runs as soon as the process has been reaped, before its pipes drain: what
	// must not outlive the process itself (its token socket) closes there.
	reaped func()
}

// startProcess takes over a started cmd and our ends of its pipes: it arms the idle timer and
// starts the stdout reader, the stderr drain and the reaper. onExit runs once the process is gone.
func startProcess(cmd *exec.Cmd, stdin, stdout, stderr *os.File, sessionDir string, o processOptions, onExit func()) *Process {
	p := &Process{
		pid: cmd.Process.Pid, log: o.log, clock: o.clock, idleFor: o.idleFor, grace: o.grace, maxMsg: o.maxMsg,
		stdin: stdin, messages: make(chan []byte, 16), abandon: make(chan struct{}), done: make(chan struct{}),
		traffic: o.clock.Now(), reaped: o.reaped,
	}
	p.mu.Lock() // the timer may fire before the assignment completes; stop reads p.idle under p.mu
	p.idle = o.clock.AfterFunc(o.idleFor, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.held == 0 { // checked and stopped under one lock: a lease taken meanwhile keeps the process
			p.retireLocked(stopIdle)
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

// Send writes msg and a newline to the process's stdin. ctx bounds the write; a message whose
// write ctx's end cuts short breaks framing, so the process is then stopped. A write that fails
// for another reason means the process's reader is gone: it can take no more messages, so it is
// stopped after the grace period, unless it exits first, rather than hold its slot until the idle
// timeout (#562), and a crash is logged as one (#571).
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
	ended := make(chan struct{}) // closed once the request's end has set its deadline
	stop := context.AfterFunc(ctx, func() { _ = p.stdin.SetWriteDeadline(time.Unix(1, 0)); close(ended) })
	n, err := p.stdin.Write(msg) // then the newline: no copy of a message up to the body limit
	if err == nil {
		_, err = p.stdin.Write(newline) // n == len(msg) > 0: a newline the request's end cuts breaks framing
	}
	if !stop() {
		<-ended // the end may come as the write finishes: its deadline must not outlive this Send (#547)
	}
	_ = p.stdin.SetWriteDeadline(time.Time{})
	if err != nil {
		ctxErr := ctx.Err() // read once: returned whenever the request ended, whether or not that cut the write
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded): // the request's end cut the write
			if n > 0 {
				p.stop(stopPartialWrite)
			}
		default:
			// Not cut by the request's end (it may have ended too): the process's reader is gone. It
			// closed its stdin or has just exited and is not reaped yet (or byward is already
			// stopping it), so framing no longer matters, whether part of the message went out or
			// not (#571). As for a closed stdout, the stop waits a grace period, which an exit
			// cancels, so a crash is still logged as one.
			p.mu.Lock()
			if !p.stopping && !p.exited {
				p.timers = append(p.timers, p.clock.AfterFunc(p.grace, func() { p.stop(stopStdinClosed) }))
			}
			p.mu.Unlock()
		}
		if ctxErr != nil {
			return ctxErr
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

// retire stops the process by byward's choice: idle, to make room under a cap, at a session's end
// or at shutdown. Its streams end as ones the server chose to end (a subscriptions/listen gets a
// completion result), not as after a crash.
func (p *Process) retire(reason stopReason) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retireLocked(reason)
}

// retireLocked is retire for callers holding p.mu. A process already stopping or exited keeps the
// reason it had: a fault stays a fault.
func (p *Process) retireLocked(reason stopReason) {
	if !p.stopping && !p.exited {
		p.chosen = true
	}
	p.stopLocked(reason)
}

// endedByChoice reports whether retire stopped the process.
func (p *Process) endedByChoice() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.chosen
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

// stop shuts the process down after a fault (retire is for a stop byward chose), as the MCP stdio
// transport says: close stdin, wait, then SIGTERM and finally SIGKILL to the whole process group,
// each after the grace period. It returns at once; Done reports the exit.
func (p *Process) stop(reason stopReason) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked(reason)
}

// stopLocked is stop for callers holding p.mu. Only the first call does anything.
func (p *Process) stopLocked(reason stopReason) {
	if p.stopping || p.exited {
		return
	}
	p.stopping = true
	p.idle.Stop()
	p.log.Info("stopping upstream process", "reason", string(reason))
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
			p.stop(stopMessageTooLarge)
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
				p.timers = append(p.timers, p.clock.AfterFunc(p.grace, func() { p.stop(stopStdoutClosed) }))
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
	if p.reaped != nil {
		p.reaped()
	}
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
