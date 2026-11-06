//go:build linux || darwin

// Package stdio is the stdio upstream: it spawns upstream processes, one per key the caller
// chooses (an MCP session or a user, ADR-0003), and relays newline-delimited JSON-RPC to and from
// them as bytes. Each process gets only an env allowlist, operator env and the user's identity
// (ADR-0016 §6); its stderr is logged line by line (ADR-0021 §6). Linux and macOS only.
package stdio

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Defaults (docs/quality-lenses.md "Default budgets").
const (
	DefaultIdleTimeout     = 30 * time.Minute
	DefaultSpawnTimeout    = 30 * time.Second
	DefaultKillGrace       = 5 * time.Second
	DefaultMaxMessageBytes = 64 << 20
	DefaultMaxProcesses    = 64
	DefaultMaxPerUser      = 8
)

var (
	// ErrUserMismatch is returned when a key already has a process serving another user: an
	// upstream process never serves more than one user (ADR-0003 §2).
	ErrUserMismatch = errors.New("stdio: key is bound to another user")
	// ErrClosed is returned by Get after Shutdown.
	ErrClosed = errors.New("stdio: manager is shut down")
	// errNotFound is returned by leaseKey when the key has no live process.
	errNotFound = errors.New("stdio: no process for key")
	// errBusy is returned by Get when a process cap is reached and no idle process can be evicted
	// (ADR-0003 §5).
	errBusy = errors.New("stdio: process cap reached")
)

// Config describes one stdio upstream.
type Config struct {
	Name    string            // upstream name, for logs
	Command []string          // argv; never run through a shell
	Env     map[string]string // operator env; values may contain SessionDirPlaceholder

	IdleTimeout     time.Duration // no stdin or stdout traffic for this long stops the process
	SpawnTimeout    time.Duration // the exec start must finish within this
	KillGrace       time.Duration // wait after closing stdin, and again after SIGTERM
	MaxMessageBytes int           // longest stdout line; a longer one stops the process
	TempDir         string        // parent of session directories; default os.TempDir()
	// MaxProcesses and MaxPerUser cap live processes, for the upstream and for each user. A
	// process counts until it has exited, so a stopping one still holds its slot.
	MaxProcesses, MaxPerUser int

	Log   *slog.Logger
	Clock Clock
	// LookupEnv reads the proxy's own environment; default os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Evicted is told about each idle process stopped to make room under a cap, with the reason
	// "user_cap" or "upstream_cap"; may be nil.
	Evicted func(id Identity, reason string)
}

// Manager owns the upstream processes of one stdio upstream.
type Manager struct {
	cfg   Config
	cmd   command
	log   *slog.Logger
	start func(*exec.Cmd) error // (*exec.Cmd).Start; tests slow it down or fail it

	mu     sync.Mutex
	procs  map[string]*entry   // by key; an evicted entry leaves at once
	live   map[*entry]struct{} // every entry holding a cap slot, until its process has exited
	closed bool
}

type entry struct {
	id       Identity
	ready    chan struct{} // closed when the spawn finished
	p        *Process
	err      error
	leases   int       // open leases; a leased process is never evicted
	lastUsed time.Time // when the last lease ended, for least-recently-used eviction
	evicted  bool
}

// New validates cfg, including that the command exists, and returns a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.SpawnTimeout <= 0 {
		cfg.SpawnTimeout = DefaultSpawnTimeout
	}
	if cfg.KillGrace <= 0 {
		cfg.KillGrace = DefaultKillGrace
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if cfg.MaxProcesses <= 0 {
		cfg.MaxProcesses = DefaultMaxProcesses
	}
	if cfg.MaxPerUser <= 0 {
		cfg.MaxPerUser = DefaultMaxPerUser
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.LookupEnv == nil {
		cfg.LookupEnv = os.LookupEnv
	}
	if cfg.Evicted == nil {
		cfg.Evicted = func(Identity, string) {}
	}
	cmd, err := newCommand(cfg.Command, cfg.Env, cfg.LookupEnv)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: cfg, cmd: cmd, log: cfg.Log.With("upstream", cfg.Name), start: (*exec.Cmd).Start,
		procs: map[string]*entry{}, live: map[*entry]struct{}{}}, nil
}

// Get returns the live process for key, spawning one for id if there is none, with a lease: the
// process is not evicted until release is called. A key bound to another user fails with
// ErrUserMismatch; a full cap with nothing idle to evict fails with errBusy.
func (m *Manager) Get(ctx context.Context, key string, id Identity) (p *Process, release func(), err error) {
	if err := id.validate(); err != nil {
		return nil, nil, err
	}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, nil, ErrClosed
		}
		e, ok := m.procs[key]
		if !ok {
			wait, err := m.admitLocked(id)
			if err != nil {
				m.mu.Unlock()
				return nil, nil, err
			}
			if wait != nil {
				m.mu.Unlock()
				if err := m.awaitExit(ctx, wait); err != nil {
					return nil, nil, err
				}
				continue
			}
			e = &entry{id: id, ready: make(chan struct{}), leases: 1}
			m.procs[key] = e
			m.live[e] = struct{}{}
			m.mu.Unlock()
			p, err := m.spawn(ctx, id, func() { m.forget(key, e) })
			m.mu.Lock() // admitLocked reads e.p under m.mu
			e.p, e.err = p, err
			m.mu.Unlock()
			close(e.ready)
			if e.err != nil {
				m.forget(key, e)
				return nil, nil, e.err
			}
			e.p.hold() // the spawning Get holds the first lease
			return e.p, m.releaser(e), nil
		}
		m.mu.Unlock()
		if e.id.user() != id.user() {
			return nil, nil, ErrUserMismatch
		}
		p, release, err := m.lease(ctx, key, e)
		if errors.Is(err, errNotFound) {
			continue // that spawn failed or the process exited; try our own
		}
		if err == nil && p.isStopping() {
			// It keeps its key until it has exited, and refuses every Send: wait, then start anew.
			release()
			if err := m.awaitExit(ctx, e); err != nil {
				return nil, nil, err
			}
			continue
		}
		return p, release, err
	}
}

// leaseKey returns the live process for key without spawning one, with a lease as in Get. No
// process, or one that is stopping, fails with errNotFound; one serving another user with
// ErrUserMismatch.
func (m *Manager) leaseKey(ctx context.Context, key string, id Identity) (*Process, func(), error) {
	m.mu.Lock()
	e, ok := m.procs[key]
	m.mu.Unlock()
	if !ok {
		return nil, nil, errNotFound
	}
	if e.id.user() != id.user() {
		return nil, nil, ErrUserMismatch
	}
	p, release, err := m.lease(ctx, key, e)
	if err == nil && p.isStopping() {
		// Not in lease: Get would spin on a stopping entry that still holds its key.
		release()
		return nil, nil, errNotFound
	}
	return p, release, err
}

// lease waits for e's spawn and leases its process; errNotFound when it failed or has exited.
func (m *Manager) lease(ctx context.Context, key string, e *entry) (*Process, func(), error) {
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	if e.err != nil {
		return nil, nil, errNotFound
	}
	select {
	case <-e.p.Done():
		m.forget(key, e)
		return nil, nil, errNotFound
	default:
	}
	m.mu.Lock()
	if e.evicted || m.procs[key] != e {
		m.mu.Unlock()
		return nil, nil, errNotFound
	}
	e.leases++
	m.mu.Unlock()
	e.p.hold()
	return e.p, m.releaser(e), nil
}

func (m *Manager) releaser(e *entry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			e.leases--
			e.lastUsed = m.cfg.Clock.Now()
			m.mu.Unlock()
			e.p.unhold()
		})
	}
}

// admitLocked decides whether id may start a process now. At the user's own cap only that user's
// processes are candidates; at the upstream cap, with the user under theirs, anyone's are. A
// candidate that is already stopping is waited for; otherwise the least recently used idle one is
// evicted and waited for. Nothing to wait for fails with errBusy. Callers hold m.mu.
func (m *Manager) admitLocked(id Identity) (wait *entry, err error) {
	user := id.user()
	mine := 0
	for e := range m.live {
		if e.id.user() == user {
			mine++
		}
	}
	atUser := mine >= m.cfg.MaxPerUser
	if !atUser && len(m.live) < m.cfg.MaxProcesses {
		return nil, nil
	}
	var victim *entry
	for e := range m.live {
		if atUser && e.id.user() != user {
			continue
		}
		if e.evicted || (e.p != nil && e.p.isStopping()) {
			return e, nil // its slot frees once it has exited
		}
		if e.p == nil || e.leases > 0 {
			continue // spawning, or in use
		}
		if victim == nil || e.lastUsed.Before(victim.lastUsed) {
			victim = e
		}
	}
	if victim == nil {
		return nil, errBusy
	}
	victim.evicted = true
	for k, e := range m.procs {
		if e == victim {
			delete(m.procs, k)
		}
	}
	reason := "upstream_cap"
	if atUser {
		reason = "user_cap"
	}
	go func() { // outside m.mu: stop takes the process lock, and Evicted may log or audit
		victim.p.stop("evicted_" + reason)
		m.cfg.Evicted(victim.id, reason)
	}()
	return victim, nil
}

// awaitExit waits until e's process has exited, or ctx ends.
func (m *Manager) awaitExit(ctx context.Context, e *entry) error {
	select {
	case <-e.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	if e.p == nil {
		return nil
	}
	select {
	case <-e.p.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop starts a graceful stop of the process for key, if any.
func (m *Manager) Stop(key string) {
	m.mu.Lock()
	e, ok := m.procs[key]
	m.mu.Unlock()
	if !ok {
		return
	}
	<-e.ready
	if e.p != nil {
		e.p.stop("closed")
	}
}

// Len is the number of processes that are starting, running or stopping.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.live)
}

// Shutdown stops every process and waits for them, or for ctx. Get fails afterwards.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	entries := make([]*entry, 0, len(m.live))
	for e := range m.live {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	for _, e := range entries {
		select {
		case <-e.ready:
		case <-ctx.Done():
			return ctx.Err()
		}
		if e.p != nil {
			e.p.stop("shutdown")
		}
	}
	for _, e := range entries {
		if e.p == nil {
			continue
		}
		select {
		case <-e.p.Done():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// forget drops e: from the keys if it is still there, and from the cap count.
func (m *Manager) forget(key string, e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.procs[key] == e {
		delete(m.procs, key)
	}
	delete(m.live, e)
}

// spawn starts one upstream process. The session directory, if the command uses one, is created
// first and removed on every failure path.
func (m *Manager) spawn(ctx context.Context, id Identity, onExit func()) (_ *Process, err error) {
	ctx, cancel := context.WithTimeout(ctx, m.cfg.SpawnTimeout)
	defer cancel()

	var dir string
	if m.cmd.usesSessionDir() {
		if dir, err = os.MkdirTemp(m.cfg.TempDir, "byward-session-"); err != nil {
			return nil, fmt.Errorf("stdio: session directory: %w", err)
		}
	}
	var files []*os.File // every pipe end, closed on failure
	defer func() {
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			if dir != "" {
				_ = os.RemoveAll(dir)
			}
		}
	}()
	pipe := func() (r, w *os.File, err error) {
		r, w, err = os.Pipe()
		if err == nil {
			files = append(files, r, w)
		}
		return r, w, err
	}
	inR, inW, err := pipe()
	if err != nil {
		return nil, fmt.Errorf("stdio: pipe: %w", err)
	}
	outR, outW, err := pipe()
	if err != nil {
		return nil, fmt.Errorf("stdio: pipe: %w", err)
	}
	errR, errW, err := pipe()
	if err != nil {
		return nil, fmt.Errorf("stdio: pipe: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, fmt.Errorf("stdio: spawn: %w", err)
	}

	cmd := &exec.Cmd{
		Path:        m.cmd.path,
		Args:        m.cmd.argv(dir),
		Env:         m.cmd.environ(m.cfg.LookupEnv, id, dir),
		Stdin:       inR,
		Stdout:      outW,
		Stderr:      errW,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	if err = m.start(cmd); err != nil {
		return nil, fmt.Errorf("stdio: start %s: %w", m.cmd.name, err)
	}
	_ = inR.Close()
	_ = outW.Close()
	_ = errW.Close()
	if err = ctx.Err(); err != nil { // the start itself overran the spawn timeout
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		return nil, fmt.Errorf("stdio: spawn timeout: %w", err)
	}

	opts := processOptions{
		log: m.log.With("process", cmd.Process.Pid, "user_key", id.Subject), clock: m.cfg.Clock,
		idleFor: m.cfg.IdleTimeout, grace: m.cfg.KillGrace, maxMsg: m.cfg.MaxMessageBytes,
	}
	return startProcess(cmd, inW, outR, errR, dir, opts, onExit), nil
}
