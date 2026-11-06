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
)

var (
	// ErrUserMismatch is returned when a key already has a process serving another user: an
	// upstream process never serves more than one user (ADR-0003 §2).
	ErrUserMismatch = errors.New("stdio: key is bound to another user")
	// ErrClosed is returned by Get after Shutdown.
	ErrClosed = errors.New("stdio: manager is shut down")
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

	Log   *slog.Logger
	Clock Clock
	// LookupEnv reads the proxy's own environment; default os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// Manager owns the upstream processes of one stdio upstream.
type Manager struct {
	cfg Config
	cmd command
	log *slog.Logger

	mu     sync.Mutex
	procs  map[string]*entry
	closed bool
}

type entry struct {
	user  string        // issuer and subject: subjects are unique only per issuer
	ready chan struct{} // closed when the spawn finished
	p     *Process
	err   error
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
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.LookupEnv == nil {
		cfg.LookupEnv = os.LookupEnv
	}
	cmd, err := newCommand(cfg.Command, cfg.Env, cfg.LookupEnv)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: cfg, cmd: cmd, log: cfg.Log.With("upstream", cfg.Name), procs: map[string]*entry{}}, nil
}

// Get returns the live process for key, spawning one for id if there is none. A key bound to
// another user fails with ErrUserMismatch.
func (m *Manager) Get(ctx context.Context, key string, id Identity) (*Process, error) {
	if err := id.validate(); err != nil {
		return nil, err
	}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrClosed
		}
		e, ok := m.procs[key]
		if !ok {
			e = &entry{user: id.user(), ready: make(chan struct{})}
			m.procs[key] = e
			m.mu.Unlock()
			e.p, e.err = m.spawn(ctx, id, func() { m.remove(key, e) })
			close(e.ready)
			if e.err != nil {
				m.remove(key, e)
			}
			return e.p, e.err
		}
		m.mu.Unlock()
		if e.user != id.user() {
			return nil, ErrUserMismatch
		}
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if e.err != nil {
			continue // that spawn failed and was removed; try our own
		}
		select {
		case <-e.p.Done():
			m.remove(key, e)
			continue
		default:
		}
		e.p.touch()
		return e.p, nil
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

// Len is the number of processes that are starting or running.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.procs)
}

// Shutdown stops every process and waits for them, or for ctx. Get fails afterwards.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	entries := make([]*entry, 0, len(m.procs))
	for _, e := range m.procs {
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

func (m *Manager) remove(key string, e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.procs[key] == e {
		delete(m.procs, key)
	}
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
	if err = cmd.Start(); err != nil {
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
