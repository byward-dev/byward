//go:build linux || darwin

package stdio

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

// evictions records the users and reasons Manager.Evicted was told about.
type evictions struct {
	mu      sync.Mutex
	users   []string
	reasons []string
	done    chan struct{} // receives once per eviction
}

func newEvictions() *evictions { return &evictions{done: make(chan struct{}, 16)} }

func (e *evictions) record(id Identity, reason string) {
	e.mu.Lock()
	e.users = append(e.users, id.Subject)
	e.reasons = append(e.reasons, reason)
	e.mu.Unlock()
	e.done <- struct{}{}
}

func (e *evictions) wait(t *testing.T, n int) []string {
	t.Helper()
	for range n {
		select {
		case <-e.done:
		case <-time.After(guard):
			t.Fatalf("no eviction reported")
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.users...)
}

func capped(perUser, total int, ev *evictions) func(*Config) {
	return func(c *Config) {
		c.MaxPerUser, c.MaxProcesses = perUser, total
		if ev != nil {
			c.Evicted = ev.record
		}
	}
}

// getAt returns an idle process for key whose last use is the fake clock's now, then moves the
// clock on, so processes got earlier are less recently used.
func (h *harness) getAt(t *testing.T, key string, id Identity) *Process {
	t.Helper()
	p := h.get(t, key, id)
	h.clk.Advance(time.Second)
	return p
}

func TestUserAtTheirCapEvictsTheirOwnLeastRecentlyUsedProcess(t *testing.T) {
	ev := newEvictions()
	h := newHarness(t, capped(2, 10, ev))
	bob1 := h.getAt(t, "b1", bob) // the least recently used overall, but not alice's
	alice1 := h.getAt(t, "a1", alice)
	alice2 := h.getAt(t, "a2", alice)

	h.get(t, "a3", alice)
	waitDone(t, alice1)
	if got := ev.wait(t, 1); len(got) != 1 || got[0] != alice.Subject || ev.reasons[0] != "user_cap" {
		t.Fatalf("evicted %v for %v, want only alice's process for user_cap", got, ev.reasons)
	}
	if isDone(bob1) || isDone(alice2) {
		t.Fatal("a process other than alice's least recently used one was stopped")
	}
	if _, _, err := h.m.leaseKey(context.Background(), "a1", alice); !errors.Is(err, errNotFound) {
		t.Fatalf("Lease of the evicted key = %v, want errNotFound", err)
	}
}

func TestUserUnderTheirCapEvictsNobodyWhileTheUpstreamHasRoom(t *testing.T) {
	ev := newEvictions()
	h := newHarness(t, capped(2, 3, ev))
	bob1 := h.getAt(t, "b1", bob)
	h.get(t, "a1", alice)
	h.get(t, "a2", alice)
	if isDone(bob1) || h.m.Len() != 3 {
		t.Fatalf("Len = %d, bob's process done = %v; want 3 and false", h.m.Len(), isDone(bob1))
	}
	if len(ev.users) != 0 {
		t.Fatalf("evicted %v with room left", ev.users)
	}
}

func TestFullUpstreamEvictsTheLeastRecentlyUsedProcessOfAnyUser(t *testing.T) {
	ev := newEvictions()
	h := newHarness(t, capped(2, 2, ev))
	bob1 := h.getAt(t, "b1", bob)
	alice1 := h.getAt(t, "a1", alice)

	h.get(t, "a2", alice) // alice is under her cap; the upstream is full
	waitDone(t, bob1)
	if got := ev.wait(t, 1); got[0] != bob.Subject || ev.reasons[0] != "upstream_cap" {
		t.Fatalf("evicted %v for %v, want bob's process for upstream_cap", got, ev.reasons)
	}
	if isDone(alice1) {
		t.Fatal("alice's own, more recently used process was stopped")
	}
}

func TestProcessInUseIsNeverEvictedSoAFullCapIsBusyUntilItIsReleased(t *testing.T) {
	ev := newEvictions()
	h := newHarness(t, capped(1, 10, ev))
	p, release := h.lease(t, "a1", alice)
	if _, _, err := h.m.Get(context.Background(), "a2", alice); !errors.Is(err, errBusy) {
		t.Fatalf("Get over the cap with only a leased process = %v, want errBusy", err)
	}
	if isDone(p) {
		t.Fatal("the leased process was stopped")
	}
	release()
	h.get(t, "a2", alice)
	waitDone(t, p)
	if got := ev.wait(t, 1); got[0] != alice.Subject || ev.reasons[0] != "user_cap" {
		t.Fatalf("evicted %v for %v, want alice's process for user_cap", got, ev.reasons)
	}
}

func TestStoppingProcessHoldsItsSlotUntilItHasExited(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Command = []string{fakeBin, "-stubborn"} // survives stdin closing and SIGTERM
		c.MaxPerUser = 1
	})
	old := h.get(t, "a1", alice)
	h.m.Stop("a1")
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := h.m.Get(short, "a2", alice); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get whose context ends while the slot is held = %v, want DeadlineExceeded", err)
	}
	if h.m.Len() != 1 {
		t.Fatalf("Len = %d after the given-up Get, want the stopping process only", h.m.Len())
	}
	got := make(chan error, 1)
	go func() {
		_, _, err := h.m.Get(context.Background(), "a2", alice)
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("Get returned %v while the stopping process still ran", err)
	case <-time.After(100 * time.Millisecond):
	}
	h.clk.Advance(2 * DefaultKillGrace) // SIGTERM, then SIGKILL
	waitDone(t, old)
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Get after the old process exited: %v", err)
		}
	case <-time.After(guard):
		t.Fatal("Get did not proceed after the old process exited")
	}
}

func TestGetForTheKeyOfAStoppingProcessWaitsForItAndStartsANewOne(t *testing.T) {
	// A modern-era user's key outlives its process: a request that comes while the process is
	// stopping must get a new process, not the stopping one, whose Send refuses everything.
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "-stubborn"} })
	old := h.get(t, "user:alice", alice)
	h.m.Stop("user:alice")
	got := make(chan *Process, 1)
	go func() {
		p, release, err := h.m.Get(context.Background(), "user:alice", alice)
		if err != nil {
			t.Errorf("Get: %v", err)
			close(got)
			return
		}
		release()
		got <- p
	}()
	select {
	case p := <-got:
		t.Fatalf("Get returned %p (the stopping process is %p) before it had exited", p, old)
	case <-time.After(100 * time.Millisecond):
	}
	h.clk.Advance(2 * DefaultKillGrace) // SIGTERM, then SIGKILL
	waitDone(t, old)
	select {
	case p := <-got:
		if p == nil || p == old || p.isStopping() {
			t.Fatalf("Get after the stopping process exited returned %p (old %p)", p, old)
		}
	case <-time.After(guard):
		t.Fatal("Get did not proceed after the stopping process exited")
	}
}

func TestLookingUpAProcessNeverStartsOneAndRefusesAnotherUser(t *testing.T) {
	h := newHarness(t, nil)
	if _, _, err := h.m.leaseKey(context.Background(), "s1", alice); !errors.Is(err, errNotFound) {
		t.Fatalf("Lease of an unknown key = %v, want errNotFound", err)
	}
	p := h.get(t, "s1", alice)
	if _, _, err := h.m.leaseKey(context.Background(), "s1", bob); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Lease by another user = %v, want ErrUserMismatch", err)
	}
	h.m.Stop("s1")
	waitDone(t, p)
	if _, _, err := h.m.leaseKey(context.Background(), "s1", alice); !errors.Is(err, errNotFound) {
		t.Fatalf("Lease after exit = %v, want errNotFound", err)
	}
	if h.m.Len() != 0 {
		t.Fatalf("Len = %d after Lease found nothing, want 0", h.m.Len())
	}
}

func TestStartThatOverrunsTheSpawnTimeoutKillsTheProcessAndLeavesNothingBehind(t *testing.T) {
	tmp := t.TempDir()
	h := newHarness(t, func(c *Config) {
		c.Command = []string{fakeBin, "{session_dir}"}
		c.TempDir = tmp
		c.SpawnTimeout = 200 * time.Millisecond
	})
	var pid int
	h.m.start = func(c *exec.Cmd) error {
		err := c.Start()
		if err == nil {
			pid = c.Process.Pid
		}
		time.Sleep(400 * time.Millisecond) // the exec start overruns the spawn timeout
		return err
	}
	if _, _, err := h.m.Get(context.Background(), "s1", alice); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get = %v, want a spawn timeout", err)
	}
	if pid == 0 {
		t.Fatal("start never ran, so this test proves nothing")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process %d still exists after the spawn timeout (kill 0: %v)", pid, err)
	}
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 || h.m.Len() != 0 {
		t.Fatalf("left behind: dirs %v, Len %d", left, h.m.Len())
	}
}

// reachedCtx reports when a Get first waits on it.
type reachedCtx struct {
	context.Context
	once    sync.Once
	reached chan struct{}
}

func (c *reachedCtx) Done() <-chan struct{} {
	c.once.Do(func() { close(c.reached) })
	return nil
}

func TestWaitersOnASpawnGiveUpWithTheirContextOrRetryWhenItFails(t *testing.T) {
	h := newHarness(t, nil)
	started, fail := make(chan struct{}), make(chan error)
	calls := 0
	h.m.start = func(c *exec.Cmd) error {
		calls++
		if calls == 1 {
			close(started)
			return <-fail
		}
		return c.Start()
	}
	first := make(chan error, 1)
	go func() {
		_, _, err := h.m.Get(context.Background(), "s1", alice)
		first <- err
	}()
	<-started

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := h.m.Get(cancelled, "s1", alice); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get whose context ends during the spawn = %v, want context.Canceled", err)
	}

	waiter := &reachedCtx{Context: context.Background(), reached: make(chan struct{})}
	retried := make(chan *Process, 1)
	go func() {
		p, release, err := h.m.Get(waiter, "s1", alice)
		if err != nil {
			t.Errorf("waiting Get after the failed spawn: %v", err)
			p = nil
		} else {
			release()
		}
		retried <- p
	}()
	<-waiter.reached
	fail <- errors.New("exec failed")
	if err := <-first; err == nil {
		t.Fatal("the failed spawn's Get returned no error")
	}
	p := <-retried
	if p == nil {
		t.FailNow()
	}
	if got := call(t, p, "ping"); got != "ping" {
		t.Fatalf("retried process answered %q", got)
	}
	if calls != 2 {
		t.Fatalf("start called %d times, want 2", calls)
	}
}
