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

// evictions records the users, reasons and open streams Manager.Evicted was told about.
type evictions struct {
	mu      sync.Mutex
	users   []string
	reasons []string
	streams []int
	done    chan struct{} // receives once per eviction
}

func newEvictions() *evictions { return &evictions{done: make(chan struct{}, 16)} }

func (e *evictions) record(ev Eviction) {
	e.mu.Lock()
	e.users = append(e.users, ev.ID.Subject)
	e.reasons = append(e.reasons, ev.Reason)
	e.streams = append(e.streams, ev.OpenStreams)
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
	if _, _, err := h.m.leaseKey(context.Background(), "a1", alice, requestLease); !errors.Is(err, errNotFound) {
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
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if _, _, err := h.m.Get(short, "user:alice", alice); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get whose context ends while the key's process is stopping = %v, want DeadlineExceeded", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // a Get still waiting at teardown gives up instead of spawning
	type got struct {
		p       *Process
		release func()
		err     error
	}
	result := make(chan got, 1)
	go func() {
		p, release, err := h.m.Get(ctx, "user:alice", alice)
		result <- got{p, release, err}
	}()
	select {
	case r := <-result:
		t.Fatalf("Get returned (pid %v, %v) while the stopping process %d still ran", pidOf(r.p), r.err, old.PID())
	case <-time.After(100 * time.Millisecond):
	}
	h.clk.Advance(2 * DefaultKillGrace) // SIGTERM, then SIGKILL
	waitDone(t, old)
	select {
	case r := <-result:
		if r.err != nil {
			t.Fatalf("Get after the stopping process exited: %v", r.err)
		}
		defer r.release()
		if r.p.PID() == old.PID() {
			t.Fatalf("Get returned the exited process %d", old.PID())
		}
		if answer := call(t, r.p, "ping"); answer != "ping" {
			t.Fatalf("the new process answered %q, want ping", answer)
		}
		if n := h.m.Len(); n != 1 {
			t.Fatalf("Len = %d, want only the new process", n)
		}
	case <-time.After(guard):
		t.Fatal("Get did not proceed after the stopping process exited")
	}
}

// pidOf is p's PID, or nil when there is no process.
func pidOf(p *Process) any {
	if p == nil {
		return nil
	}
	return p.PID()
}

func TestLookingUpAProcessNeverStartsOneAndRefusesAnotherUser(t *testing.T) {
	h := newHarness(t, nil)
	if _, _, err := h.m.leaseKey(context.Background(), "s1", alice, requestLease); !errors.Is(err, errNotFound) {
		t.Fatalf("Lease of an unknown key = %v, want errNotFound", err)
	}
	p := h.get(t, "s1", alice)
	if _, _, err := h.m.leaseKey(context.Background(), "s1", bob, requestLease); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Lease by another user = %v, want ErrUserMismatch", err)
	}
	h.m.Stop("s1")
	waitDone(t, p)
	if _, _, err := h.m.leaseKey(context.Background(), "s1", alice, requestLease); !errors.Is(err, errNotFound) {
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

const streamIdle = 10 * time.Minute

// stream returns the process for key with a stream lease, as a GET stream or a
// subscriptions/listen takes it, then moves the clock on, so processes streamed earlier have been
// quiet longer.
func (h *harness) stream(t *testing.T, key string, id Identity) (*Process, func()) {
	t.Helper()
	p, release, err := h.m.get(context.Background(), key, id, streamLease)
	if err != nil {
		t.Fatalf("stream lease of %q: %v", key, err)
	}
	t.Cleanup(release)
	h.clk.Advance(time.Second)
	return p, release
}

func TestAUserWhoseStreamsHoldEverySlotGivesThemUpQuietestFirstOnceTheyHaveBeenQuietLongEnough(t *testing.T) {
	ev := newEvictions()
	h := newHarness(t, func(c *Config) {
		capped(4, 4, ev)(c)
		c.StreamIdleTimeout = streamIdle
	})
	var alices []*Process // quietest first: each was streamed a second after the one before
	for _, key := range []string{"a1", "a2", "a3", "a4"} {
		p, _ := h.stream(t, key, alice)
		alices = append(alices, p)
	}
	if _, _, err := h.m.Get(context.Background(), "b1", bob); !errors.Is(err, errBusy) {
		t.Fatalf("Get while alice's streams have been quiet under %s = %v, want errBusy", streamIdle, err)
	}
	h.clk.Advance(streamIdle)
	// Each of bob's new sessions takes the slot of alice's quietest remaining process, in order: a
	// choice that ignored how long each had been quiet would get the order right 1 time in 24.
	for i, key := range []string{"b1", "b2", "b3", "b4"} {
		_, release := h.lease(t, key, bob) // held, so bob's own processes are never the idle ones to evict
		t.Cleanup(release)
		waitDone(t, alices[i])
		if got := ev.wait(t, 1); got[i] != alice.Subject || ev.reasons[i] != "upstream_cap" || ev.streams[i] != 1 {
			t.Fatalf("eviction %d: %v for %v with %v open streams, want alice's for upstream_cap with 1", i, got, ev.reasons, ev.streams)
		}
		for _, later := range alices[i+1:] {
			if isDone(later) {
				t.Fatalf("eviction %d stopped a more recently active process of alice's", i)
			}
		}
	}
}

func TestAtTheUpstreamCapAnIdleProcessOfAnyoneGoesBeforeAQuietStreamOfAUserUnderTheirCap(t *testing.T) {
	ev := newEvictions()
	h := newHarness(t, func(c *Config) {
		capped(2, 2, ev)(c)
		c.StreamIdleTimeout = streamIdle
	})
	bob1, _ := h.stream(t, "b1", bob) // quiet for longer than the timeout: evictable, but held
	h.clk.Advance(streamIdle)
	carol1 := h.getAt(t, "c1", carol) // idle, and more recently used than bob's stream
	h.get(t, "a1", alice)
	waitDone(t, carol1)
	if got := ev.wait(t, 1); got[0] != carol.Subject || ev.streams[0] != 0 {
		t.Fatalf("evicted %v with %v open streams, want carol's idle process with none", got, ev.streams)
	}
	if isDone(bob1) {
		t.Fatal("bob's stream-held process was stopped while an idle process was there to evict")
	}
}

func TestAQuietStreamsProcessIsEvictableOnceQuietForTheTimeoutUnlessTrafficARequestOrZeroKeepsIt(t *testing.T) {
	cases := []struct {
		name     string
		timeout  time.Duration
		traffic  bool // the process exchanges a message after the streams open
		request  bool // a request lease is held beside the stream
		ended    bool // the stream ends, then a request lease is held: the stream must no longer count
		more     bool // two more streams on the running process, one of which ends: still only streams
		wantBusy bool
	}{
		{name: "quiet for the timeout is evictable", timeout: streamIdle},
		{name: "traffic within the timeout keeps it", timeout: streamIdle, traffic: true, wantBusy: true},
		{name: "a request in flight keeps it", timeout: streamIdle, request: true, wantBusy: true},
		{name: "0 keeps quiet streams however long", timeout: 0, wantBusy: true},
		{name: "ended streams no longer count, so a quiet request keeps it", timeout: streamIdle, ended: true, wantBusy: true},
		{name: "more streams on the running process, one ended, leave it evictable", timeout: streamIdle, more: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) {
				capped(1, 1, nil)(c)
				c.StreamIdleTimeout = tc.timeout
			})
			p, release := h.stream(t, "a1", alice)
			if tc.ended {
				release()
				_, req := h.lease(t, "a1", alice)
				t.Cleanup(req)
			}
			if tc.more {
				h.stream(t, "a1", alice)
				_, second := h.stream(t, "a1", alice)
				second()
			}
			if tc.request {
				_, release := h.lease(t, "a1", alice)
				t.Cleanup(release)
			}
			h.clk.Advance(streamIdle - time.Second) // with the stream's own second: exactly the timeout
			if tc.traffic {
				if answer := call(t, p, "ping"); answer != "ping" {
					t.Fatalf("the process answered %q, want ping", answer)
				}
				h.clk.Advance(time.Second)
			}
			_, _, err := h.m.Get(context.Background(), "a2", alice)
			if busy := errors.Is(err, errBusy); busy != tc.wantBusy {
				t.Fatalf("Get over the cap = %v, want busy %v", err, tc.wantBusy)
			}
			if !tc.wantBusy {
				waitDone(t, p)
			}
		})
	}
}
