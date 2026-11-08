//go:build linux || darwin

package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRelaysMessagesByteForByte(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	msg := `{"jsonrpc":"2.0", "id":"é-1","method":"tools/call","params":{"name":"x","arguments":{}}}`
	if got := call(t, p, msg); got != msg {
		t.Fatalf("relayed %q, want %q unchanged", got, msg)
	}
}

func TestSendRejectsMessagesThatBreakFraming(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	for _, msg := range []string{"", "{}\n{}", "{}\n"} {
		if err := p.Send(context.Background(), []byte(msg)); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("Send(%q) = %v, want ErrInvalidMessage", msg, err)
		}
	}
}

func TestUpstreamGetsOnlyAllowlistOperatorEnvAndIdentity(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want []string
	}{
		{"without email", alice, nil},
		{"with opted-in email", Identity{Subject: alice.Subject, Issuer: alice.Issuer, Email: "alice@example.com"},
			[]string{"BYWARD_EMAIL=alice@example.com"}},
		{"a user", Identity{Subject: alice.Subject, Issuer: alice.Issuer, PrincipalType: "user"}, []string{"BYWARD_PRINCIPAL_TYPE=user"}},
		{"an app-only caller", Identity{Subject: alice.Subject, Issuer: alice.Issuer, PrincipalType: "client"}, []string{"BYWARD_PRINCIPAL_TYPE=client"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.Env = map[string]string{"FOO": "bar", "LANG": "en_US.UTF-8"} })
			var env []string
			if err := json.Unmarshal([]byte(call(t, h.get(t, "s1", tc.id), "env")), &env); err != nil {
				t.Fatal(err)
			}
			want := append([]string{
				"FOO=bar",
				"LANG=en_US.UTF-8", // operator env wins over the inherited value
				"BYWARD_ISSUER=" + alice.Issuer,
				"BYWARD_SUBJECT=" + alice.Subject,
				"PATH=/usr/bin:/bin",
			}, tc.want...)
			slices.Sort(env)
			slices.Sort(want)
			if !slices.Equal(env, want) {
				t.Fatalf("upstream env =\n%q\nwant\n%q", env, want)
			}
		})
	}
}

func TestIdentityIsNeverInArguments(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "--flag", "x"} })
	var args []string
	if err := json.Unmarshal([]byte(call(t, h.get(t, "s1", alice), "args")), &args); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args, []string{"--flag", "x"}) {
		t.Fatalf("args = %q, want the configured ones only", args)
	}
}

func TestInvalidCommandConfigIsRejected(t *testing.T) {
	cases := []struct {
		name    string
		command []string
		env     map[string]string
	}{
		{"no command", nil, nil},
		{"empty argv[0]", []string{""}, nil},
		{"NUL in an argument", []string{fakeBin, "a\x00b"}, nil},
		{"identity env name", []string{fakeBin}, map[string]string{"BYWARD_SUBJECT": "v"}},
		{"reserved prefix, lower case", []string{fakeBin}, map[string]string{"byward_issuer": "v"}},
		{"other reserved name", []string{fakeBin}, map[string]string{"BYWARD_OTHER": "v"}},
		{"empty env name", []string{fakeBin}, map[string]string{"": "v"}},
		{"= in env name", []string{fakeBin}, map[string]string{"A=B": "v"}},
		{"NUL in env value", []string{fakeBin}, map[string]string{"A": "a\x00b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Config{Command: tc.command, Env: tc.env, LookupEnv: lookup(proxyEnv)}); err == nil {
				t.Fatal("accepted, want an error")
			}
		})
	}
}

func TestMissingCommandNamesTheImagePattern(t *testing.T) {
	notExec := filepath.Join(t.TempDir(), "server.js")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"not on PATH":    "npx-not-installed",
		"absent path":    "/nonexistent/bin/uvx",
		"not executable": notExec,
		"a directory":    t.TempDir(),
	}
	for name, argv0 := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{Command: []string{argv0}, LookupEnv: lookup(proxyEnv)})
			if !errors.Is(err, ErrCommandNotFound) {
				t.Fatalf("err = %v, want ErrCommandNotFound", err)
			}
			if !strings.Contains(err.Error(), "COPY --from=ghcr.io/byward-dev/byward:") {
				t.Fatalf("error %q does not name the COPY --from pattern", err)
			}
		})
	}
}

func TestCommandIsResolvedAgainstTheUpstreamPATH(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(fakeBin, filepath.Join(dir, "my-mcp-server")); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *Config) {
		c.Command = []string{"my-mcp-server"}
		c.Env = map[string]string{"PATH": "relative/dir:" + dir}
	})
	if got := call(t, h.get(t, "s1", alice), "ping"); got != "ping" {
		t.Fatalf("got %q", got)
	}
}

func TestEachProcessGetsItsOwnSessionDirRemovedOnExit(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Command = []string{fakeBin, "--data={session_dir}/db"}
		c.Env = map[string]string{"STATE": "{session_dir}"}
	})
	dirOf := func(p *Process) string {
		var args []string
		if err := json.Unmarshal([]byte(call(t, p, "args")), &args); err != nil {
			t.Fatal(err)
		}
		dir := strings.TrimSuffix(strings.TrimPrefix(args[0], "--data="), "/db")
		var env []string
		if err := json.Unmarshal([]byte(call(t, p, "env")), &env); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(env, "STATE="+dir) {
			t.Fatalf("env %q lacks STATE=%s", env, dir)
		}
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("session dir %s: %v %v", dir, fi, err)
		}
		return dir
	}
	p1, p2 := h.get(t, "s1", alice), h.get(t, "s2", alice)
	d1, d2 := dirOf(p1), dirOf(p2)
	if d1 == d2 {
		t.Fatalf("two processes share session dir %s", d1)
	}
	h.m.Stop("s1")
	waitDone(t, p1)
	if _, err := os.Stat(d1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session dir %s still exists after exit: %v", d1, err)
	}
	if _, err := os.Stat(d2); err != nil {
		t.Fatalf("other process's session dir removed: %v", err)
	}
}

func TestEachStderrLineIsOneTaggedLogRecord(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	call(t, p, "stderr 3")
	call(t, p, "stderrlong 10000")
	h.m.Stop("s1")
	waitDone(t, p)

	recs := h.log.with("upstream stderr")
	if len(recs) != 4 {
		t.Fatalf("got %d stderr records, want 4", len(recs))
	}
	for i, r := range recs {
		if r.attrs["upstream"] != "fake" || r.attrs["process"] != int64(p.PID()) || r.attrs["user_key"] != alice.Subject {
			t.Errorf("record %d tags = %v", i, r.attrs)
		}
	}
	for i := range 3 {
		if got := recs[i].attrs["line"]; got != "line "+strconv.Itoa(i) || recs[i].attrs["truncated"] != false {
			t.Errorf("record %d = %v", i, recs[i].attrs)
		}
	}
	if long := recs[3].attrs["line"].(string); len(long) != MaxStderrLine || recs[3].attrs["truncated"] != true {
		t.Errorf("long line logged with %d bytes, truncated=%v; want %d, true", len(long), recs[3].attrs["truncated"], MaxStderrLine)
	}
}

func TestStopEscalatesToKillingTheWholeProcessGroup(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "-stubborn"} })
	p := h.get(t, "s1", alice)
	if _, err := strconv.Atoi(call(t, p, "child")); err != nil {
		t.Fatalf("fake did not start a grandchild: %v", err)
	}

	h.m.Stop("s1")
	next := func(want string) {
		t.Helper()
		select {
		case got := <-p.Messages():
			if string(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(guard):
			t.Fatalf("no %q", want)
		}
	}
	next("stdin closed")            // step 1: stdin is closed, no signal yet
	h.clk.Advance(DefaultKillGrace) // step 2: SIGTERM after the grace
	next("got SIGTERM")
	if exits := h.log.with("upstream process exited"); len(exits) != 0 {
		t.Fatalf("exited before SIGKILL: %v", exits)
	}
	h.clk.Advance(DefaultKillGrace) // step 3: SIGKILL to the group
	// The grandchild holds stdout and stderr open, and the clock never reaches the pipe
	// fallback: Done closes only if SIGKILL reached the whole group.
	waitDone(t, p)
	exits := h.log.with("upstream process exited")
	if len(exits) != 1 || exits[0].attrs["signal"] != "killed" {
		t.Fatalf("exit records = %v, want one with signal=killed", exits)
	}
}

func TestStopClosesStdinFirstAndAWellBehavedServerExits(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	h.m.Stop("s1")
	waitDone(t, p) // no clock advance: no signal was needed
	if err := p.Err(); err != nil {
		t.Fatalf("exit error = %v, want a clean exit", err)
	}
	if exits := h.log.with("upstream process exited"); len(exits) != 1 || exits[0].attrs["exit_code"] != int64(0) {
		t.Fatalf("exit records = %v", exits)
	}
	if h.m.Len() != 0 {
		t.Fatalf("Len = %d after exit, want 0", h.m.Len())
	}
}

func TestIdleProcessIsStoppedAndTrafficKeepsItAlive(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)

	h.clk.Advance(DefaultIdleTimeout - time.Minute)
	call(t, p, "ping") // traffic restarts the idle timer
	h.clk.Advance(DefaultIdleTimeout - time.Minute)
	if stops := h.log.with("stopping upstream process"); len(stops) != 0 {
		t.Fatal("stopped although it had traffic within the idle timeout")
	}
	h.clk.Advance(time.Minute) // timer callbacks run inside Advance: the stop is logged by now
	waitDone(t, p)
	if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "idle" {
		t.Fatalf("stop records = %v, want reason=idle", stops)
	}
}

func TestCrashFailsOnlyItsOwnKey(t *testing.T) {
	h := newHarness(t, nil)
	a, b := h.get(t, "a", alice), h.get(t, "b", bob)
	if err := a.Send(context.Background(), []byte("crash")); err != nil {
		t.Fatal(err)
	}
	waitDone(t, a)
	var exit *exec.ExitError
	if err := a.Err(); !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("crash exit error = %v, want exit status 3", err)
	}
	if err := a.Send(context.Background(), []byte("ping")); !errors.Is(err, ErrExited) {
		t.Fatalf("Send to crashed process = %v, want ErrExited", err)
	}
	if got := call(t, b, "ping"); got != "ping" {
		t.Fatalf("other key's process answered %q", got)
	}
	if again := h.get(t, "a", alice); again == a {
		t.Fatal("crashed key was not given a new process")
	}
	if w := h.log.with("upstream process exited unexpectedly"); len(w) != 1 || w[0].attrs["exit_code"] != int64(3) {
		t.Fatalf("crash records = %v", w)
	}
}

func TestKeyIsBoundToOneUser(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	if _, _, err := h.m.Get(context.Background(), "s1", bob); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Get by another user = %v, want ErrUserMismatch", err)
	}
	if again := h.get(t, "s1", alice); again != p {
		t.Fatal("same user and key got a different process")
	}
}

// A user and an app-only caller never share a process, even with the same subject and issuer.
func TestAUserAndAnAppWithTheSameSubjectNeverShareAProcess(t *testing.T) {
	h := newHarness(t, nil)
	user := Identity{Subject: alice.Subject, Issuer: alice.Issuer, PrincipalType: "user"}
	app := Identity{Subject: alice.Subject, Issuer: alice.Issuer, PrincipalType: "client"}
	h.get(t, "s1", user)
	if _, _, err := h.m.Get(context.Background(), "s1", app); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Get by the app = %v, want ErrUserMismatch", err)
	}
}

func TestConcurrentGetsForOneKeySpawnOnce(t *testing.T) {
	h := newHarness(t, nil)
	var wg sync.WaitGroup
	pids := make([]int, 8)
	for i := range pids {
		wg.Go(func() {
			if p, _, err := h.m.Get(context.Background(), "s1", alice); err == nil {
				pids[i] = p.PID()
			}
		})
	}
	wg.Wait()
	for _, pid := range pids {
		if pid == 0 || pid != pids[0] {
			t.Fatalf("pids = %v, want one process for all", pids)
		}
	}
}

func TestGetRequiresAnIdentity(t *testing.T) {
	h := newHarness(t, nil)
	cases := map[string]Identity{
		"empty":                 {},
		"no issuer":             {Subject: "s"},
		"no subject":            {Issuer: "i"},
		"NUL in subject":        {Subject: "a\x00b", Issuer: "i"},
		"NUL in email":          {Subject: "s", Issuer: "i", Email: "a\x00b"},
		"NUL in principal type": {Subject: "s", Issuer: "i", PrincipalType: "user\x00x"},
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			// Refused by the identity check itself, before any process is started.
			if _, _, err := h.m.Get(context.Background(), "s1", id); err == nil || !strings.Contains(err.Error(), "stdio: identity") {
				t.Fatalf("Get = %v, want the identity refused", err)
			}
		})
	}
	if h.m.Len() != 0 {
		t.Fatalf("Len = %d", h.m.Len())
	}
}

func TestCancelledSpawnLeavesNothingBehind(t *testing.T) {
	tmp := t.TempDir()
	h := newHarness(t, func(c *Config) {
		c.Command = []string{fakeBin, "{session_dir}"}
		c.TempDir = tmp
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := h.m.Get(ctx, "s1", alice); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get = %v, want context.Canceled", err)
	}
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 || h.m.Len() != 0 {
		t.Fatalf("left behind: dirs %v, Len %d", left, h.m.Len())
	}
	if _, _, err := h.m.Get(context.Background(), "s1", alice); err != nil {
		t.Fatalf("Get after the failed spawn: %v", err)
	}
}

func TestOversizeStdoutMessageStopsTheProcess(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxMessageBytes = 8 })
	p := h.get(t, "s1", alice)
	if got := call(t, p, "12345678"); got != "12345678" {
		t.Fatalf("message at the limit relayed as %q", got)
	}
	if err := p.Send(context.Background(), []byte("123456789")); err != nil {
		t.Fatal(err)
	}
	for msg := range p.Messages() { // closed once the process is gone
		t.Fatalf("over-limit output delivered: %q", msg)
	}
	waitDone(t, p)
	if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "message_too_large" {
		t.Fatalf("stop records = %v", stops)
	}
}

func TestShutdownStopsEveryProcessAndRefusesNewOnes(t *testing.T) {
	h := newHarness(t, nil)
	a, b := h.get(t, "a", alice), h.get(t, "b", bob)
	ctx, cancel := context.WithTimeout(context.Background(), guard)
	defer cancel()
	if err := h.m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !isDone(a) || !isDone(b) {
		t.Fatal("Shutdown returned with a process still running")
	}
	if _, _, err := h.m.Get(context.Background(), "c", alice); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after Shutdown = %v, want ErrClosed", err)
	}
}

// Regression (d6eb42d): an idle timer that fires before AfterFunc returns must not race with the
// assignment of the timer. syncClock fires the timer before AfterFunc returns, almost always, so
// the bug panics without -race. A callback that loses the process lock to the spawning Get's hold
// skips the stop; the release resets the timer, which fires it again.
func TestIdleTimerFiringDuringStartStopsTheProcess(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Clock = syncClock{} })
	waitDone(t, h.get(t, "s1", alice))
	if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "idle" {
		t.Fatalf("stop records = %v, want one with reason=idle", stops)
	}
}

func TestSendThatTimesOutMidWriteStopsTheProcess(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	if got := call(t, p, "block"); got != "blocking" {
		t.Fatalf("got %q", got)
	}
	// Larger than any pipe buffer, so the write blocks part-way; the deadline only bounds it.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := p.Send(ctx, bytes.Repeat([]byte("a"), 4<<20)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send = %v, want context.DeadlineExceeded", err)
	}
	if stops := h.log.with("stopping upstream process"); len(stops) != 1 || stops[0].attrs["reason"] != "partial_write" {
		t.Fatalf("stop records = %v, want reason=partial_write", stops)
	}
	if err := p.Send(context.Background(), []byte("ping")); !errors.Is(err, ErrExited) {
		t.Fatalf("Send after a broken write = %v, want ErrExited", err)
	}
}

func TestSendWithACancelledContextWritesNothing(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Send(ctx, []byte("lost")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send = %v, want context.Canceled", err)
	}
	if got := call(t, p, "ping"); got != "ping" {
		t.Fatalf("next message = %q, want the cancelled one never written", got)
	}
}

func TestPipesHeldByAProcessOutsideTheGroupAreClosedAfterTheGrace(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Clock, c.KillGrace = realClock{}, 50*time.Millisecond })
	p := h.get(t, "s1", alice)
	pid, err := strconv.Atoi(call(t, p, "detach"))
	if err != nil {
		t.Fatalf("fake did not start a detached grandchild: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err := p.Send(context.Background(), []byte("crash")); err != nil {
		t.Fatal(err)
	}
	waitDone(t, p)
	if forced := h.log.with("upstream pipes force-closed"); len(forced) != 1 {
		t.Fatalf("force-close records = %v, want one", forced)
	}
}

func TestShutdownGivesUpWhenItsContextEnds(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "-stubborn"} })
	h.get(t, "s1", alice)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.m.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown = %v, want context.Canceled while a process ignores the stop", err)
	}
}

// syncClock fires every timer at once on another goroutine. AfterFunc gives it 50 ms to finish
// before returning; that only makes a firing during start likely enough for the d6eb42d bug to
// show, and no outcome depends on it. Like a real timer that has fired, a timer that is Reset fires
// again.
type syncClock struct{}

func (syncClock) Now() time.Time { return time.Now() }

func (syncClock) AfterFunc(_ time.Duration, f func()) Timer {
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(50 * time.Millisecond): // f is blocked, as it should be, on the process lock
	}
	return firedTimer{f}
}

// firedTimer is a timer that has fired: Reset fires it again at once; Stop cancels nothing, which
// is safe because the callback re-checks held under the process lock and stopLocked acts only
// once.
type firedTimer struct{ f func() }

func (t firedTimer) Reset(time.Duration) bool { go t.f(); return false }
func (firedTimer) Stop() bool                 { return false }

func TestSameSubjectFromAnotherIssuerIsAnotherUser(t *testing.T) {
	h := newHarness(t, nil)
	h.get(t, "s1", alice)
	other := Identity{Subject: alice.Subject, Issuer: "https://other-idp.example"}
	if _, _, err := h.m.Get(context.Background(), "s1", other); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Get = %v, want ErrUserMismatch", err)
	}
}

func TestProcessThatClosesStdoutButKeepsRunningIsStoppedAfterTheGrace(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp"} })
	p := h.get(t, "s1", alice)
	if err := p.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"closestdout"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-p.Messages():
		if ok {
			t.Fatal("got a message, want stdout closed")
		}
	case <-time.After(guard):
		t.Fatal("stdout did not close")
	}
	if isDone(p) {
		t.Fatal("the process exited by itself, so this test proves nothing")
	}
	// It can answer no one, so it must not keep its cap slot until the idle timeout.
	h.clk.Advance(DefaultKillGrace)
	waitDone(t, p)
	if recs := h.log.with("stopping upstream process"); len(recs) != 1 || recs[0].attrs["reason"] != "stdout_closed" {
		t.Fatalf("stop records %v, want one for stdout_closed", recs)
	}
}

func TestCrashIsNotLoggedAsAStdoutStop(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	_ = p.Send(context.Background(), []byte("crash"))
	waitDone(t, p)
	h.clk.Advance(DefaultKillGrace) // a timer armed at stdout EOF must be gone with the process
	if len(h.log.with("stopping upstream process")) != 0 || len(h.log.with("upstream process exited unexpectedly")) != 1 {
		t.Fatal("a crash must be logged as an unexpected exit, not as a stop")
	}
}

// An idle timer that fired just before a lease took the process lock finds it held and keeps the
// process; the release re-arms it.
func TestIdleTimerThatFiresWhileHeldKeepsTheProcessAndTheReleaseRearmsIt(t *testing.T) {
	h := newHarness(t, nil)
	p, release := h.lease(t, "s1", alice)
	h.clk.mu.Lock()
	idle := h.clk.timers[0].f // the clock's first timer is the process's idle timer
	h.clk.mu.Unlock()
	idle()
	if n := len(h.log.with("stopping upstream process")); n != 0 {
		t.Fatalf("%d stops: an idle firing stopped a held process", n)
	}
	release()
	h.clk.Advance(DefaultIdleTimeout)
	if recs := h.log.with("stopping upstream process"); len(recs) != 1 || recs[0].attrs["reason"] != "idle" {
		t.Fatalf("stop records %v, want one for idle after the release", recs)
	}
	waitDone(t, p)
}

func TestProcessInUseNeverIdlesOutAndIdlesFromItsLastRelease(t *testing.T) {
	h := newHarness(t, nil)
	p, release := h.lease(t, "s1", alice)
	stops := func() int { return len(h.log.with("stopping upstream process")) }
	h.clk.Advance(2 * DefaultIdleTimeout) // a quiet open stream, e.g. a subscription
	if stops() != 0 {
		t.Fatal("a process in use was stopped as idle")
	}
	release()
	h.clk.Advance(DefaultIdleTimeout - time.Second)
	if stops() != 0 {
		t.Fatal("stopped before the idle timeout counted from the release")
	}
	h.clk.Advance(time.Second)
	if recs := h.log.with("stopping upstream process"); len(recs) != 1 || recs[0].attrs["reason"] != "idle" {
		t.Fatalf("stop records %v, want one for idle", recs)
	}
	waitDone(t, p)
}

func TestEveryLeaseOfAProcessKeepsItFromIdlingOut(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice) // the spawning lease, released
	_, release, err := h.m.leaseKey(context.Background(), "s1", alice, requestLease)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	h.clk.Advance(2 * DefaultIdleTimeout)
	if n := len(h.log.with("stopping upstream process")); n != 0 {
		t.Fatalf("%d stops: a process held by a later lease was stopped as idle", n)
	}
	release()
	h.clk.Advance(DefaultIdleTimeout) // the control: without a lease it does idle out
	if recs := h.log.with("stopping upstream process"); len(recs) != 1 || recs[0].attrs["reason"] != "idle" {
		t.Fatalf("stop records %v, want one for idle after the release", recs)
	}
	waitDone(t, p)
}
