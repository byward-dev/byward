//go:build linux || darwin

package stdio

import (
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
			[]string{"MCP_AUTHPROXY_EMAIL=alice@example.com"}},
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
				"MCP_AUTHPROXY_ISSUER=" + alice.Issuer,
				"MCP_AUTHPROXY_SUBJECT=" + alice.Subject,
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

func TestOperatorEnvIsValidated(t *testing.T) {
	for _, key := range []string{"MCP_AUTHPROXY_SUBJECT", "mcp_authproxy_issuer", "MCP_AUTHPROXY_OTHER", "", "A=B"} {
		_, err := New(Config{Command: []string{fakeBin}, Env: map[string]string{key: "v"}, LookupEnv: lookup(proxyEnv)})
		if err == nil {
			t.Errorf("env %q accepted, want an error", key)
		}
	}
}

func TestMissingCommandNamesTheImagePattern(t *testing.T) {
	notExec := filepath.Join(t.TempDir(), "server.js")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, argv0 := range []string{"npx-not-installed", "/nonexistent/bin/uvx", notExec, t.TempDir()} {
		_, err := New(Config{Command: []string{argv0}, LookupEnv: lookup(proxyEnv)})
		if !errors.Is(err, ErrCommandNotFound) {
			t.Errorf("%s: err = %v, want ErrCommandNotFound", argv0, err)
			continue
		}
		if !strings.Contains(err.Error(), "COPY --from=ghcr.io/corker/mcp-authproxy:") {
			t.Errorf("%s: error %q does not name the COPY --from pattern", argv0, err)
		}
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
	h.clk.Advance(DefaultKillGrace) // stdin closed, grace over: SIGTERM, which both ignore
	if isDone(p) {
		t.Fatal("process exited before SIGKILL although it ignores stdin EOF and SIGTERM")
	}
	h.clk.Advance(DefaultKillGrace) // SIGKILL to the group
	waitDone(t, p)

	// The grandchild holds stdout and stderr open; they only reach EOF if it died as well.
	if p.forced.Load() {
		t.Fatal("pipes had to be force-closed: a group member survived SIGKILL")
	}
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
	if p.isStopping() {
		t.Fatal("stopped although it had traffic within the idle timeout")
	}
	h.clk.Advance(time.Minute)
	if !p.isStopping() {
		t.Fatal("not stopped after the idle timeout")
	}
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
	if again := h.get(t, "a", alice); again.PID() == a.PID() {
		t.Fatal("crashed key was not given a new process")
	}
	if w := h.log.with("upstream process exited unexpectedly"); len(w) != 1 || w[0].attrs["exit_code"] != int64(3) {
		t.Fatalf("crash records = %v", w)
	}
}

func TestKeyIsBoundToOneUser(t *testing.T) {
	h := newHarness(t, nil)
	p := h.get(t, "s1", alice)
	if _, err := h.m.Get(context.Background(), "s1", bob); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Get by another user = %v, want ErrUserMismatch", err)
	}
	if again := h.get(t, "s1", alice); again != p {
		t.Fatal("same user and key got a different process")
	}
}

func TestConcurrentGetsForOneKeySpawnOnce(t *testing.T) {
	h := newHarness(t, nil)
	var wg sync.WaitGroup
	pids := make([]int, 8)
	for i := range pids {
		wg.Go(func() {
			if p, err := h.m.Get(context.Background(), "s1", alice); err == nil {
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
	for _, id := range []Identity{{}, {Subject: "s"}, {Issuer: "i"}, {Subject: "a\x00b", Issuer: "i"}} {
		if _, err := h.m.Get(context.Background(), "s1", id); err == nil {
			t.Errorf("Get(%+v) succeeded", id)
		}
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
	if _, err := h.m.Get(ctx, "s1", alice); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get = %v, want context.Canceled", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 || h.m.Len() != 0 {
		t.Fatalf("left behind: dirs %v, Len %d", left, h.m.Len())
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
	if _, err := h.m.Get(context.Background(), "c", alice); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after Shutdown = %v, want ErrClosed", err)
	}
}
