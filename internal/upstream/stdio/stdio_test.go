//go:build linux || darwin

package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/faketokensocket"
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

// An upstream process gets exactly the allowlist, the operator's env and its identity: nothing
// else, so no BYWARD_EMAIL (ADR-0016 §6).
func TestUpstreamGetsOnlyAllowlistOperatorEnvAndIdentity(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want []string
	}{
		{"without a principal type", alice, nil},
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
				"LC_ALL=C.UTF-8", "LC_CTYPE=C.UTF-8", "LC_MESSAGES=C", // inherited by name; LC_NUMERIC is not
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

// #307: with On-Behalf-Of, each process gets a token socket in a session directory under the
// temporary directory. One whose longest such path is over the socket path limit fails New, naming
// the limit and TMPDIR, instead of failing every spawn with a 502.
func TestOnBehalfOfRefusesATempDirTooLongForItsTokenSocketAtStartup(t *testing.T) {
	// The longest path is tempDir + "/byward-session-" + 10 digits + "/token.sock".
	fits := "/" + strings.Repeat("d", maxSocketPath-len("/byward-session-4294967295/token.sock")-1)
	tooLong := fits + "d"
	ask := func(context.Context, Identity) DownstreamToken { return DownstreamToken{} }
	for _, tc := range []struct {
		name    string
		tempDir string
		obo     bool
		wantErr bool
	}{
		{"exactly at the limit", fits, true, false},
		{"one byte over", tooLong, true, true},
		{"over, without On-Behalf-Of", tooLong, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Command: []string{fakeBin}, LookupEnv: lookup(proxyEnv), TempDir: tc.tempDir}
			if tc.obo {
				cfg.DownstreamToken = ask
			}
			_, err := New(cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New: %v, want an error %v", err, tc.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrTempDirTooLong) {
				t.Fatalf("error %v is not ErrTempDirTooLong", err)
			}
			for _, want := range []string{tc.tempDir, strconv.Itoa(maxSocketPath+1) + " bytes", strconv.Itoa(maxSocketPath) + " bytes", "on " + runtime.GOOS, "TMPDIR"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not name %q: the path, its length, the limit and TMPDIR", err, want)
				}
			}
		})
	}
}

// The token socket's path limit is the platform's own: sun_path less its NUL. A 105-byte path, as
// a Linux deployment may have, starts on Linux and is refused on macOS.
func TestTheTokenSocketPathLimitIsThePlatformsOwn(t *testing.T) {
	want := map[string]int{"linux": 107, "darwin": 103}[runtime.GOOS]
	if maxSocketPath != want {
		t.Fatalf("maxSocketPath = %d on %s, want %d", maxSocketPath, runtime.GOOS, want)
	}
	tempDir := "/" + strings.Repeat("d", 105-len("/byward-session-4294967295/token.sock")-1) // a 105-byte socket path
	_, err := New(Config{Command: []string{fakeBin}, LookupEnv: lookup(proxyEnv), TempDir: tempDir,
		DownstreamToken: func(context.Context, Identity) DownstreamToken { return DownstreamToken{} }})
	switch runtime.GOOS {
	case "darwin":
		if !errors.Is(err, ErrTempDirTooLong) {
			t.Fatalf("New with a 105-byte socket path on darwin: %v, want ErrTempDirTooLong", err)
		}
	default:
		if err != nil {
			t.Fatalf("New with a 105-byte socket path on %s: %v, want it to start", runtime.GOOS, err)
		}
	}
	// The limit is bind's: a socket of exactly maxSocketPath bytes binds and accepts a connection
	// (the limit is not above it), and one byte more is refused with EINVAL (it is not below it).
	// Go's syscall layer refuses that one, from the same sun_path size, before the kernel would.
	dir := faketokensocket.Dir(t)
	dir = filepath.Join(dir, strings.Repeat("d", maxSocketPath-len(dir)-len("/")-len("/"+tokenSocketName)))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	over := filepath.Join(dir, "x"+tokenSocketName)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: over, Net: "unix"})
	if err == nil {
		_ = ln.Close()
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("binding a %d-byte socket path: %v, want EINVAL: maxSocketPath %d is below the limit", len(over), err, maxSocketPath)
	}
	s, err := listenTokenSocket(dir, slog.New(slog.DiscardHandler), func(context.Context) DownstreamToken { return DownstreamToken{} })
	if err != nil {
		t.Fatalf("a %d-byte socket path: %v", len(filepath.Join(dir, tokenSocketName)), err)
	}
	defer s.close()
	if len(s.path) != maxSocketPath {
		t.Fatalf("the socket path is %d bytes, want %d", len(s.path), maxSocketPath)
	}
	c, err := net.Dial("unix", s.path)
	if err != nil {
		t.Fatalf("dial the %d-byte socket path: %v", maxSocketPath, err)
	}
	_ = c.Close()
}

func TestAMissingCommandNamesTheImagePatternAndAPATHFromTheUpstreamEnvironmentOnlyByItsCounts(t *testing.T) {
	const secret = "S3CRET-path-entry"
	notExec := filepath.Join(t.TempDir(), "server.js")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A program that exists only under a relative PATH entry is not found: only absolute ones are
	// searched. The working directory is the entry's parent, so the entry does name the program.
	relDir, _ := newUnstartable(t, "relative-entry")
	t.Chdir(filepath.Dir(relDir))
	rel := filepath.Base(relDir)
	if _, err := os.Stat(filepath.Join(rel, "srv")); err != nil {
		t.Fatalf("the relative entry does not name the program: %v", err)
	}
	cases := []struct {
		name, argv0 string
		env         map[string]string // the operator env; without a PATH, the proxy's is searched
		shown       string            // what the message shows for the PATH
	}{
		{"not on the proxy's PATH", "npx-not-installed", nil, `PATH "/nonexistent-byward/bin"`},
		{"an absent path", "/nonexistent/bin/uvx", nil, "not an executable file"},
		{"a file that is not executable", notExec, nil, "not an executable file"},
		{"a directory", dir, nil, "not an executable file"},
		{"an upstream env without a PATH: the proxy's is shown", "npx-not-installed", map[string]string{"API_KEY": secret}, `PATH "/nonexistent-byward/bin"`},
		{"an upstream PATH of two entries: counted, never shown", "npx-not-installed", map[string]string{"PATH": "/opt/" + secret + "/bin:/opt/" + secret + "/sbin"}, "PATH from the upstream environment, 2 entries not shown; 2 absolute entries searched"},
		{"an upstream PATH of one entry: counted, never shown", "npx-not-installed", map[string]string{"PATH": "/opt/" + secret + "/bin"}, "PATH from the upstream environment, 1 entry not shown; 1 absolute entry searched"},
		{"an empty upstream PATH: counted, never shown", "npx-not-installed", map[string]string{"PATH": ""}, "PATH from the upstream environment, 0 entries not shown; 0 absolute entries searched"},
		{"a relative entry, counted but not searched", "npx-not-installed", map[string]string{"PATH": "relative/" + secret + ":/opt/" + secret}, "PATH from the upstream environment, 2 entries not shown; 1 absolute entry searched"},
		{"a program only under a relative entry: not found", "srv", map[string]string{"PATH": rel}, "PATH from the upstream environment, 1 entry not shown; 0 absolute entries searched"},
		{"an empty entry, counted but not searched", "npx-not-installed", map[string]string{"PATH": "/opt/" + secret + "::/bin-" + secret}, "PATH from the upstream environment, 3 entries not shown; 2 absolute entries searched"},
		{"a command given as a path, with a PATH from the upstream environment: no PATH is searched or shown", "/nonexistent/bin/uvx", map[string]string{"PATH": secret}, "not an executable file"},
		{"a command given as a relative path, with a PATH from the upstream environment: no PATH is searched or shown", "./missing", map[string]string{"PATH": "/opt/" + secret}, "not an executable file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{Command: []string{tc.argv0}, Env: tc.env, LookupEnv: lookup(map[string]string{"PATH": "/nonexistent-byward/bin"})})
			if !errors.Is(err, ErrCommandNotFound) {
				t.Fatalf("err = %v, want ErrCommandNotFound", err)
			}
			want := "stdio upstream command not found: " + strconv.Quote(tc.argv0) + " (" + tc.shown + "). The byward image has no node or python runtime: " +
				"build your own image FROM the runtime and add the proxy with COPY --from=ghcr.io/byward-dev/byward:<version> /usr/local/bin/byward /usr/local/bin/byward"
			if got := err.Error(); got != want || strings.Contains(got, secret) {
				t.Fatalf("error:\n%s\nwant:\n%s\nand never %q", got, want, secret)
			}
		})
	}
}

// newUnstartable writes srv, an executable file that is no program (no #!), so starting it fails
// with an exec format error, in a directory named name, and returns that directory and srv's path.
func newUnstartable(t *testing.T, name string) (dir, srv string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	srv = filepath.Join(dir, "srv")
	if err := os.WriteFile(srv, []byte("not a program\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srv, 0o700); err != nil { //nolint:gosec // G302: an executable, as the test needs
		t.Fatal(err)
	}
	return dir, srv
}

// The rows with a start func inject errors a real start does not return today; they pin what
// startError does with each kind of error, should a start return it.
func TestAProgramThatCannotStartIsShownByItsPathOnlyWhenThatPathIsNotFromTheUpstreamEnvironment(t *testing.T) {
	const secret = "S3CRET-path-entry"
	dir, srv := newUnstartable(t, secret)
	upstream := map[string]string{"PATH": dir}
	errKept := errors.New("srv: out of processes") // names the program as configured, which is no secret
	const hidden = "stdio: start srv: the start failed with an error that names the program's path on the PATH from the upstream environment, which is not shown"
	cases := []struct {
		name  string
		argv0 string
		env   map[string]string     // the operator env
		proxy string                // the proxy's PATH; empty: none
		start func(*exec.Cmd) error // nil: the real start
		want  string
		cause error // the error still unwraps to it; nil: not checked
	}{
		{name: "an exec format error keeps its cause, named as configured", argv0: "srv", env: upstream,
			want: "stdio: start srv: fork/exec srv (found on the PATH from the upstream environment): exec format error", cause: syscall.ENOEXEC},
		{name: "a path error whose cause names the path: replaced whole", argv0: "srv", env: upstream,
			start: func(c *exec.Cmd) error {
				return &fs.PathError{Op: "fork/exec", Path: c.Path, Err: fmt.Errorf("cannot read %s", c.Path)}
			},
			want: hidden, cause: errStartNamesPath},
		{name: "a path error whose cause names only the PATH entry: replaced whole", argv0: "srv", env: upstream,
			start: func(c *exec.Cmd) error {
				return &fs.PathError{Op: "fork/exec", Path: c.Path, Err: fmt.Errorf("cannot search %s", filepath.Dir(c.Path))}
			},
			want: hidden, cause: errStartNamesPath},
		{name: "another start error naming the path: replaced whole", argv0: "srv", env: upstream,
			start: func(c *exec.Cmd) error { return fmt.Errorf("cannot run %s", c.Path) },
			want:  hidden, cause: errStartNamesPath},
		{name: "another start error naming only the PATH entry: replaced whole", argv0: "srv", env: upstream,
			start: func(c *exec.Cmd) error { return fmt.Errorf("cannot search %s", filepath.Dir(c.Path)) },
			want:  hidden, cause: errStartNamesPath},
		{name: "a path error about another file: kept", argv0: "srv", env: upstream,
			start: func(*exec.Cmd) error { return &fs.PathError{Op: "chdir", Path: "/x", Err: fs.ErrNotExist} },
			want:  "stdio: start srv: chdir /x: file does not exist", cause: fs.ErrNotExist},
		{name: "a start error not naming the path: kept", argv0: "srv", env: upstream,
			start: func(*exec.Cmd) error { return errKept },
			want:  "stdio: start srv: srv: out of processes", cause: errKept},
		{name: "found on the proxy's PATH: the path is shown", argv0: "srv", proxy: dir,
			want: "stdio: start srv: fork/exec " + srv + ": exec format error", cause: syscall.ENOEXEC},
		{name: "a command given as a path: its path is shown, as configured", argv0: srv, env: map[string]string{"PATH": "/opt/bin"},
			want: "stdio: start " + srv + ": fork/exec " + srv + ": exec format error", cause: syscall.ENOEXEC},
		{name: "a command given as a path, with another start error naming it: kept", argv0: srv, env: map[string]string{"PATH": "/opt/bin"},
			start: func(c *exec.Cmd) error { return fmt.Errorf("cannot run %s: %w", c.Path, errKept) },
			want:  "stdio: start " + srv + ": cannot run " + srv + ": srv: out of processes", cause: errKept},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) {
				c.Command, c.Env, c.LookupEnv = []string{tc.argv0}, tc.env, lookup(map[string]string{"PATH": tc.proxy})
			})
			if tc.start != nil {
				h.m.start = tc.start
			}
			_, _, err := h.m.Get(context.Background(), "k", alice)
			if err == nil {
				t.Fatal("Get succeeded, want the start to fail")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("error:\n%s\nwant:\n%s", got, tc.want)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("error %v does not unwrap to %v", err, tc.cause)
			}
		})
	}
}

func TestAStartFailureIsLoggedWithoutAPATHEntryFromTheUpstreamEnvironment(t *testing.T) {
	const secret = "S3CRET-path-entry"
	dir, _ := newUnstartable(t, secret)
	b := newBridge(t, func(c *Config) { c.Command, c.Env = []string{"srv"}, map[string]string{"PATH": dir} })
	res := b.post(t, "alice", "", initialize)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadGateway || string(body) != "upstream unavailable\n" {
		t.Fatalf("status %d, body %q; want 502 and %q", res.StatusCode, body, "upstream unavailable\n")
	}
	recs := b.log.with("cannot start the upstream process")
	if len(recs) != 1 {
		t.Fatalf("%d \"cannot start the upstream process\" records, want 1: %v", len(recs), recs)
	}
	const want = "stdio: start srv: fork/exec srv (found on the PATH from the upstream environment): exec format error"
	if got := fmt.Sprint(recs[0].attrs["error"]); got != want {
		t.Fatalf("logged error:\n%s\nwant:\n%s", got, want)
	}
	b.log.mu.Lock()
	defer b.log.mu.Unlock()
	for _, r := range *b.log.recs {
		if strings.Contains(fmt.Sprint(r.msg, r.attrs), secret) {
			t.Fatalf("a log record shows the PATH entry: %s %v", r.msg, r.attrs)
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
		"NUL in issuer":         {Subject: "s", Issuer: "a\x00b"},
		"NUL in grant":          {Subject: "s", Issuer: "i", Grant: "g\x00x"},
		"NUL in MCP client":     {Subject: "s", Issuer: "i", Client: "c\x00x"},
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

// A stop byward chose ends a subscriptions/listen with a completion result; a fault does not
// (#180).
func TestAnIdleTimeoutStopOrShutdownCountsAsBywardsChoiceButAFaultNeverDoes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		end    func(h *harness, p *Process)
		chosen bool
	}{
		{"the idle timeout", func(h *harness, _ *Process) { h.clk.Advance(DefaultIdleTimeout) }, true},
		{"Stop", func(h *harness, _ *Process) { h.m.Stop("k") }, true},
		{"Shutdown", func(h *harness, _ *Process) {
			ctx, cancel := context.WithTimeout(context.Background(), guard)
			defer cancel()
			_ = h.m.Shutdown(ctx)
		}, true},
		{"a crash", func(_ *harness, p *Process) { _ = p.Send(context.Background(), []byte("crash")) }, false},
		{"a message over the size limit", func(_ *harness, p *Process) { _ = p.Send(context.Background(), []byte("123456789")) }, false},
		{"a fault, then a stop byward chose", func(_ *harness, p *Process) { p.stop("partial_write"); p.retire("shutdown") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.MaxMessageBytes = 8 })
			p := h.get(t, "k", alice)
			tc.end(h, p)
			waitDone(t, p)
			if got := p.endedByChoice(); got != tc.chosen {
				t.Fatalf("endedByChoice = %v, want %v", got, tc.chosen)
			}
		})
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
