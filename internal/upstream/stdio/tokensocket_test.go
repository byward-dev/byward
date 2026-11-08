//go:build linux || darwin

package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// shortTempDir is a temporary directory short enough for a socket path inside it: a test's own
// t.TempDir() on macOS can be longer than the 103 bytes a socket path may have.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// tokens is a Config.DownstreamToken that hands out tok-1, tok-2, ... and records whom each was for.
type tokens struct {
	mu    sync.Mutex
	asks  []Identity
	err   string // when set, every answer is this error
	empty bool   // when set, every answer has neither a token nor an error
}

func (k *tokens) answer(_ context.Context, id Identity) DownstreamToken {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.asks = append(k.asks, id)
	if k.err != "" {
		return DownstreamToken{Error: k.err}
	}
	if k.empty {
		return DownstreamToken{}
	}
	return DownstreamToken{AccessToken: "tok-" + itoa(len(k.asks)), ExpiresAt: time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)}
}

func (k *tokens) grants() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var g []string
	for _, id := range k.asks {
		g = append(g, id.Grant)
	}
	return g
}

// tokenHarness is a Manager whose processes get token sockets answered by k, in a temporary
// directory short enough for a socket path.
func tokenHarness(t *testing.T, k *tokens) *harness {
	t.Helper()
	return newHarness(t, func(c *Config) {
		c.DownstreamToken = k.answer
		c.TempDir = shortTempDir(t)
	})
}

// answerOf decodes a token socket answer line.
func answerOf(t *testing.T, line string) (token, expires, code string) {
	t.Helper()
	var a struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		Error       string
	}
	if err := json.Unmarshal([]byte(line), &a); err != nil {
		t.Fatalf("not a token socket answer: %q", line)
	}
	return a.AccessToken, a.ExpiresAt, a.Error
}

func TestAProcessAsksItsSocketForAFreshTokenEachTimeWithoutARestart(t *testing.T) {
	k := &tokens{}
	h := tokenHarness(t, k)
	p := h.get(t, "a1", alice)
	for _, want := range []string{"tok-1", "tok-2"} {
		tok, expires, code := answerOf(t, call(t, p, "token"))
		if tok != want || expires != "2026-11-08T13:00:00Z" || code != "" {
			t.Fatalf("answer token %q, expires %q, error %q; want %s expiring 2026-11-08T13:00:00Z", tok, expires, code, want)
		}
	}
	if isDone(p) {
		t.Fatal("the process was restarted or stopped")
	}
}

func TestTheTokenIsForTheGrantOfTheRequestThatLeasedTheProcessLast(t *testing.T) {
	k := &tokens{}
	h := tokenHarness(t, k)
	first, second := alice, alice
	first.Grant, second.Grant = "grant-1", "grant-2"
	p := h.get(t, "a1", first)
	answerOf(t, call(t, p, "token"))
	h.get(t, "a1", second) // the same user's process, now serving a request of another grant
	answerOf(t, call(t, p, "token"))
	if got := k.grants(); len(got) != 2 || got[0] != "grant-1" || got[1] != "grant-2" {
		t.Fatalf("tokens were asked for grants %q, want grant-1 then grant-2", got)
	}
}

func TestAChildOfTheProcessGetsTheTokenAsAServerStartedByALauncherWould(t *testing.T) {
	h := tokenHarness(t, &tokens{})
	if tok, _, code := answerOf(t, call(t, h.get(t, "a1", alice), "tokenchild")); tok != "tok-1" || code != "" {
		t.Fatalf("the child got token %q, error %q; want tok-1", tok, code)
	}
}

func TestAnErrorFromTheTokenSourceIsTheAnswerAndNoTokenIsSent(t *testing.T) {
	k := &tokens{err: "consent_required"}
	h := tokenHarness(t, k)
	line := call(t, h.get(t, "a1", alice), "token")
	if tok, _, code := answerOf(t, line); tok != "" || code != "consent_required" || strings.Contains(line, "access_token") {
		t.Fatalf("answer %q, want only the error consent_required", line)
	}
}

func TestAnAnswerWithoutATokenIsAFailureNotAnEmptyToken(t *testing.T) {
	line := call(t, tokenHarness(t, &tokens{empty: true}).get(t, "a1", alice), "token")
	if tok, _, code := answerOf(t, line); tok != "" || code != "failed" || strings.Contains(line, "access_token") {
		t.Fatalf("answer %q, want only the error failed", line)
	}
}

func TestOnlyAProcessWithATokenSourceGetsASocket(t *testing.T) {
	h := newHarness(t, nil)
	if env := call(t, h.get(t, "a1", alice), "env"); strings.Contains(env, EnvDownstreamTokenSocket) {
		t.Fatalf("a process without On-Behalf-Of has %s in its environment: %s", EnvDownstreamTokenSocket, env)
	}
}

func TestTheSocketIsOursAloneAndGoneWithTheProcess(t *testing.T) {
	h := tokenHarness(t, &tokens{})
	p := h.get(t, "a1", alice)
	var env []string
	if err := json.Unmarshal([]byte(call(t, p, "env")), &env); err != nil {
		t.Fatal(err)
	}
	var path string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, EnvDownstreamTokenSocket+"="); ok {
			path = v
		}
	}
	if path == "" {
		t.Fatalf("no %s in the process's environment", EnvDownstreamTokenSocket)
	}
	for name, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		fi, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Fatalf("%s has mode %o, want %o", name, got, want)
		}
	}
	h.m.Stop("a1")
	waitDone(t, p)
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("the session directory is still there after exit: %v", err)
	}
}

// serveFor serves a token socket in a fresh directory for root, answering with k.
func serveFor(t *testing.T, root int, k *tokens, log *recorder) string {
	t.Helper()
	s, err := listenTokenSocket(shortTempDir(t), slog.New(log), func(ctx context.Context) DownstreamToken { return k.answer(ctx, alice) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	go s.serve(root)
	return s.path
}

// ask sends line to the socket at path and returns the answer.
func ask(t *testing.T, path, line string) string {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(guard))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	answer, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(answer, "\n")
}

func TestTheSocketGivesATokenForAJSONObjectAndRefusesAnyOtherLine(t *testing.T) {
	for _, tc := range []struct {
		name, line, wantCode string
	}{
		{name: "an empty object", line: `{}`},
		{name: "unknown fields are ignored", line: `{"scopes":"ignored"}`},
		{name: "not JSON", line: `token please`, wantCode: TokenBadRequest},
		{name: "not an object", line: `[]`, wantCode: TokenBadRequest},
		{name: "null", line: `null`, wantCode: TokenBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The test process is the root of the tree here, so the peer check passes.
			path := serveFor(t, os.Getpid(), &tokens{}, &recorder{mu: &sync.Mutex{}, recs: &[]record{}})
			tok, _, code := answerOf(t, ask(t, path, tc.line))
			if code != tc.wantCode || (tc.wantCode == "") != (tok == "tok-1") {
				t.Fatalf("token %q, error %q; want error %q", tok, code, tc.wantCode)
			}
		})
	}
}

func TestAProcessOutsideTheUpstreamsTreeIsRefusedAndLogged(t *testing.T) {
	// The root is a process that is not this test's ancestor: the test asks as a stranger would.
	log := &recorder{mu: &sync.Mutex{}, recs: &[]record{}}
	k := &tokens{}
	line := ask(t, serveFor(t, stranger(t), k, log), `{}`)
	if tok, _, code := answerOf(t, line); tok != "" || code != TokenRefused {
		t.Fatalf("a stranger got %q, want only the error %s", line, TokenRefused)
	}
	if len(k.grants()) != 0 {
		t.Fatal("the token source was asked for a stranger")
	}
	recs := log.with("token socket: the peer is not the upstream process or one of its descendants")
	if len(recs) != 1 || recs[0].attrs["reason"] != "token_peer_refused" || recs[0].attrs["peer_process"] != int64(os.Getpid()) {
		t.Fatalf("refusal log %+v, want one with reason token_peer_refused naming this process", recs)
	}
}

func TestAncestryReachesTheRootOrStops(t *testing.T) {
	gone := errors.New("gone")
	parents := map[int]int{40: 30, 30: 20, 20: 1, 1: 0, 7: 7}
	parent := func(pid int) (int, error) {
		if p, ok := parents[pid]; ok {
			return p, nil
		}
		return 0, gone
	}
	for _, tc := range []struct {
		name      string
		pid, root int
		want      error // nil: a descendant
	}{
		{name: "the root itself", pid: 20, root: 20},
		{name: "a grandchild", pid: 40, root: 20},
		{name: "a stranger stops at init", pid: 40, root: 99, want: errNotDescendant},
		{name: "a loop stops at the bound", pid: 7, root: 99, want: errNotDescendant},
		{name: "a vanished parent is an error", pid: 50, root: 99, want: gone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := descends(tc.pid, tc.root, parent); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestATokenSocketPathTooLongForTheKernelIsRefusedNamingTMPDIR(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), strings.Repeat("d", 100))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := listenTokenSocket(dir, slog.New(&recorder{mu: &sync.Mutex{}, recs: &[]record{}}), nil); err == nil || !strings.Contains(err.Error(), "TMPDIR") {
		t.Fatalf("got %v, want a refusal naming TMPDIR", err)
	}
}

func TestAnAnswerThatTakesItsWholeTimeStillReachesThePeer(t *testing.T) {
	s, err := listenTokenSocket(shortTempDir(t), slog.New(&recorder{mu: &sync.Mutex{}, recs: &[]record{}}), func(ctx context.Context) DownstreamToken {
		<-ctx.Done() // an exchange that runs to its bound
		return DownstreamToken{Error: "unavailable"}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	s.timeout, s.margin = 400*time.Millisecond, 200*time.Millisecond
	go s.serve(os.Getpid())
	if _, _, code := answerOf(t, ask(t, s.path, `{}`)); code != "unavailable" {
		t.Fatalf("the peer got error %q, want unavailable", code)
	}
}

func TestTheSocketClosesAsSoonAsTheProcessIsReapedEvenWhileADescendantHoldsItsPipes(t *testing.T) {
	h := tokenHarness(t, &tokens{})
	p := h.get(t, "a1", alice)
	var env []string
	if err := json.Unmarshal([]byte(call(t, p, "env")), &env); err != nil {
		t.Fatal(err)
	}
	var path string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, EnvDownstreamTokenSocket+"="); ok {
			path = v
		}
	}
	call(t, p, "detach") // a child in its own session keeps stdout open after the process exits
	h.m.Stop("a1")
	eventually(t, "the token socket to close", func() bool {
		c, err := net.Dial("unix", path)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
	if isDone(p) {
		t.Fatal("the process finished before the socket closed, so this test proves nothing")
	}
	h.clk.Advance(2 * DefaultKillGrace) // the pipes are force-closed after the grace
	waitDone(t, p)
}

// stranger is a process outside this test's ancestry, as a root that the test asks a socket for.
func stranger(t *testing.T) int {
	t.Helper()
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	return other.Process.Pid
}

// #244: a refused peer that writes its request only after byward has decided still reads the
// refusal. Without the read before the answer, its write meets a closed connection: EPIPE.
func TestARefusedPeerThatWritesLateStillReadsTheRefusal(t *testing.T) {
	log := &recorder{mu: &sync.Mutex{}, recs: &[]record{}}
	c, err := net.Dial("unix", serveFor(t, stranger(t), &tokens{}, log))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(guard))
	// The refusal's log record is the one point a peer can see that comes after byward decided;
	// writing only then is what a slow peer does. An answer sent without reading would already
	// have closed the connection by the time the record shows.
	eventually(t, "byward to refuse the peer", func() bool {
		return len(log.with("token socket: the peer is not the upstream process or one of its descendants")) == 1
	})
	if _, err := c.Write([]byte("{}\n")); err != nil {
		t.Fatalf("writing the request after the refusal was decided: %v, want it accepted", err)
	}
	answer, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	if _, _, code := answerOf(t, strings.TrimSuffix(answer, "\n")); code != TokenRefused {
		t.Fatalf("answer %q, want the error %s", answer, TokenRefused)
	}
}

// A refused peer that never sends a request is answered soon, and the connection closed, so it does
// not hold the socket for the processes that may ask.
func TestARefusedPeerThatSendsNothingIsAnsweredSoonAndClosed(t *testing.T) {
	s, err := listenTokenSocket(shortTempDir(t), slog.New(&recorder{mu: &sync.Mutex{}, recs: &[]record{}}), func(context.Context) DownstreamToken {
		t.Error("a refused peer reached the token source")
		return DownstreamToken{}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	s.refusalWait = 200 * time.Millisecond
	go s.serve(stranger(t))
	start := time.Now()
	c, err := net.Dial("unix", s.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(guard))
	r := bufio.NewReader(c)
	answer, err := r.ReadString('\n') // no request at all
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	// The socket serves one connection at a time: a stranger must give it up soon, not at the
	// connection's 40 s deadline.
	if took := time.Since(start); took >= 4*s.refusalWait {
		t.Fatalf("answered after %v, want within about %v", took, s.refusalWait)
	}
	if _, _, code := answerOf(t, strings.TrimSuffix(answer, "\n")); code != TokenRefused {
		t.Fatalf("answer %q, want the error %s", answer, TokenRefused)
	}
	if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the answer: %v, want the connection closed", err)
	}
}

// A refused peer's request larger than the socket buffer is drained too, so its write completes
// and it reads the refusal.
func TestARefusedPeerWithALargeRequestStillReadsTheRefusal(t *testing.T) {
	c, err := net.Dial("unix", serveFor(t, stranger(t), &tokens{}, &recorder{mu: &sync.Mutex{}, recs: &[]record{}}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(guard))
	if _, err := c.Write([]byte(`{"pad":"` + strings.Repeat("x", 48<<10) + `"}` + "\n")); err != nil {
		t.Fatalf("writing a 48 KiB request: %v, want it accepted", err)
	}
	answer, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	if _, _, code := answerOf(t, strings.TrimSuffix(answer, "\n")); code != TokenRefused {
		t.Fatalf("answer %q, want the error %s", answer, TokenRefused)
	}
}
