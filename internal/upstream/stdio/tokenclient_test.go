//go:build linux || darwin

package stdio

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The client against the real token socket: the kernel's peer check sees this test process as the
// peer, so a socket served for this process answers it and one served for a stranger refuses it.
func TestAskingTheTokenSocketGivesTheTokenOrTheErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		stranger bool
		k        *tokens
		wantCode string
	}{
		{name: "from the upstream process itself", k: &tokens{}},
		{name: "from outside the upstream's tree", stranger: true, k: &tokens{}, wantCode: TokenRefused},
		{name: "when the token source refuses", k: &tokens{err: "consent_required"}, wantCode: "consent_required"},
		{name: "when the token source answers without a token", k: &tokens{empty: true}, wantCode: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := os.Getpid()
			if tc.stranger {
				root = stranger(t)
			}
			path := serveFor(t, root, tc.k, &recorder{mu: &sync.Mutex{}, recs: &[]record{}})
			ctx, cancel := context.WithTimeout(context.Background(), guard)
			defer cancel()
			got, err := AskDownstreamToken(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			want := DownstreamToken{Error: tc.wantCode}
			if tc.wantCode == "" {
				want = DownstreamToken{AccessToken: "tok-1", ExpiresAt: time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)}
			}
			if got.AccessToken != want.AccessToken || !got.ExpiresAt.Equal(want.ExpiresAt) || got.Error != want.Error {
				t.Fatalf("got %+v, want %+v", got, want)
			}
			if tc.stranger && len(tc.k.grants()) != 0 {
				t.Fatal("the token source was asked for a stranger")
			}
		})
	}
}

// scriptedSocket answers one connection's request with answer, then closes it, and returns the
// socket's path and the request it read.
func scriptedSocket(t *testing.T, answer string) (string, <-chan string) {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "token.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	reqs := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(guard))
		b := make([]byte, 64)
		n, _ := c.Read(b)
		reqs <- string(b[:n])
		_, _ = c.Write([]byte(answer))
	}()
	return path, reqs
}

// An answer that is neither a token with its expiry nor an error code alone is an error, and the
// error never quotes the answer, which may hold a token.
func TestAnAnswerThatIsNotATokenOrAnErrorCodeIsAnError(t *testing.T) {
	const secret = "eyJ.secret.token"
	for name, tc := range map[string]struct {
		answer string
		want   error
	}{
		"not JSON":                          {"token " + secret + "\n", errBadAnswer},
		"a token without expiry":            {`{"access_token":"` + secret + `"}` + "\n", errBadAnswer},
		"a token with a bad expiry":         {`{"access_token":"` + secret + `","expires_at":"soon"}` + "\n", errBadAnswer},
		"a token and an error":              {`{"access_token":"` + secret + `","expires_at":"2026-11-08T13:00:00Z","error":"failed"}` + "\n", errBadAnswer},
		"an expiry without a token":         {`{"expires_at":"2026-11-08T13:00:00Z"}` + "\n", errBadAnswer},
		"a code with a line break":          {`{"error":"failed\nbyward: ` + secret + `"}` + "\n", errBadAnswer},
		"a code with an escape":             {`{"error":"\u001b[31mfailed"}` + "\n", errBadAnswer},
		"a field of the wrong type":         {`{"access_token":5,"error":"failed"}` + "\n", errBadAnswer},
		"a code in capitals":                {`{"error":"FAILED"}` + "\n", errBadAnswer},
		"a code with a non-ASCII byte":      {`{"error":"failéd"}` + "\n", errBadAnswer},
		"a code ending past z":              {`{"error":"failed{"}` + "\n", errBadAnswer},
		"a code with a backtick":            {`{"error":"fail` + "`" + `"}` + "\n", errBadAnswer},
		"a token with a line break":         {`{"access_token":"` + secret + `\nx","expires_at":"2026-11-08T13:00:00Z"}` + "\n", errBadAnswer},
		"a token with a space":              {`{"access_token":"` + secret + ` x","expires_at":"2026-11-08T13:00:00Z"}` + "\n", errBadAnswer},
		"a token with DEL":                  {`{"access_token":"` + secret + `\u007f","expires_at":"2026-11-08T13:00:00Z"}` + "\n", errBadAnswer},
		"an answer one byte over 64 KiB":    {answerLine(secret, 64<<10+1), errLongAnswer},
		"a code that starts with a capital": {`{"error":"Failed"}` + "\n", errBadAnswer},
		"a token that starts with a space":  {`{"access_token":" ` + secret + `","expires_at":"2026-11-08T13:00:00Z"}` + "\n", errBadAnswer},
		"a token with a non-ASCII byte":     {`{"access_token":"` + secret + `\u009b31m","expires_at":"2026-11-08T13:00:00Z"}` + "\n", errBadAnswer},
		"no newline before close":           {`{"access_token":"` + secret + `","expires_at":"2026-11-08T13:00:00Z"}`, io.EOF},
		"nothing before close":              {"", io.EOF},
	} {
		t.Run(name, func(t *testing.T) {
			path, reqs := scriptedSocket(t, tc.answer)
			ctx, cancel := context.WithTimeout(context.Background(), guard)
			defer cancel()
			got, err := AskDownstreamToken(ctx, path)
			if !errors.Is(err, tc.want) || got != (DownstreamToken{}) {
				t.Fatalf("got %+v, %v; want only the error %v", got, err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("the error quotes the answer: %v", err)
			}
			if req := <-reqs; req != "{}\n" {
				t.Fatalf("request %q, want {} on one line", req)
			}
		})
	}
}

// answerLine is a token answer of exactly size bytes, its newline included, whose token starts with
// prefix.
func answerLine(prefix string, size int) string {
	const head, tail = `{"access_token":"`, `","expires_at":"2026-11-08T13:00:00Z"}` + "\n"
	return head + prefix + strings.Repeat("t", size-len(head)-len(prefix)-len(tail)) + tail
}

// An answer line of exactly 64 KiB, its newline included, is read whole; one byte more is
// errLongAnswer (TestAnAnswerThatIsNotATokenOrAnErrorCodeIsAnError).
func TestAnAnswerOfExactly64KiBIsReadWhole(t *testing.T) {
	line := answerLine("eyJ", 64<<10)
	path, _ := scriptedSocket(t, line)
	ctx, cancel := context.WithTimeout(context.Background(), guard)
	defer cancel()
	got, err := AskDownstreamToken(ctx, path)
	want := line[len(`{"access_token":"`):strings.Index(line, `","expires_at"`)]
	if err != nil || got.AccessToken != want {
		t.Fatalf("got a token of %d bytes, %v; want %d bytes", len(got.AccessToken), err, len(want))
	}
}

// Every byte a code or a token may hold comes back whole: a to z and _ in a code, printable ASCII
// without the space in a token.
func TestEveryByteACodeOrATokenMayHoldComesBack(t *testing.T) {
	var printable []byte
	for b := byte('!'); b <= '~'; b++ {
		printable = append(printable, b)
	}
	tok, _ := json.Marshal(string(printable))
	for _, tc := range []struct {
		name, answer string
		want         DownstreamToken
	}{
		{"a token of every printable byte", `{"access_token":` + string(tok) + `,"expires_at":"2026-11-08T13:00:00Z"}` + "\n",
			DownstreamToken{AccessToken: string(printable), ExpiresAt: time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)}},
		{"a code of a to z and _", `{"error":"abcdefghijklmnopqrstuvwxyz_"}` + "\n", DownstreamToken{Error: "abcdefghijklmnopqrstuvwxyz_"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := scriptedSocket(t, tc.answer)
			ctx, cancel := context.WithTimeout(context.Background(), guard)
			defer cancel()
			got, err := AskDownstreamToken(ctx, path)
			if err != nil || got.AccessToken != tc.want.AccessToken || !got.ExpiresAt.Equal(tc.want.ExpiresAt) || got.Error != tc.want.Error {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestAMissingTokenSocketIsAnError(t *testing.T) {
	got, err := AskDownstreamToken(context.Background(), filepath.Join(shortTempDir(t), "token.sock"))
	if !errors.Is(err, syscall.ENOENT) || got != (DownstreamToken{}) {
		t.Fatalf("got %+v, %v; want only the dial error for a socket that is not there", got, err)
	}
}

// silentSocket reads one connection's request, then says so on asked and never answers.
func silentSocket(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "token.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	asked := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = c.Read(make([]byte, 64))
		close(asked)
	}()
	return path, asked
}

// askUntilDone runs AskDownstreamToken in the background and returns its error, failing the test
// if it is still waiting after guard.
func askUntilDone(t *testing.T, ctx context.Context, path string, whileWaiting func()) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := AskDownstreamToken(ctx, path); done <- err }()
	whileWaiting()
	select {
	case err := <-done:
		return err
	case <-time.After(guard):
		t.Fatal("the client is still waiting after its context ended")
		return nil
	}
}

// A cancel while the client waits for the answer ends its read with the cancel's own error.
func TestACancelEndsTheWaitForASilentSocket(t *testing.T) {
	path, asked := silentSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := askUntilDone(t, ctx, path, func() {
		select {
		case <-asked: // the client has sent its request, so it is in its read
			cancel()
		case <-time.After(guard):
			t.Fatal("the socket never got the request")
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want context.Canceled", err)
	}
}

// A deadline ends the wait for a silent socket, wherever the client is, with the deadline's error.
func TestADeadlineEndsTheWaitForASilentSocket(t *testing.T) {
	path, _ := silentSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := askUntilDone(t, ctx, path, func() {}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want context.DeadlineExceeded", err)
	}
}
