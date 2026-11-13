//go:build linux || darwin

package stdio

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
// socket's path and the requests it read.
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
	for name, answer := range map[string]string{
		"not JSON":                      "token " + secret + "\n",
		"a token without expiry":        `{"access_token":"` + secret + `"}` + "\n",
		"a token with a bad expiry":     `{"access_token":"` + secret + `","expires_at":"soon"}` + "\n",
		"a token and an error":          `{"access_token":"` + secret + `","expires_at":"2026-11-08T13:00:00Z","error":"failed"}` + "\n",
		"an expiry without a token":     `{"expires_at":"2026-11-08T13:00:00Z"}` + "\n",
		"a code with a line break":      `{"error":"failed\nbyward: ` + secret + `"}` + "\n",
		"a code with an escape":         `{"error":"\u001b[31mfailed"}` + "\n",
		"a field of the wrong type":     `{"access_token":5,"error":"failed"}` + "\n",
		"a code in capitals":            `{"error":"FAILED"}` + "\n",
		"a code with a non-ASCII byte":  `{"error":"failéd"}` + "\n",
		"a code ending past z":          `{"error":"failed{"}` + "\n",
		"a code with a backtick":        `{"error":"fail` + "`" + `"}` + "\n",
		"a token with a line break":     `{"access_token":"` + secret + `\nx","expires_at":"2026-11-08T13:00:00Z"}` + "\n",
		"a token with a space":          `{"access_token":"` + secret + ` x","expires_at":"2026-11-08T13:00:00Z"}` + "\n",
		"a token with DEL":              `{"access_token":"` + secret + `\u007f","expires_at":"2026-11-08T13:00:00Z"}` + "\n",
		"an answer longer than 64 KiB":  `{"access_token":"` + secret + strings.Repeat("t", 64<<10) + `","expires_at":"2026-11-08T13:00:00Z"}` + "\n",
		"a token with a non-ASCII byte": `{"access_token":"` + secret + `\u009b31m","expires_at":"2026-11-08T13:00:00Z"}` + "\n",
		"no newline before close":       `{"access_token":"` + secret + `","expires_at":"2026-11-08T13:00:00Z"}`,
		"nothing before close":          "",
	} {
		t.Run(name, func(t *testing.T) {
			path, reqs := scriptedSocket(t, answer)
			ctx, cancel := context.WithTimeout(context.Background(), guard)
			defer cancel()
			got, err := AskDownstreamToken(ctx, path)
			if err == nil || got != (DownstreamToken{}) {
				t.Fatalf("got %+v, %v; want only an error", got, err)
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

// A large token, tens of KiB, is read whole.
func TestALargeTokenIsReadWhole(t *testing.T) {
	long := strings.Repeat("t", 32<<10)
	path, _ := scriptedSocket(t, `{"access_token":"`+long+`","expires_at":"2026-11-08T13:00:00Z"}`+"\n")
	ctx, cancel := context.WithTimeout(context.Background(), guard)
	defer cancel()
	got, err := AskDownstreamToken(ctx, path)
	if err != nil || got.AccessToken != long {
		t.Fatalf("got a token of %d bytes, %v; want %d bytes", len(got.AccessToken), err, len(long))
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
	_, err := AskDownstreamToken(context.Background(), filepath.Join(shortTempDir(t), "token.sock"))
	if err == nil {
		t.Fatal("no error for a socket that is not there")
	}
}

// A socket that reads the request and never answers holds the client only until its context ends.
// The cancel comes once the socket has the request, so it ends the client's read, not its dial; a
// deadline ends whichever the client is in.
func TestASilentTokenSocketHoldsTheClientOnlyUntilItsContextEnds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline bool
		want     error
	}{
		{name: "a cancel while it waits for the answer", want: context.Canceled},
		{name: "a deadline", deadline: true, want: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			ctx, cancel := context.WithCancel(context.Background())
			if tc.deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := AskDownstreamToken(ctx, path); done <- err }()
			if !tc.deadline {
				select {
				case <-asked:
					cancel()
				case <-time.After(guard):
					t.Fatal("the socket never got the request")
				}
			}
			select {
			case err := <-done:
				if !errors.Is(err, tc.want) {
					t.Fatalf("err %v, want %v: the context's own end", err, tc.want)
				}
			case <-time.After(guard):
				t.Fatal("the client is still waiting after its context ended")
			}
		})
	}
}
