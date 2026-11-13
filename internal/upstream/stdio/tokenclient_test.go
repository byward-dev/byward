//go:build linux || darwin

package stdio

import (
	"context"
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

// scriptedSocket answers each connection's request with answer, then closes it, and returns the
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
		"not JSON":                  "token " + secret + "\n",
		"a token without expiry":    `{"access_token":"` + secret + `"}` + "\n",
		"a token with a bad expiry": `{"access_token":"` + secret + `","expires_at":"soon"}` + "\n",
		"a token and an error":      `{"access_token":"` + secret + `","expires_at":"2026-11-08T13:00:00Z","error":"failed"}` + "\n",
		"an empty object":           "{}\n",
		"no newline before close":   `{"access_token":"` + secret + `","expires_at":"2026-11-08T13:00:00Z"}`,
		"nothing before close":      "",
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

func TestAMissingTokenSocketIsAnError(t *testing.T) {
	_, err := AskDownstreamToken(context.Background(), filepath.Join(shortTempDir(t), "token.sock"))
	if err == nil {
		t.Fatal("no error for a socket that is not there")
	}
}

// A socket that never answers holds the client only until its context ends, deadline or not.
func TestASilentTokenSocketHoldsTheClientOnlyUntilItsContextEnds(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "token.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	for name, ctx := range map[string]func() (context.Context, context.CancelFunc){
		"a deadline": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		},
		"a cancel without a deadline": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)
			return ctx, cancel
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := ctx()
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := AskDownstreamToken(ctx, path); done <- err }()
			select {
			case err := <-done:
				if err == nil || !(errors.Is(err, os.ErrDeadlineExceeded)) {
					t.Fatalf("err %v, want a deadline error", err)
				}
			case <-time.After(guard):
				t.Fatal("the client is still waiting after its context ended")
			}
		})
	}
}
