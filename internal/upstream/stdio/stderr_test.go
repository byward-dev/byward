//go:build linux || darwin

package stdio

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestStderrIsRateLimitedAndSuppressedLinesAreCounted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{mu: &sync.Mutex{}, recs: &[]record{}}
		r, w := io.Pipe()
		go func() {
			for i := range stderrBurst + 50 {
				_, _ = fmt.Fprintf(w, "burst %d\n", i)
			}
			time.Sleep(time.Second) // fake time: refills stderrRate tokens
			_, _ = fmt.Fprintln(w, "after a second")
			_ = w.Close()
		}()
		drainStderr(r, slog.New(rec), time.Now)

		if got := len(rec.with("upstream stderr")); got != stderrBurst+1 {
			t.Fatalf("logged %d lines, want %d: the burst plus the line after the refill", got, stderrBurst+1)
		}
		sup := rec.with("upstream stderr lines suppressed")
		if len(sup) != 1 || sup[0].attrs["suppressed"] != int64(50) {
			t.Fatalf("suppressed records = %v, want one with suppressed=50", sup)
		}
	})
}

func TestStderrSuppressedCountIsFlushedAtEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{mu: &sync.Mutex{}, recs: &[]record{}}
		drainStderr(strings.NewReader(strings.Repeat("x\n", stderrBurst+7)), slog.New(rec), time.Now)
		sup := rec.with("upstream stderr lines suppressed")
		if len(sup) != 1 || sup[0].attrs["suppressed"] != int64(7) {
			t.Fatalf("suppressed records = %v, want one with suppressed=7", sup)
		}
	})
}

func TestReadLineCapsStderrLines(t *testing.T) {
	cases := []struct {
		name, in, want string
		truncated      bool
	}{
		{"plain", "hello\n", "hello", false},
		{"crlf", "hello\r\n", "hello", false},
		{"no final newline", "hello", "hello", false},
		{"exactly the cap", strings.Repeat("a", MaxStderrLine) + "\n", strings.Repeat("a", MaxStderrLine), false},
		{"over the cap", strings.Repeat("a", 3*MaxStderrLine) + "\n", strings.Repeat("a", MaxStderrLine), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			if strings.HasSuffix(in, "\n") {
				in += "next\n"
			}
			br := bufio.NewReaderSize(strings.NewReader(in), MaxStderrLine+1)
			line, truncated, err := readLine(br)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if string(line) != tc.want || truncated != tc.truncated {
				t.Fatalf("got %d bytes truncated=%v, want %d bytes truncated=%v", len(line), truncated, len(tc.want), tc.truncated)
			}
			if in != tc.in {
				if next, _, _ := readLine(br); string(next) != "next" {
					t.Fatalf("following line = %q, want it intact", next)
				}
			}
		})
	}
}

func TestReadMessageEnforcesTheSizeLimit(t *testing.T) {
	cases := []struct {
		name, in, want string
		err            error
	}{
		{"lf", "{}\n", "{}", nil},
		{"crlf", "{}\r\n", "{}", nil},
		{"empty line", "\n", "", nil},
		{"at the limit", "12345678\n", "12345678", nil},
		{"at the limit with crlf", "12345678\r\n", "12345678", nil},
		{"over the limit", "123456789\n", "", errMessageTooLarge},
		{"over the limit across buffer refills", strings.Repeat("a", 100) + "\n", "", errMessageTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReaderSize(strings.NewReader(tc.in), 16) // smallest buffer: forces refills
			got, err := readMessage(br, 8)
			if !errors.Is(err, tc.err) || string(got) != tc.want {
				t.Fatalf("got %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
}
