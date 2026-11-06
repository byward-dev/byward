package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
)

func probe(t *testing.T, h *Health, path string) (int, string) {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w.Code, w.Body.String()
}

var (
	pass = func(context.Context) error { return nil }
	fail = func(context.Context) error { return errors.New("open /secret/path: denied") }
	hang = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
)

func TestLivezIsTheProcessOnly(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler), Check{Name: "store", Ready: fail})
	if code, _ := probe(t, h, "/livez"); code != 200 {
		t.Fatalf("livez = %d with a failing readiness check, want 200 (liveness ignores readiness)", code)
	}
}

func TestReadyzReportsEachCheckAndFailsWhenAnyCheckFailsOrDraining(t *testing.T) {
	cases := []struct {
		name     string
		checks   []Check
		drain    bool
		wantCode int
		wantBody []string
	}{
		{"every check passes", []Check{{"keys", pass}, {"store", pass}}, false, 200, []string{`"status":"ok"`, `"keys":"ok"`, `"store":"ok"`}},
		{"one check fails", []Check{{"keys", pass}, {"store", fail}}, false, 503, []string{`"status":"unavailable"`, `"keys":"ok"`, `"store":"fail"`}},
		{"draining", []Check{{"keys", pass}}, true, 503, []string{`"draining":"fail"`, `"keys":"ok"`}},
		{"a hung check times out", []Check{{"store", hang}}, false, 503, []string{`"store":"fail"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// synctest: the hung check's 2 s timeout passes on the fake clock, with no real wait.
			synctest.Test(t, func(t *testing.T) {
				h := New(slog.New(slog.DiscardHandler), c.checks...)
				if c.drain {
					h.Drain()
				}
				code, body := probe(t, h, "/readyz")
				if code != c.wantCode {
					t.Errorf("readyz = %d, want %d; body %s", code, c.wantCode, body)
				}
				for _, w := range c.wantBody {
					if !strings.Contains(body, w) {
						t.Errorf("readyz body lacks %s: %s", w, body)
					}
				}
			})
		})
	}
}

func TestReadyzKeepsCheckErrorsInTheLogNotTheBody(t *testing.T) {
	var logs bytes.Buffer
	h := New(slog.New(slog.NewJSONHandler(&logs, nil)), Check{Name: "store", Ready: fail})
	_, body := probe(t, h, "/readyz")
	if strings.Contains(body, "/secret/path") {
		t.Errorf("the check error reached the probe body: %s", body)
	}
	if !strings.Contains(logs.String(), "/secret/path") {
		t.Errorf("the check error is missing from the log: %s", logs.String())
	}
}
