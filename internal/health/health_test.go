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
	"time"
)

func probe(t *testing.T, h *Health, path string) (int, string) {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w.Code, w.Body.String()
}

func TestLivezIsTheProcessOnly(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler), Check{Name: "store", Ready: func(context.Context) error { return errors.New("down") }})
	if code, _ := probe(t, h, "/livez"); code != 200 {
		t.Fatalf("livez = %d with a failing readiness check, want 200", code)
	}
}

func TestReadyzReportsEachCheckWithoutErrorDetails(t *testing.T) {
	var logs bytes.Buffer
	h := New(slog.New(slog.NewJSONHandler(&logs, nil)),
		Check{Name: "keys", Ready: func(context.Context) error { return nil }},
		Check{Name: "store", Ready: func(context.Context) error { return errors.New("open /secret/path: denied") }})
	code, body := probe(t, h, "/readyz")
	if code != 503 || !strings.Contains(body, `"store":"fail"`) || !strings.Contains(body, `"keys":"ok"`) {
		t.Fatalf("readyz = %d %s", code, body)
	}
	if strings.Contains(body, "/secret/path") || !strings.Contains(logs.String(), "/secret/path") {
		t.Fatalf("the error must go to the log, not the probe body: body=%s logs=%s", body, logs.String())
	}
}

func TestReadyzPassesWhenEveryCheckDoes(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler), Check{Name: "keys", Ready: func(context.Context) error { return nil }})
	if code, body := probe(t, h, "/readyz"); code != 200 || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("readyz = %d %s", code, body)
	}
}

func TestReadyzFailsWhileDraining(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler))
	h.Drain()
	if code, body := probe(t, h, "/readyz"); code != 503 || !strings.Contains(body, `"draining":"fail"`) {
		t.Fatalf("readyz while draining = %d %s", code, body)
	}
}

func TestAHungCheckTimesOut(t *testing.T) {
	h := New(slog.New(slog.DiscardHandler), Check{Name: "store", Ready: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}})
	start := time.Now()
	if code, _ := probe(t, h, "/readyz"); code != 503 || time.Since(start) > checkTimeout+time.Second {
		t.Fatalf("readyz = %d after %v", code, time.Since(start))
	}
}
