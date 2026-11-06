package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig"

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "json")
	h := http.Header{"Authorization": {"Bearer " + token}}
	log.Info("request",
		"authorization", "Bearer "+token, // not an allowed key
		"token", token, // not an allowed key
		"headers", h, // not an allowed key
		"error", errors.New("upstream said: Bearer "+token), // allowed key, secret value
		"reason", "Bearer "+token, // allowed key, secret value
		"value", h, // allowed key, but a header map is never logged
		"method", "POST",
	)
	out := buf.String()
	for _, leak := range []string{token, "Bearer", "authorization", "headers"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"method":"POST"`) || !strings.Contains(out, `"reason":"[REDACTED]"`) {
		t.Fatalf("expected allowed attrs: %s", out)
	}
}

func TestGroupContentsAreDropped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "json").Info("x", slog.Group("req", "reason", "inside"))
	if strings.Contains(buf.String(), "inside") {
		t.Fatalf("group content logged: %s", buf.String())
	}
}

func TestTimeIsUTC(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "json").Info("x")
	if !strings.Contains(buf.String(), `Z","level"`) {
		t.Fatalf("time not UTC: %s", buf.String())
	}
}

func TestMiddlewareLogsRequestWithoutQueryOrHeaders(t *testing.T) {
	var buf bytes.Buffer
	var seen string
	h := Middleware(New(&buf, "json"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest("POST", "/mcp?access_token="+token, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Mcp-Method", "tools/call")
	h.ServeHTTP(httptest.NewRecorder(), r)
	out := buf.String()
	if len(seen) != 32 || !strings.Contains(out, seen) {
		t.Fatalf("request id %q not logged: %s", seen, out)
	}
	if strings.Contains(out, token) || strings.Contains(out, "access_token") {
		t.Fatalf("log leaks: %s", out)
	}
	if !strings.Contains(out, `"status":418`) || !strings.Contains(out, `"mcp_method":"tools/call"`) {
		t.Fatalf("missing fields: %s", out)
	}
}
