package logging

import (
	"regexp"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	var line struct{ Time string }
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339Nano, line.Time)
	if err != nil || ts.Location() != time.UTC {
		t.Fatalf("time %q not UTC: %v", line.Time, err)
	}
}

func TestTextFormatRedactsToo(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "text").Info("request", "reason", "Bearer "+token, "token", token)
	if strings.Contains(buf.String(), token) || !strings.Contains(buf.String(), redacted) {
		t.Fatalf("text log leaks: %s", buf.String())
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
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	r.RemoteAddr = "192.0.2.7:51234"
	r.Header.Set("X-Request-Id", "spoofed")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	out := buf.String()
	if rec.Header().Get("X-Request-Id") != seen || strings.Contains(out, "spoofed") {
		t.Fatalf("request id not echoed or inbound id trusted: %q / %s", rec.Header().Get("X-Request-Id"), out)
	}
	if !uuidV4.MatchString(seen) || !strings.Contains(out, seen) {
		t.Fatalf("request id %q not logged: %s", seen, out)
	}
	if strings.Contains(out, token) || strings.Contains(out, "access_token") {
		t.Fatalf("log leaks: %s", out)
	}
	if !strings.Contains(out, `"remote_ip":"192.0.2.7"`) || strings.Contains(out, "6.6.6.6") {
		t.Fatalf("remote ip must be the TCP peer: %s", out)
	}
	if !strings.Contains(out, `"status":418`) || !strings.Contains(out, `"mcp_method":"tools/call"`) {
		t.Fatalf("missing fields: %s", out)
	}
}

func TestInformationalStatusIsNotLoggedAsFinal(t *testing.T) {
	var buf bytes.Buffer
	h := Middleware(New(&buf, "json"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(buf.String(), `"status":502`) {
		t.Fatalf("logged %s", buf.String())
	}
}

// Entra takes client-request-id only as a GUID (ADR-0021 §2), so request IDs are version 4 UUIDs.
var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestRequestIDsAreDistinctVersion4UUIDs(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newRequestID()
		if !uuidV4.MatchString(id) || seen[id] {
			t.Fatalf("request id %q is not a fresh version 4 UUID", id)
		}
		seen[id] = true
	}
}
