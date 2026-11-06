//go:build linux || darwin

package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// The stderr records must survive the proxy's logging allowlist, and a credential-shaped line from
// the upstream is redacted like any other value (invariant: never log tokens).
func TestStderrRecordsThroughTheProxyLogger(t *testing.T) {
	var buf bytes.Buffer
	m, err := New(Config{Name: "fake", Command: []string{"/bin/sh", "-c", `echo "starting" >&2; echo "Authorization: Bearer abc.def" >&2`},
		Log: logging.New(&buf, "json"), LookupEnv: lookup(proxyEnv)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.Get(context.Background(), "s1", alice)
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, p) // Done waits for the stderr drain

	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		if rec["msg"] == "upstream stderr" {
			lines = append(lines, rec)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("stderr records = %v, want 2", lines)
	}
	for _, k := range []string{"upstream", "process", "user_key", "line", "truncated"} {
		if _, ok := lines[0][k]; !ok {
			t.Errorf("key %q dropped by the logging allowlist: %v", k, lines[0])
		}
	}
	if lines[0]["line"] != "starting" || lines[1]["line"] != "[REDACTED]" {
		t.Fatalf("lines = %q, %q; want %q, %q", lines[0]["line"], lines[1]["line"], "starting", "[REDACTED]")
	}
	if strings.Contains(buf.String(), "abc.def") {
		t.Fatal("bearer token reached the log")
	}
}
