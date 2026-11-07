package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ADR-0025's answer shapes for a refusal decided before relaying.
func TestAnswerFollowsTheRefusalShapes(t *testing.T) {
	const msg = "This tool needs an administrator to grant access; ask your operator."
	data := map[string]string{"downstream": "consent_required"}
	overCapture := `{"jsonrpc":"2.0","method":"tools/call","params":{"pad":"` + strings.Repeat("x", captureLimit) + `"},"id":1}`
	cases := []struct {
		name, method, body string
		wantStatus         int
		wantBody           string // a substring; "" means empty
	}{
		{"tools/call: a tool error the model can read", "POST", toolsCall, 200,
			`{"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"` + msg + `","type":"text"}],"isError":true}}`},
		{"another method: JSON-RPC error with data", "POST", `{"jsonrpc":"2.0","id":"a-1","method":"tools/list"}`, 200,
			`{"error":{"code":-32603,"data":{"downstream":"consent_required"},"message":"` + msg + `"},"id":"a-1","jsonrpc":"2.0"}`},
		{"notification: accepted", "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ""},
		{"GET: no stream offered", "GET", ``, 405, ""},
		{"batch: id unknown, the fallback status", "POST", `[` + toolsCall + `]`, 503, msg},
		{"not JSON-RPC: the fallback status", "POST", `hello`, 503, msg},
		{"over the capture limit: the fallback status", "POST", overCapture, 503, msg},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			Answer(w, httptest.NewRequest(c.method, "/mcp", strings.NewReader(c.body)), msg, data, http.StatusServiceUnavailable)
			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d (body %q)", w.Code, c.wantStatus, w.Body)
			}
			if c.wantBody == "" && w.Body.Len() != 0 {
				t.Fatalf("body %q, want empty", w.Body)
			}
			if !strings.Contains(w.Body.String(), c.wantBody) {
				t.Fatalf("body %q, want %q", w.Body, c.wantBody)
			}
			if c.wantStatus == 200 && !json.Valid(w.Body.Bytes()) {
				t.Fatalf("not JSON: %s", w.Body)
			}
			if c.method != "POST" && w.Header().Get("Allow") != "POST" {
				t.Fatal("405 without Allow: POST")
			}
		})
	}
}
