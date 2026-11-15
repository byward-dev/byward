package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

const toolsCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"ping"}}`

// Bodies over the capture limit: one cut off inside the request, one a whole request whose capture
// is cut off in the padding after it (it parses, so only the truncation makes its id unknown).
var (
	overCapture = `{"jsonrpc":"2.0","method":"tools/call","params":{"pad":"` + strings.Repeat("x", captureLimit) + `"},"id":1}`
	padded      = toolsCall + strings.Repeat(" ", captureLimit)
)

// refuse makes the fake upstream answer every request with status and body (and a challenge
// that must never reach the client).
func refuse(t *testing.T, status int, body string) http.Handler {
	t.Helper()
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://elsewhere.example/x", error="insufficient_scope"`)
		w.Header().Set("Mcp-Session-Id", "leaked")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
	return relayTo(t, up, "/mcp")
}

func TestUpstreamRefusalBecomesAReadableJSONRPCResponse(t *testing.T) {
	// The upstream's own answer, padded to exactly the capture limit: the most that is relayed.
	answer := `{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"missing role"}}`
	atLimit := answer + strings.Repeat(" ", captureLimit-len(answer))
	cases := []struct {
		name            string
		upstream        int
		upstreamBody    string
		method, reqBody string
		wantStatus      int
		wantBody        string // substring; "" means empty body
	}{
		{"403 on tools/call: tool error the model can read", 403, `forbidden`, "POST", toolsCall, 200,
			`{"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"The upstream MCP server denied this request; ask your operator.","type":"text"}],"isError":true}}`},
		{"401 on tools/call names the credential", 401, ``, "POST", toolsCall, 200, `rejected the proxy's credentials`},
		{"403 on another method: JSON-RPC error", 403, ``, "POST", `{"jsonrpc":"2.0","id":"a-1","method":"initialize","params":{}}`, 200,
			`{"error":{"code":-32603,"data":{"upstreamStatus":403},"message":"The upstream MCP server denied this request; ask your operator."},"id":"a-1","jsonrpc":"2.0"}`},
		{"upstream's own JSON-RPC answer with the same id is relayed", 403, `{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"missing role Mcp.Admin"}}`, "POST", toolsCall, 200,
			`"missing role Mcp.Admin"`},
		{"upstream's JSON-RPC answer of exactly the capture limit is relayed", 403, atLimit, "POST", toolsCall, 200, `"missing role"`},
		{"upstream's JSON-RPC answer past the capture limit is not trusted", 403, atLimit + " ", "POST", toolsCall, 200,
			`{"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"The upstream MCP server denied this request; ask your operator.","type":"text"}],"isError":true}}`},
		{"upstream's JSON-RPC answer for another id is not trusted", 403, `{"jsonrpc":"2.0","id":8,"error":{"code":-32001,"message":"other"}}`, "POST", toolsCall, 200,
			`"isError":true`},
		{"notification: accepted", 403, ``, "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ""},
		{"GET stream: no stream offered", 403, ``, "GET", ``, 405, ""},
		{"DELETE: termination not allowed", 403, ``, "DELETE", ``, 405, ""},
		{"401 on another method names the credential", 401, ``, "POST", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, 200,
			`"data":{"upstreamStatus":401},"message":"The upstream MCP server rejected the proxy's credentials; ask your operator."`},
		{"not JSON-RPC: id unknown, 502", 403, ``, "POST", `hello`, 502, "upstream refused the proxy"},
		{"over the capture limit: id unknown, 502", 403, ``, "POST", overCapture, 502, "upstream refused the proxy"},
		{"over the capture limit, its readable part a whole request: id unknown, 502", 403, ``, "POST", padded, 502, "upstream refused the proxy"},
		{"other statuses pass through", 404, `nope`, "POST", toolsCall, 404, "nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			refuse(t, c.upstream, c.upstreamBody).ServeHTTP(w, httptest.NewRequest(c.method, "/mcp", strings.NewReader(c.reqBody)))
			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d (body %q)", w.Code, c.wantStatus, w.Body)
			}
			if c.wantBody == "" && w.Body.Len() != 0 {
				t.Fatalf("body %q, want empty", w.Body)
			}
			if !strings.Contains(w.Body.String(), c.wantBody) {
				t.Fatalf("body %q, want %q", w.Body, c.wantBody)
			}
			if w.Header().Get("WWW-Authenticate") != "" {
				t.Fatal("the upstream's challenge reached the client")
			}
			if c.upstream != 404 && w.Header().Get("Mcp-Session-Id") != "" {
				t.Fatal("headers of a refused response reached the client")
			}
			if c.wantStatus == 200 && (!json.Valid(w.Body.Bytes()) || w.Header().Get("Content-Type") != "application/json") {
				t.Fatalf("Content-Type %q, body %s; want JSON", w.Header().Get("Content-Type"), w.Body)
			}
			if c.method != "POST" && w.Header().Get("Allow") != "POST" {
				t.Fatalf("Allow %q, want POST", w.Header().Get("Allow"))
			}
		})
	}
}

// Every 401 or 403 from the upstream is observed once with its status, by every observer, whether
// it is answered as a JSON-RPC message, accepted, or answered 502; any other status is not a refusal.
func TestEachUpstreamRefusalIsObservedOnce(t *testing.T) {
	for _, c := range []struct {
		name       string
		upstream   int
		body       string
		wantStatus int
		want       []int
	}{
		{"403 on tools/call", 403, toolsCall, 200, []int{403}},
		{"401 on tools/call", 401, toolsCall, 200, []int{401}},
		{"403 on a notification", 403, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, []int{403}},
		{"403 the proxy cannot answer", 403, `hello`, 502, []int{403}},
		{"404 is no refusal", 404, toolsCall, 404, nil},
		{"200 is no refusal", 200, toolsCall, 200, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			up.Handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(c.upstream) }
			var first, second []int
			h := relayTo(t, up, "/mcp", WithRefusalObserver(func(status int) { first = append(first, status) }),
				WithRefusalObserver(func(status int) { second = append(second, status) }))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(c.body)))
			if w.Code != c.wantStatus {
				t.Fatalf("answered %d, want %d", w.Code, c.wantStatus)
			}
			if !slices.Equal(first, c.want) || !slices.Equal(second, c.want) {
				t.Fatalf("observed %v and %v, want %v by each observer", first, second, c.want)
			}
		})
	}
}

// MCP's id is a string or an integer: a refused request with one is answered with it, byte for byte
// (a large integer too, and one written with spaces around it without them), and any other id
// leaves the request unanswerable, so the refusal becomes a 502.
func TestAStringOrIntegerIDIsEchoedExactlyAndAnyOtherLeavesTheRequestUnanswerable(t *testing.T) {
	for _, tc := range []struct {
		id    string
		valid bool
	}{
		{`7`, true}, {`9`, true}, {`-12`, true}, {`0`, true}, {`12345678901234567890`, true}, {` 7 `, true},
		{`"xé"`, true}, {`"a\"b"`, true}, {`"1.5"`, true},
		{`null`, false}, {`true`, false}, {`{}`, false}, {`[]`, false},
		{`1.5`, false}, {`-1.5e3`, false}, {`1e3`, false}, {`1E3`, false}, {`7.0`, false},
	} {
		t.Run(fmt.Sprintf("%s answerable=%v", tc.id, tc.valid), func(t *testing.T) {
			w := httptest.NewRecorder()
			body := `{"jsonrpc": "2.0", "method": "m", "id":` + tc.id + `}`
			refuse(t, 403, "").ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(body)))
			if !tc.valid {
				if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "upstream refused the proxy") {
					t.Fatalf("id %s: status %d, body %q; want 502, the id unknown", tc.id, w.Code, w.Body)
				}
				return
			}
			var out struct{ ID json.RawMessage }
			if err := json.Unmarshal(w.Body.Bytes(), &out); w.Code != http.StatusOK || err != nil || !bytes.Equal(out.ID, []byte(strings.TrimSpace(tc.id))) {
				t.Fatalf("id %s: status %d, answered with id %s (%v); want 200 and the id as sent", tc.id, w.Code, out.ID, err)
			}
		})
	}
}

// decide's verdicts, in order: the method first, then a truncated body (even one whose readable part
// parses), then the request itself.
func TestDecideRulesByMethodThenTruncationThenTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name, method, body string
		truncated          bool
		want               outcome
	}{
		{"GET", "GET", ``, false, outcomeStreamRefused},
		{"DELETE, even with a truncated request", "DELETE", toolsCall, true, outcomeStreamRefused},
		{"a whole request, truncated", "POST", toolsCall, true, outcomeUnanswerable},
		{"a batch", "POST", `[` + toolsCall + `]`, false, outcomeUnanswerable},
		{"not JSON-RPC", "POST", `hello`, false, outcomeUnanswerable},
		{"no body", "POST", ``, false, outcomeUnanswerable},
		{"a notification", "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, false, outcomeNotification},
		{"a request", "POST", toolsCall, false, outcomeSynthesized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, got := decide(tc.method, []byte(tc.body), tc.truncated)
			if got != tc.want {
				t.Fatalf("decide = %q, want %q", got, tc.want)
			}
			if got == outcomeSynthesized && (req.method != "tools/call" || string(req.id) != "7") {
				t.Fatalf("request method %q, id %s; want tools/call with id 7", req.method, req.id)
			}
		})
	}
}

func FuzzRefusalAnswer(f *testing.F) {
	for _, s := range []string{toolsCall, `{"jsonrpc":"2.0","id":"<&>","method":"tools/call"}`, `{"jsonrpc":"2.0","method":"x"}`, `[1]`, `{"id":1}`, `{"jsonrpc":"2.0","id":"q","method":"tools/call"}`, ``} {
		f.Add([]byte(s), []byte(`{"jsonrpc":"2.0","id":7,"result":{}}`))
	}
	f.Fuzz(func(t *testing.T, reqBody, upBody []byte) {
		req, ok := parseRequest(reqBody)
		if !ok || req.id == nil {
			return
		}
		out := synthesize(req, 403)
		var m struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(out, &m); err != nil || m.JSONRPC != "2.0" || !bytes.Equal(m.ID, req.id) {
			t.Fatalf("synthesized answer %s does not echo id %s byte for byte", out, req.id)
		}
		_ = matchingResponse(upBody, req.id) // must not panic
	})
}
