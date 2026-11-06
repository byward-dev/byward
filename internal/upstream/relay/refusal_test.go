package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeupstream"
)

const toolsCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"ping"}}`

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
		{"upstream's JSON-RPC answer for another id is not trusted", 403, `{"jsonrpc":"2.0","id":8,"error":{"code":-32001,"message":"other"}}`, "POST", toolsCall, 200,
			`"isError":true`},
		{"notification: accepted", 403, ``, "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ""},
		{"GET stream: no stream offered", 403, ``, "GET", ``, 405, ""},
		{"DELETE: termination not allowed", 403, ``, "DELETE", ``, 405, ""},
		{"401 on another method names the credential", 401, ``, "POST", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, 200,
			`"data":{"upstreamStatus":401},"message":"The upstream MCP server rejected the proxy's credentials; ask your operator."`},
		{"batch: id unknown, 502", 403, ``, "POST", `[` + toolsCall + `]`, 502, "upstream refused the proxy"},
		{"not JSON-RPC: 502", 403, ``, "POST", `hello`, 502, "upstream refused the proxy"},
		{"null id: 502", 403, ``, "POST", `{"jsonrpc":"2.0","id":null,"method":"tools/call"}`, 502, "upstream refused the proxy"},
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
			if c.wantStatus == 200 && !json.Valid(w.Body.Bytes()) {
				t.Fatalf("not JSON: %s", w.Body)
			}
		})
	}
}

func TestRefusalWithTruncatedCaptureFallsBackTo502(t *testing.T) {
	big := `{"jsonrpc":"2.0","method":"tools/call","params":{"pad":"` + strings.Repeat("x", captureLimit) + `"},"id":1}`
	w := httptest.NewRecorder()
	refuse(t, 403, "").ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(big)))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "upstream refused the proxy") {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
}

func TestIDIsEchoedExactly(t *testing.T) {
	for _, id := range []string{`7`, `-1.5e3`, `"xé"`, `"a\"b"`} {
		req, ok := parseRequest([]byte(`{"jsonrpc":"2.0","method":"m","id":` + id + `}`))
		if !ok {
			t.Fatalf("%s rejected", id)
		}
		var out struct{ ID json.RawMessage }
		if err := json.Unmarshal(synthesize(req, 403), &out); err != nil || !bytes.Equal(out.ID, []byte(id)) {
			t.Fatalf("id %s echoed as %s (%v)", id, out.ID, err)
		}
	}
	for _, id := range []string{`null`, `true`, `{}`, `[]`} {
		if _, ok := parseRequest([]byte(`{"jsonrpc":"2.0","method":"m","id":` + id + `}`)); ok {
			t.Fatalf("invalid id %s accepted", id)
		}
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
