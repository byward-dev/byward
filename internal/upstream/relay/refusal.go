package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// An upstream 401 or 403 means it refused the proxy's credential or identity assertion: the
// client's own token was valid, or the request would not have reached the upstream. Every non-2xx
// status breaks some client (VS Code puts the server into an error state, go-sdk closes the
// session on 403, Inspector asks the user to log in), so the refusal is answered as a JSON-RPC
// response the client and the model can read (ADR-0025). Only this path looks at bodies.

// captureLimit bounds the copy of each request body kept for answering a refusal.
const captureLimit = 64 << 10

const (
	msgUnauthorized = "The upstream MCP server rejected the proxy's credentials; ask your operator."
	msgForbidden    = "The upstream MCP server denied this request; ask your operator."
)

// capture keeps the first captureLimit bytes of a request body as it streams to the upstream.
// The transport writes it on its own goroutine, and an upstream may refuse before reading the whole
// body, so reads take a locked snapshot; a partial body then fails to parse and becomes a 502.
type capture struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func (c *capture) snapshot() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...), c.truncated
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := captureLimit - len(c.buf); len(p) > room {
		c.buf = append(c.buf, p[:max(room, 0)]...)
		c.truncated = true
	} else {
		c.buf = append(c.buf, p...)
	}
	return len(p), nil
}

type teeBody struct {
	io.Reader
	io.Closer
}

type captureKey struct{}

// rpcRequest is the part of a JSON-RPC request needed to answer it.
type rpcRequest struct {
	id     json.RawMessage // nil for a notification
	method string
}

// parseRequest reads the captured body as one JSON-RPC request. Batches, truncated bodies, and
// anything that is not a well-formed request return ok=false; the caller then falls back to 502.
func parseRequest(body []byte) (rpcRequest, bool) {
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.JSONRPC != "2.0" || m.Method == "" {
		return rpcRequest{}, false
	}
	if m.ID != nil && !validID(m.ID) {
		return rpcRequest{}, false
	}
	return rpcRequest{id: m.ID, method: m.Method}, true
}

// validID accepts the JSON-RPC id forms MCP allows: a string or a number (never null).
func validID(id json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return false
	}
	switch v.(type) {
	case string, float64:
		return true
	}
	return false
}

// matchingResponse reports whether body is already a JSON-RPC response to id (some upstreams
// send their denial that way); it is then relayed as is, so the upstream's own message arrives.
func matchingResponse(body []byte, id json.RawMessage) bool {
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.JSONRPC != "2.0" || (m.Result == nil) == (m.Error == nil) {
		return false
	}
	var a, b bytes.Buffer
	return json.Compact(&a, m.ID) == nil && json.Compact(&b, id) == nil && bytes.Equal(a.Bytes(), b.Bytes())
}

// synthesize answers req after an upstream refusal with upstreamStatus.
func synthesize(req rpcRequest, upstreamStatus int) []byte {
	msg := msgForbidden
	if upstreamStatus == http.StatusUnauthorized {
		msg = msgUnauthorized
	}
	return rpcAnswer(req, msg, map[string]int{"upstreamStatus": upstreamStatus})
}

// rpcAnswer answers req with msg: a tools/call gets a tool result with isError (the spec's tool
// execution error, which reaches the model in every client); anything else a JSON-RPC error
// -32603 carrying data.
func rpcAnswer(req rpcRequest, msg string, data any) []byte {
	var v any
	if req.method == "tools/call" {
		v = map[string]any{"jsonrpc": "2.0", "id": req.id, "result": map[string]any{
			"content": []map[string]string{{"type": "text", "text": msg}}, "isError": true}}
	} else {
		v = map[string]any{"jsonrpc": "2.0", "id": req.id, "error": map[string]any{
			"code": -32603, "message": msg, "data": data}}
	}
	// No HTML escaping: the id must come back byte for byte, and `<`, `>`, `&` are valid in it.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // only maps of strings, ints, bools and a validated raw id
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// outcome names what translate did, for the operator log.
type outcome string

const (
	outcomeStreamRefused outcome = "non-POST refused with 405"
	outcomeNotification  outcome = "notification accepted with 202"
	outcomeRelayed       outcome = "upstream JSON-RPC response relayed with 200"
	outcomeSynthesized   outcome = "answered with a JSON-RPC response"
	outcomeUnanswerable  outcome = "request id unknown; 502"
	outcomeTimedOut      outcome = "request id unknown; 504"
)

// translate rewrites an upstream refusal in place. It reports outcomeUnanswerable when the
// response must become a 502 instead.
func translate(res *http.Response, c *capture) outcome {
	up, _ := io.ReadAll(io.LimitReader(res.Body, captureLimit+1))
	_ = res.Body.Close() // always; a refusal body over the bound costs only that connection
	if res.Request.Method != http.MethodPost {
		// GET: the spec's "no SSE stream offered"; DELETE: "termination not allowed". Clients treat
		// both as harmless.
		replace(res, http.StatusMethodNotAllowed, nil)
		res.Header.Set("Allow", "POST")
		return outcomeStreamRefused
	}
	if c == nil {
		return outcomeUnanswerable
	}
	body, truncated := c.snapshot()
	if truncated {
		return outcomeUnanswerable
	}
	req, ok := parseRequest(body)
	switch {
	case !ok:
		return outcomeUnanswerable
	case req.id == nil:
		replace(res, http.StatusAccepted, nil)
		return outcomeNotification
	case len(up) <= captureLimit && matchingResponse(up, req.id):
		replace(res, http.StatusOK, up)
		return outcomeRelayed
	default:
		replace(res, http.StatusOK, synthesize(req, res.StatusCode))
		return outcomeSynthesized
	}
}

func replace(res *http.Response, status int, body []byte) {
	res.StatusCode = status
	res.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
	res.Header = http.Header{}
	res.Trailer = nil
	res.TransferEncoding = nil
	res.ContentLength = int64(len(body))
	res.Body = io.NopCloser(bytes.NewReader(body))
	if body != nil {
		res.Header.Set("Content-Type", "application/json")
	}
}
