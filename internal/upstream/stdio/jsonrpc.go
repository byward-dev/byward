//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// JSON-RPC error codes (JSON-RPC 2.0 §5.1).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInternalError  = -32603
)

type kind int

const (
	kindInvalid kind = iota
	kindRequest
	kindNotification
	kindResponse
)

// envelope is what the bridge reads of a JSON-RPC message: enough to route it, nothing more.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func (e envelope) kind() kind {
	// A request id is a string or an integer (MCP 2025-11-25 basic, Requests); a notification has
	// none at all.
	present := len(e.ID) > 0
	hasID := present && validID(e.ID)
	switch {
	case e.Method != "" && hasID:
		return kindRequest
	case e.Method != "" && !present:
		return kindNotification
	case hasID && (e.Result != nil || e.Error != nil):
		return kindResponse
	}
	return kindInvalid
}

// validID reports whether id, a JSON value, is a string or an integer.
func validID(id json.RawMessage) bool {
	switch c := id[0]; {
	case c == '"':
		return true
	case c == '-' || (c >= '0' && c <= '9'):
		return !bytes.ContainsAny(id, ".eE")
	}
	return false
}

func parseEnvelope(msg []byte) (envelope, error) {
	var e envelope
	if err := json.Unmarshal(msg, &e); err != nil {
		return e, err
	}
	return e, nil
}

type rpcFault struct {
	code int
	msg  string
}

// parseMessage checks a POST body is one JSON-RPC message and returns it as one line for stdin.
// The bytes are kept as sent unless they hold a line break, which can only be whitespace in JSON
// and would break the stdio framing; then the whitespace is removed.
func parseMessage(body []byte) ([]byte, envelope, *rpcFault) {
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		return nil, envelope{}, &rpcFault{codeInvalidRequest, "Bad Request: send one JSON-RPC message per request (batches are not part of MCP 2025-11-25)"}
	}
	env, err := parseEnvelope(body)
	if err != nil || len(body) == 0 || body[0] != '{' {
		return nil, envelope{}, &rpcFault{codeParseError, "Parse error: the body is not a JSON-RPC message"}
	}
	if env.kind() == kindInvalid {
		return nil, envelope{}, &rpcFault{codeInvalidRequest, "Invalid Request: not a JSON-RPC request, notification or response"}
	}
	// env.Method is encoding/json's reading: any case, last key wins. An upstream may read the exact
	// key, or the first, so a repeated top-level key or a method in another case is refused before
	// the method decides anything (initialize or not, which era, which header rules).
	if _, err := locate(body, pathMethod); err != nil {
		return nil, envelope{}, &rpcFault{codeInvalidRequest, "Invalid Request: the message is ambiguous: a top-level key is repeated, or the method is given in another case"}
	}
	if bytes.ContainsAny(body, "\r\n") {
		var b bytes.Buffer
		if err := json.Compact(&b, body); err != nil {
			return nil, envelope{}, &rpcFault{codeParseError, "Parse error: the body is not a JSON-RPC message"}
		}
		body = b.Bytes()
	}
	env.ID = compactID(env.ID)
	return body, env, nil
}

// compactID is the id with insignificant whitespace removed, so it matches however it is spaced.
func compactID(id json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		return id
	}
	return b.Bytes()
}

func rpcError(id json.RawMessage, code int, message string) []byte {
	if id == nil {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id, Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{code, message}})
	return b
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(rpcError(id, code, message))
}
