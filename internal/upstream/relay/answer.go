package relay

import (
	"io"
	"net/http"
)

// Answer answers r in the proxy's name, without the upstream, the way an upstream refusal is
// answered (ADR-0025), for refusals decided before relaying (On-Behalf-Of, ADR-0017 §5):
//   - anything but POST: 405;
//   - a notification: 202;
//   - a tools/call: a tool result with isError and msg;
//   - another request: JSON-RPC error -32603 with msg and data;
//   - a request whose id cannot be read (a batch, an oversized or malformed body): fallback, with
//     msg as plain text.
//
// It reads at most the capture limit of r's body, which has not been relayed yet.
func Answer(w http.ResponseWriter, r *http.Request, msg string, data any, fallback int) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, captureLimit+1))
	}
	req, ok := parseRequest(body)
	switch {
	case len(body) > captureLimit || !ok:
		http.Error(w, msg, fallback)
		return
	case req.id == nil:
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rpcAnswer(req, msg, data))
}
