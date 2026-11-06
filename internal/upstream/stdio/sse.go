//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// sse writes server-sent events, each flushed and bounded by writeTimeout.
type sse struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func startSSE(w http.ResponseWriter) sse {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	s := sse{w: w, rc: http.NewResponseController(w)}
	_ = s.rc.Flush()
	return s
}

// write sends msg, one JSON-RPC message, as one event. A bare CR ends an SSE line, and in JSON it
// can only be whitespace, so a message holding one is compacted first.
func (s sse) write(msg []byte) error {
	if bytes.IndexByte(msg, '\r') >= 0 {
		var b bytes.Buffer
		if json.Compact(&b, msg) == nil {
			msg = b.Bytes()
		}
	}
	_ = s.rc.SetWriteDeadline(time.Now().Add(writeTimeout))
	buf := make([]byte, 0, len(msg)+22)
	buf = append(buf, "event: message\ndata: "...)
	buf = append(append(buf, msg...), "\n\n"...)
	if _, err := s.w.Write(buf); err != nil {
		return err
	}
	return s.rc.Flush()
}
