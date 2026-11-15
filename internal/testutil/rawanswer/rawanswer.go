// Package rawanswer serves an HTTP answer byte for byte, past net/http's own framing, so a test can
// send what a misbehaving server sends.
package rawanswer

import "net/http"

// RefusedTrailer is a chunked 200 whose trailer line Go's transport refuses (a control character);
// the line holds SECRET, which no error may quote.
const RefusedTrailer = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Sid: SECRET\x01\r\n\r\n"

// Handler writes raw to the connection as the whole answer and closes it.
func Handler(raw string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte(raw))
	}
}
