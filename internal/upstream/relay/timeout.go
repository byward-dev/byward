package relay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
)

// An upstream that never sends its response headers would hold its in-flight slot until the
// client gives up, and some clients never do. After the response-header timeout (ADR-0018 §7) the
// request is answered the way a refusal is (ADR-0025): every non-2xx status breaks some client.
// A streamed response is not limited once its headers have arrived.

const msgTimeout = "The upstream MCP server did not answer in time; try again later, or ask your operator."

type wroteKey struct{}

// traceWrite records in ctx when the request has been fully written to the upstream. Dial and TLS
// handshake timeouts happen before that and stay a 502 like any unreachable upstream; after it the
// response-header timeout is the only transport timeout that can fire.
func traceWrite(ctx context.Context) context.Context {
	wrote := new(atomic.Bool)
	ctx = context.WithValue(ctx, wroteKey{}, wrote)
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(i httptrace.WroteRequestInfo) {
		if i.Err == nil {
			wrote.Store(true)
		}
	}})
}

// isHeaderTimeout reports whether err is the response-header timeout: a timeout (HTTP/1 and HTTP/2
// both report it as a net.Error with Timeout) after the request was written, while the client
// still waits.
func isHeaderTimeout(ctx context.Context, err error) bool {
	wrote, _ := ctx.Value(wroteKey{}).(*atomic.Bool)
	var ne net.Error
	return wrote != nil && wrote.Load() && errors.As(err, &ne) && ne.Timeout() && ctx.Err() == nil
}

// answerTimeout answers a request whose upstream did not answer in time. The transport starts
// the timer only after the request body is fully written, so the capture is complete unless it
// was truncated.
func answerTimeout(ctx context.Context, w http.ResponseWriter, method string) outcome {
	if method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return outcomeStreamRefused
	}
	c, _ := ctx.Value(captureKey{}).(*capture)
	if c == nil {
		return timeoutUnanswerable(w)
	}
	body, truncated := c.snapshot()
	req, ok := parseRequest(body)
	switch {
	case truncated || !ok:
		return timeoutUnanswerable(w)
	case req.id == nil:
		w.WriteHeader(http.StatusAccepted)
		return outcomeNotification
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rpcAnswer(req, msgTimeout, map[string]bool{"upstreamTimeout": true}))
	return outcomeSynthesized
}

// timeoutUnanswerable is the fallback when the request id is unknown: RFC 9110 §15.6.5.
func timeoutUnanswerable(w http.ResponseWriter) outcome {
	http.Error(w, "upstream did not answer in time", http.StatusGatewayTimeout)
	return outcomeTimedOut
}
