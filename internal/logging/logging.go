// Package logging builds the proxy's slog logger: an allowlist of attribute keys, redaction of
// bearer-shaped values, UTC timestamps, and a request ID per request (ADR-0021).
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Redacted replaces a value that must never be logged.
const redacted = "[REDACTED]"

// allowed lists every attribute key the proxy may log. Anything else is dropped, so a new field
// has to be added here on purpose (invariant: never log tokens, secrets, codes or verifiers).
var allowed = map[string]bool{
	slog.TimeKey: true, slog.LevelKey: true, slog.MessageKey: true,
	"request_id": true, "method": true, "path": true, "status": true, "duration_ms": true,
	"mcp_method": true, "remote_ip": true, "host": true, "origin": true, "reason": true,
	"error": true, "listen": true, "version": true, "relaxation": true,
	"setting": true, "value": true, "source": true, "panic": true,
	// stdio upstream processes (ADR-0003 §5, ADR-0021 §6): stderr lines are upstream-controlled text
	// and still pass the bearer-shaped redaction.
	"upstream": true, "process": true, "user_key": true, "line": true, "truncated": true,
	"suppressed": true, "exit_code": true, "signal": true,
	// Audit stream (ADR-0021 §3; docs/reference/observability.md). Grant and key IDs are internal
	// identifiers, never credentials.
	"log.type": true, "schema_version": true, "event": true, "outcome": true, "client_id": true,
	"client_trust": true, "grant_id": true, "key_id": true, "idp": true,
	// IdP errors (ADR-0021 §7): the IdP's error code and its own trace and correlation IDs.
	"idp_error_code": true, "trace_id": true, "correlation_id": true,
}

// New returns a logger writing JSON (or text) to w.
func New(w io.Writer, format string) *slog.Logger {
	opts := &slog.HandlerOptions{ReplaceAttr: replace}
	if format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func replace(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 || !allowed[a.Key] {
		return slog.Attr{}
	}
	if a.Key == slog.TimeKey {
		return slog.Time(slog.TimeKey, a.Value.Time().UTC())
	}
	switch a.Value.Kind() {
	case slog.KindString:
		if looksSecret(a.Value.String()) {
			return slog.String(a.Key, redacted)
		}
	case slog.KindAny, slog.KindLogValuer:
		// Structured values (header maps, requests) could carry credentials: only errors and
		// stringers pass, and only after the same check.
		var s string
		switch v := a.Value.Resolve().Any().(type) {
		case error:
			s = v.Error()
		case interface{ String() string }:
			s = v.String()
		default:
			return slog.Attr{}
		}
		if looksSecret(s) {
			s = redacted
		}
		return slog.String(a.Key, s)
	}
	return a
}

func looksSecret(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "bearer ") || strings.Contains(l, "basic ") || strings.Contains(l, "eyj")
}

type ctxKey struct{}

// RequestID returns the request ID stored in ctx, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// WithRequestID stores id in ctx.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// newRequestID returns a random (version 4) UUID. Entra takes it as `client-request-id` only in
// GUID form and returns it as `correlation_id`, so one ID matches across both logs (ADR-0021 §2).
func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Middleware gives each request an ID and logs one line per request. The query string is never
// logged; neither are headers, except the `Mcp-Method` value.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		r = r.WithContext(withRequestID(r.Context(), id))
		// Echoed so users and operators can quote it; inbound IDs are not trusted (no trusted proxies yet).
		w.Header().Set("X-Request-Id", id)
		rec := NewStatusRecorder(w)
		next.ServeHTTP(rec, r)
		attrs := []any{"request_id", id, "method", r.Method, "path", r.URL.Path, "status", rec.Status(),
			"duration_ms", time.Since(start).Milliseconds(), "remote_ip", RemoteIP(r)}
		if m := r.Header.Get("Mcp-Method"); m != "" {
			attrs = append(attrs, "mcp_method", m)
		}
		log.InfoContext(r.Context(), "request", attrs...)
	})
}

// StatusRecorder records the final status a handler writes (200 if it writes none). The request
// log, metrics and server spans all read the status through it.
type StatusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// NewStatusRecorder wraps w.
func NewStatusRecorder(w http.ResponseWriter) *StatusRecorder {
	return &StatusRecorder{ResponseWriter: w, status: http.StatusOK}
}

// Status is the final status written so far.
func (s *StatusRecorder) Status() int { return s.status }

// WriteHeader records code. 1xx informational responses (other than 101) precede the final status.
func (s *StatusRecorder) WriteHeader(code int) {
	if !s.wroteHeader && (code < 100 || code > 199 || code == http.StatusSwitchingProtocols) {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *StatusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush, deadlines).
func (s *StatusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
