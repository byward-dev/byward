// Package logging builds the proxy's slog logger: an allowlist of attribute keys, redaction of
// bearer-shaped values, UTC timestamps, and a request ID per request (ADR-0021).
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Redacted replaces a value that must never be logged.
const Redacted = "[REDACTED]"

// allowed lists every attribute key the proxy may log. Anything else is dropped, so a new field
// has to be added here on purpose (invariant: never log tokens, secrets, codes or verifiers).
var allowed = map[string]bool{
	slog.TimeKey: true, slog.LevelKey: true, slog.MessageKey: true,
	"request_id": true, "method": true, "path": true, "status": true, "duration_ms": true,
	"mcp_method": true, "remote_ip": true, "host": true, "origin": true, "reason": true,
	"error": true, "listen": true, "version": true, "relaxation": true,
	"setting": true, "value": true, "source": true, "panic": true,
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
			return slog.String(a.Key, Redacted)
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
			s = Redacted
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
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// NewRequestID returns 16 random bytes in hex.
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Middleware gives each request an ID and logs one line per request. The query string is never
// logged; neither are headers, except the `Mcp-Method` value.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := NewRequestID()
		r = r.WithContext(WithRequestID(r.Context(), id))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		attrs := []any{"request_id", id, "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(), "remote_ip", remoteIP(r)}
		if m := r.Header.Get("Mcp-Method"); m != "" {
			attrs = append(attrs, "mcp_method", m)
		}
		log.InfoContext(r.Context(), "request", attrs...)
	})
}

// remoteIP is the TCP peer. Forwarded headers are not trusted until trusted proxies are
// configurable (ADR-0018 §6).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush, deadlines).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
