// Package origin checks the `Host` of every request and the `Origin` on the MCP endpoint before
// authentication (ADR-0018 §1–2): a wrong Host gets 421, a disallowed Origin 403.
package origin

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/corker/mcp-authproxy/internal/logging"
)

// Hosts allows only the given hosts (host[:port], compared case-insensitively; default ports
// :80 and :443 are ignored). Mismatches get 421 Misdirected Request and are logged.
func Hosts(log *slog.Logger, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, h := range allowed {
		set[hostKey(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !set[hostKey(r.Host)] {
			log.WarnContext(r.Context(), "host rejected", "request_id", logging.RequestID(r.Context()), "host", r.Host)
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hostKey(h string) string {
	h = strings.ToLower(h)
	for _, p := range []string{":443", ":80"} {
		h = strings.TrimSuffix(h, p)
	}
	return h
}

// Origins enforces an exact allowlist of `Origin` values (scheme://host[:port], lower case). A
// missing Origin passes (non-browser MCP clients send none); multiple Origin headers, `null` or an
// unlisted value get 403.
func Origins(log *slog.Logger, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, o := range allowed {
		set[strings.ToLower(o)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.Header.Values("Origin")
		if len(vals) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if len(vals) > 1 || !set[strings.ToLower(vals[0])] {
			o := vals[0]
			if len(vals) > 1 {
				o = "multiple"
			}
			log.WarnContext(r.Context(), "origin rejected", "request_id", logging.RequestID(r.Context()), "origin", o)
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
