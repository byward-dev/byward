// Package origin checks the `Host` of every request and the `Origin` on the MCP endpoint before
// authentication (ADR-0018 §1–2): a wrong Host gets 421, a disallowed Origin 403.
package origin

import (
	"net/http"
	"strings"

	"github.com/byward-dev/byward/internal/audit"
)

// Hosts allows only the given hosts (host[:port], compared case-insensitively; default ports
// :80 and :443 are ignored). Mismatches get 421 Misdirected Request and an audit event, rate-limited
// per source because the sender is not authenticated.
func Hosts(rec *audit.Log, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, h := range allowed {
		set[hostKey(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !set[hostKey(r.Host)] {
			rec.RecordUnauthenticated(r, audit.Event{Name: audit.HostRejected, Outcome: audit.Failure, Host: r.Host})
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

// CORS for listed origins on the MCP endpoint: browser-based MCP clients send a preflight without
// credentials, so it is answered here, before authentication, and every response to a listed
// origin carries the headers the client must read (the 401 challenge, the session ID).
const (
	allowMethods  = "GET, POST, DELETE"
	allowHeaders  = "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Mcp-Method, Mcp-Name, Last-Event-ID"
	exposeHeaders = "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, Retry-After"
)

// Origins enforces an exact allowlist of `Origin` values (scheme://host[:port], lower case). A
// missing Origin passes (non-browser MCP clients send none); multiple Origin headers, `null` or an
// unlisted value get 403. A listed origin gets CORS headers, and its preflight is answered with 204.
func Origins(rec *audit.Log, allowed []string, next http.Handler) http.Handler {
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
			rec.RecordUnauthenticated(r, audit.Event{Name: audit.OriginRejected, Outcome: audit.Failure, Origin: o})
			// Claude Code and VS Code treat any 403 as "needs auth", so the body names the real fix.
			http.Error(w, "origin "+o+" is not allowed; the operator can add it to BYWARD_ALLOWED_ORIGINS", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", vals[0])
		h.Add("Vary", "Origin")
		h.Set("Access-Control-Expose-Headers", exposeHeaders)
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", allowMethods)
			h.Set("Access-Control-Allow-Headers", allowHeaders)
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
