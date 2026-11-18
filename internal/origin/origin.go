// Package origin checks the `Host` of every request and the `Origin` on the MCP endpoint before
// authentication (ADR-0018 §1–2): a wrong Host gets 421, a disallowed Origin 403.
package origin

import (
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
)

// Hosts allows only the given hosts (host[:port], compared as config.CanonicalHost writes them:
// case-insensitively, an IP address in any spelling as browsers serialize it). One default port,
// :443 or :80, is ignored, once: a proxy behind a TLS-terminating load balancer may send the host
// with :80 (nginx's $host:$server_port), and a default port on the right host names no other site.
// Mismatches get 421 Misdirected Request and an audit event, rate-limited per source because the
// sender is not authenticated.
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

// InternalHosts guards the internal listener (ADR-0018 §2, §10). Kubelet probes and Prometheus
// address a pod by its IP, which changes, so any IP literal passes, as do `localhost` and the
// operator's allowed hosts (port ignored: the listener's port is the operator's choice). A DNS
// rebinding attack always arrives with the attacker's own host name, and gets 421.
func InternalHosts(rec *audit.Log, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{"localhost": true}
	for _, h := range allowed {
		set[config.Hostname(h)] = true // config stores IP addresses canonical; any IP literal passes anyway
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := config.Hostname(config.CanonicalHost(r.Host)) // 127.1 is an IP literal too
		if _, err := netip.ParseAddr(name); err != nil && !set[name] {
			rec.RecordUnauthenticated(r, audit.Event{Name: audit.HostRejected, Outcome: audit.Failure, Host: r.Host})
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostKey is h as Hosts compares it: config.CanonicalHost (so 127.1 matches 127.0.0.1, and any
// spelling of an IPv6 address its shortest form), without one default port (:443 or :80), trimmed
// once, so [::1]:80:443 is not [::1].
func hostKey(h string) string {
	h = config.CanonicalHost(h)
	for _, p := range []string{":443", ":80"} {
		if t, ok := strings.CutSuffix(h, p); ok {
			return t
		}
	}
	return h
}

// CORS for listed origins on the MCP endpoint: browser-based MCP clients send a preflight without
// credentials, so it is answered here, before authentication, and every response to a listed
// origin carries the headers the client must read (the 401 challenge, the session ID).
const (
	allowMethods  = "GET, POST, DELETE"
	exposeHeaders = "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, Retry-After"
)

// allowHeaders are the request headers a browser MCP client may send: its credential and content
// headers, and MCP's own (config.MCPRequestHeaders).
var allowHeaders = "Authorization, Content-Type, Accept, " + strings.Join(config.MCPRequestHeaders, ", ")

// MCP 2026-07-28 (Streamable HTTP, "Custom Headers from Tool Parameters") has a client mirror tool
// parameters into Mcp-Param-{name} headers, a family Access-Control-Allow-Headers cannot name by
// prefix. A preflight's own Mcp-Param-* names are allowed instead: each a valid header name with a
// non-empty suffix, at most maxParamHeaderName bytes, and at most maxParamHeaders distinct names;
// any other requested name is left out, so the browser refuses it as before.
const (
	maxParamHeaders    = 32
	maxParamHeaderName = 128
)

// paramHeaderPrefix is config.MCPParamPrefix in lower case, as a preflight's names are compared.
var paramHeaderPrefix = strings.ToLower(config.MCPParamPrefix)

// paramHeaders are the Mcp-Param-* names a preflight's headers h request
// (Access-Control-Request-Headers), as allowHeaders' extension: ", " and the names, or "".
func paramHeaders(h http.Header) string {
	var names []string
	seen := map[string]bool{}
lines:
	for _, v := range h.Values("Access-Control-Request-Headers") {
		for n := range strings.SplitSeq(v, ",") {
			if len(names) == maxParamHeaders {
				break lines
			}
			n = strings.TrimSpace(n)
			lower := strings.ToLower(n)
			if len(n) > maxParamHeaderName || !strings.HasPrefix(lower, paramHeaderPrefix) ||
				len(n) == len(paramHeaderPrefix) || !httpguts.ValidHeaderFieldName(n) || seen[lower] {
				continue
			}
			seen[lower] = true
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return ", " + strings.Join(names, ", ")
}

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
			h.Set("Access-Control-Allow-Headers", allowHeaders+paramHeaders(r.Header))
			h.Add("Vary", "Access-Control-Request-Headers") // the allowed headers depend on it
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
