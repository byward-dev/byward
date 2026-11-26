// Package origin checks the `Host` of every request and the `Origin` on the MCP endpoint before
// authentication (ADR-0018 §1–2): a wrong Host gets 421, a disallowed Origin 403.
package origin

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/host"
)

// Hosts allows only the given hosts (host[:port], compared as host.Canonical writes them:
// case-insensitively, an IP address in any spelling as browsers serialize it). One default port,
// :443 or :80, is ignored, once: a proxy behind a TLS-terminating load balancer may send the host
// with :80 (nginx's $host:$server_port), and a default port on the right host names no other site.
// Mismatches get 421 Misdirected Request and an audit event, rate-limited per source because the
// sender is not authenticated.
func Hosts(rec *audit.Log, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, h := range allowed {
		set[host.MatchKey(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !set[host.MatchKey(r.Host)] {
			rec.RecordUnauthenticated(r, audit.Event{Name: audit.HostRejected, Outcome: audit.Failure, Host: r.Host})
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// InternalHosts guards the internal listener (ADR-0018 §2, §10). Kubelet probes and Prometheus
// address a pod by its IP, which changes, so any IP literal passes, as do `localhost` and the
// operator's allowed hosts, on any port of up to 5 digits (the listener's port is the operator's
// choice). A Host header in no shape host.CutHostname takes, or naming no IP address and no allowed
// host, gets 421. A DNS rebinding attack always arrives with the attacker's own host name, and gets 421.
func InternalHosts(rec *audit.Log, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{"localhost": true}
	for _, h := range allowed {
		set[host.Hostname(h)] = true // config stores IP addresses canonical; any IP literal passes anyway
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 127.1 is an IP literal too; a Host that names no host, or a port that is not up to 5 digits, is refused.
		name, ok := host.CutHostname(host.Canonical(r.Host))
		if _, err := netip.ParseAddr(name); !ok || err != nil && !set[name] {
			rec.RecordUnauthenticated(r, audit.Event{Name: audit.HostRejected, Outcome: audit.Failure, Host: r.Host})
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// Origins enforces an allowlist of `Origin` values (scheme://host[:port]), compared in the form
// browsers serialize them (originKey, ADR-0032 A3): https://127.1, https://[0:0::1],
// https://APP.example and https://app.example:443 match the entry https://127.0.0.1, https://[::1] or
// https://app.example. That widens nothing for an attacker: this check defends against a browser,
// which only ever sends the serialized form, so folding a spelling lets no browser through that was
// not already allowed; and a non-browser client can send any header it likes anyway. A missing Origin
// passes (non-browser MCP clients send none); multiple Origin headers, `null`, a value that is no bare
// origin (a path, a trailing slash, user info, a query or a fragment) or an unlisted one get 403. A
// listed origin gets CORS headers, echoing the Origin exactly as sent, and its preflight is answered
// with 204.
func Origins(rec *audit.Log, allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, o := range allowed {
		if k := originKey(o); k != "" {
			set[k] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.Header.Values("Origin")
		if len(vals) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if len(vals) > 1 || !set[originKey(vals[0])] {
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

// originKey is o as Origins compares it: host.Origin, the folding ADR-0032 A3 names (case, an IP
// address's spelling, the scheme's own default port) and nothing a browser never sends (a port with
// leading zeros, an empty port, a full-width or Unicode name); "" when o is no bare origin
// (scheme://host[:port] and nothing else), which matches nothing.
func originKey(o string) string {
	// The only check for a query or a fragment: originKey reads neither, and url.Parse leaves no trace
	// of an empty one.
	if strings.ContainsAny(o, "?#") {
		return ""
	}
	u, err := url.Parse(o)
	if err != nil || u.Opaque != "" || u.User != nil || u.Path != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return host.Origin(u.Scheme, u.Host)
}
