// Package mcpsession binds legacy-era MCP sessions to the signed-in user (ADR-0004 §2, ADR-0007 §3,
// invariant 13). The upstream's `Mcp-Session-Id` never reaches the client: the proxy replaces it with
// a sealed value carrying the upstream session ID, the user and the upstream, so any replica can
// check it without state. A request presenting a session sealed for another user or upstream, or a
// value that does not open, gets 404, which the MCP transport makes clients answer with a new
// session (2025-11-25 Streamable HTTP, Session Management rules 3 and 4). Requests without the
// header pass through untouched; the upstream decides whether it needs one. Modern-era clients send
// none, so they are unaffected.
package mcpsession

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/token"
)

// Header is the MCP session header (MCP 2025-11-25 transports, Session Management).
const Header = "Mcp-Session-Id"

// Prefix marks a sealed session ID, like the proxy's token prefixes.
const Prefix = "byw_ms_"

// Config is what Bind needs.
type Config struct {
	// Box seals the binding; give it a purpose of its own ("mcp-session").
	Box *token.Box
	// Upstream identifies the upstream the sessions belong to, so a session ID cannot be replayed
	// against another upstream.
	Upstream string
	// User returns the signed-in user of an authenticated request (the access token's subject).
	User     func(*http.Request) (string, bool)
	Lifetime time.Duration
	Now      func() time.Time
	Audit    *audit.Log
	Log      *slog.Logger
}

// binding is the sealed content. Short names keep the header small.
type binding struct {
	Session  string `json:"s"`
	User     string `json:"u"`
	Upstream string `json:"x"`
}

// Rejection reasons on the audit stream; the client only ever sees 404.
const (
	reasonInvalid       = "invalid or expired session ID"
	reasonOtherUser     = "session of another user"
	reasonOtherUpstream = "session of another upstream"
)

// Bind wraps next, the upstream, so session IDs are sealed toward the client and checked and
// unsealed toward the upstream.
func Bind(c Config, next http.Handler) http.Handler {
	if c.Now == nil {
		c.Now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := c.User(r)
		if !ok {
			// Only authenticated requests reach the upstream; without a user nothing can be bound.
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if ids := r.Header.Values(Header); len(ids) > 0 {
			if len(ids) > 1 {
				http.Error(w, "send one "+Header, http.StatusBadRequest)
				return
			}
			session, reason := c.open(ids[0], user)
			if reason != "" {
				c.Audit.Record(r, audit.Event{Name: audit.SessionRejected, Outcome: audit.Failure, Reason: reason, UserKey: user})
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			r = r.Clone(r.Context())
			r.Header.Set(Header, session)
		}
		next.ServeHTTP(&sealer{ResponseWriter: w, c: c, r: r, user: user}, r)
	})
}

func (c Config) open(id, user string) (session, reason string) {
	body, ok := strings.CutPrefix(id, Prefix)
	if !ok {
		return "", reasonInvalid
	}
	plain, err := c.Box.Open(body)
	if err != nil {
		return "", reasonInvalid
	}
	var b binding
	if json.Unmarshal(plain, &b) != nil || b.Session == "" {
		return "", reasonInvalid
	}
	switch {
	case b.User != user:
		return "", reasonOtherUser
	case b.Upstream != c.Upstream:
		return "", reasonOtherUpstream
	}
	return b.Session, ""
}

// sealer replaces the upstream's session ID in the response headers before they are written.
type sealer struct {
	http.ResponseWriter
	c       Config
	r       *http.Request
	user    string
	written bool
	sealed  string // the value seal last wrote: net/http keeps headers set before a 1xx, so the
	// final response can carry it again and must not be sealed twice
}

func (s *sealer) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		// Informational responses (100 Continue, 103 Early Hints) come before the final one, each
		// with its own headers: seal those too, and keep the final response's sealing to come.
		s.seal()
		s.ResponseWriter.WriteHeader(code)
		return
	}
	if !s.written {
		s.written = true
		s.seal()
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *sealer) Write(p []byte) (int, error) {
	if !s.written {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach Flush and deadlines on the real writer (streams).
func (s *sealer) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *sealer) seal() {
	h := s.Header()
	ids := h.Values(Header)
	if len(ids) == 0 || (len(ids) == 1 && ids[0] == s.sealed) {
		return
	}
	h.Del(Header)
	plain, _ := json.Marshal(binding{Session: ids[0], User: s.user, Upstream: s.c.Upstream})
	sealed, err := s.c.Box.Seal(plain, s.c.Now().Add(s.c.Lifetime))
	if err != nil {
		// Never pass the unbound ID on; without one the client cannot use the session.
		s.c.Log.ErrorContext(s.r.Context(), "sealing the MCP session ID failed", "request_id", logging.RequestID(s.r.Context()), "error", err)
		return
	}
	s.sealed = Prefix + sealed
	h.Set(Header, s.sealed)
}
