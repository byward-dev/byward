// Package resource is the proxy's protected-resource role toward MCP clients: it serves
// protected resource metadata (RFC 9728) and guards the MCP endpoint with proxy tokens taken
// from the `Authorization` header only (ADR-0013, ADR-0014).
package resource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/byward-dev/byward/internal/audit"
)

// WellKnownPath is the RFC 9728 well-known path prefix.
const WellKnownPath = "/.well-known/oauth-protected-resource"

// Identity is who a valid proxy token belongs to, and the claims asserted about them to the
// upstream (ADR-0016 §1). Only Subject is set without authentication.
type Identity struct {
	Subject  string
	ClientID string
	// PrincipalType is PrincipalUser, or PrincipalClient for an app-only caller (ADR-0022 §5).
	PrincipalType string
	// GrantID is the grant the token was issued for; it leads to the user's stored IdP tokens
	// (On-Behalf-Of, ADR-0017). Never sent to the upstream.
	GrantID string
	// The opted-in identity claims, as sealed at the token's issue; an app-only caller's roles.
	Roles, Groups []string
	Email, Name   string
	// EmailVerified: the IdP vouches for Email; false for an email asserted only because the
	// operator opted in to unverified ones.
	EmailVerified bool
	// Audit, when set, is a record Guard writes on admitting the request: an app-only token's
	// first use (ADR-0022 §7). It holds no credential.
	Audit *audit.Event
}

// Principal types (ADR-0016 §1, ADR-0022 §5).
const (
	PrincipalUser   = "user"
	PrincipalClient = "client"
)

// Validation errors. Only expired and invalid are distinguished to clients; every other failure,
// cryptographic or not, looks like ErrInvalid. ErrForbidden is a valid app-only token whose caller
// the app gate refuses (403, ADR-0014 §3 amendment).
var (
	ErrExpired   = errors.New("expired")
	ErrInvalid   = errors.New("invalid")
	ErrForbidden = errors.New("forbidden")
)

// Rejection is a refusal that names its own audit record; Err is ErrExpired, ErrInvalid or
// ErrForbidden. Without one, Guard records access_token_rejected.
type Rejection struct {
	Err   error
	Event audit.Event
}

func (r *Rejection) Error() string { return r.Err.Error() + ": " + r.Event.Reason }

func (r *Rejection) Unwrap() error { return r.Err }

// Dispatch chooses the validator by the token's format, never by fallback (ADR-0022 §2): a token
// with the proxy-token prefix goes to sealed alone; a three-part JWT goes to app alone, and only
// when app is non-nil (app-only tokens on); anything else is invalid without either seeing it.
func Dispatch(prefix string, sealed, app Validator) Validator {
	return dispatch{prefix: prefix, sealed: sealed, app: app}
}

type dispatch struct {
	prefix      string
	sealed, app Validator
}

func (d dispatch) Validate(ctx context.Context, tok string) (Identity, error) {
	switch {
	case strings.HasPrefix(tok, d.prefix):
		return d.sealed.Validate(ctx, tok)
	case d.app != nil && isJWT(tok):
		return d.app.Validate(ctx, tok)
	}
	return Identity{}, ErrInvalid
}

// isJWT is the compact JWS shape: three non-empty base64url segments.
func isJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsFunc(p, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
		}) {
			return false
		}
	}
	return true
}

// Validator checks a bearer token: a proxy token, or an app-only token (ADR-0022). An error wraps
// ErrExpired, ErrInvalid or ErrForbidden, optionally as a *Rejection naming its audit record. A
// returned Identity always sets PrincipalType (PrincipalUser or PrincipalClient): the assertion
// minter refuses one without it, and MCP sessions and stdio processes are keyed by it.
type Validator interface {
	Validate(ctx context.Context, token string) (Identity, error)
}

// NoTokens rejects every token; it is the validator until the broker issues proxy tokens.
type NoTokens struct{}

// Validate implements Validator.
func (NoTokens) Validate(context.Context, string) (Identity, error) { return Identity{}, ErrInvalid }

// Metadata describes this protected resource.
type Metadata struct {
	Resource      *url.URL // the public MCP URL, exactly as users enter it
	Issuer        string   // the broker's issuer
	Scope         string
	Name          string
	Documentation string
}

// PathInsertedURL is the metadata URL clients try first: the well-known prefix inserted before
// the resource path.
func (m Metadata) PathInsertedURL() string {
	return m.Resource.Scheme + "://" + m.Resource.Host + WellKnownPath + m.Resource.Path
}

// Paths are the request paths that serve the metadata document.
func (m Metadata) Paths() []string { return []string{WellKnownPath + m.Resource.Path, WellKnownPath} }

type document struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// MetadataHandler serves the same document at both well-known paths, with CORS for browser-based
// clients and `Cache-Control: max-age=3600` (RFC 9728 §7.10).
func MetadataHandler(m Metadata) http.Handler {
	body, err := json.Marshal(document{
		Resource:               m.Resource.String(),
		AuthorizationServers:   []string{m.Issuer},
		ScopesSupported:        []string{m.Scope},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           m.Name,
		ResourceDocumentation:  m.Documentation,
	})
	if err != nil {
		panic(err) // static strings only; cannot fail
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			_, _ = w.Write(body)
		default:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// cors follows ADR-0013 §6: echo the Origin, no credentials.
func cors(w http.ResponseWriter, r *http.Request) {
	o := r.Header.Get("Origin")
	if o == "" {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", o)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Retry-After")
	h.Set("Access-Control-Max-Age", "3600")
}

type identityKey struct{}

// IdentityFrom returns the identity Guard attached to the request context.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

const (
	descExpired   = "The access token expired"
	descInvalid   = "The access token is invalid"
	descForbidden = "The caller lacks an app role or other access this resource requires"
)

// Guard admits requests carrying a valid token in `Authorization: Bearer`: a proxy token, or an
// app-only token while they are on (v chooses, ADR-0022); an app the app gate refuses gets 403
// insufficient_scope, every other refusal 401. Tokens in the query string are ignored (the relay removes `access_token` before the upstream sees it); a token sent
// both ways gets 400.
func Guard(m Metadata, v Validator, rec *audit.Log, next http.Handler) http.Handler {
	challenge := `Bearer resource_metadata="` + m.PathInsertedURL() + `", scope="` + m.Scope + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		_, inQuery := q["access_token"]
		auth := r.Header.Values("Authorization")
		if len(auth) > 1 || (inQuery && len(auth) > 0) {
			writeError(w, http.StatusBadRequest, "", "invalid_request", "The token must be sent once, in the Authorization header")
			return
		}
		token, ok := bearer(auth)
		if !ok {
			w.Header().Set("WWW-Authenticate", challenge)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id, err := v.Validate(r.Context(), token)
		if err != nil {
			desc, reason := descInvalid, "invalid"
			switch {
			case errors.Is(err, ErrExpired):
				desc, reason = descExpired, "expired"
			case errors.Is(err, ErrForbidden):
				reason = "forbidden"
			}
			ev := audit.Event{Name: audit.AccessTokenRejected, Outcome: audit.Failure, Reason: reason}
			if rej := (*Rejection)(nil); errors.As(err, &rej) {
				ev = rej.Event
			}
			rec.RecordUnauthenticated(r, ev)
			if errors.Is(err, ErrForbidden) {
				// No scope or resource_metadata: there is nothing an interactive step-up could
				// add; only the operator's role assignment can (RFC 6750 §3.1).
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", error_description="`+descForbidden+`"`)
				writeError(w, http.StatusForbidden, "", "insufficient_scope", descForbidden)
				return
			}
			writeError(w, http.StatusUnauthorized, challenge, "invalid_token", desc)
			return
		}
		if id.Audit != nil {
			rec.Record(r, *id.Audit)
			id.Audit = nil
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

func bearer(auth []string) (string, bool) {
	if len(auth) != 1 {
		return "", false
	}
	scheme, tok, ok := strings.Cut(auth[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}

func writeError(w http.ResponseWriter, status int, challenge, code, desc string) {
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge+`, error="`+code+`", error_description="`+desc+`"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
