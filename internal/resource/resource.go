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

	"github.com/corker/mcp-authproxy/internal/audit"
)

// WellKnownPath is the RFC 9728 well-known path prefix.
const WellKnownPath = "/.well-known/oauth-protected-resource"

// Identity is who a valid proxy token belongs to.
type Identity struct {
	Subject string
}

// Validation errors. Only these two are distinguished to clients; every other failure,
// cryptographic or not, looks like ErrInvalid.
var (
	ErrExpired = errors.New("expired")
	ErrInvalid = errors.New("invalid")
)

// Validator checks a proxy token.
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

// identityFrom returns the identity Guard attached to the request context.
func identityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

const (
	descExpired = "The access token expired"
	descInvalid = "The access token is invalid"
)

// Guard admits requests carrying a valid proxy token in `Authorization: Bearer`. Tokens in the
// query string are ignored (the relay removes `access_token` before the upstream sees it); a token sent
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
			if errors.Is(err, ErrExpired) {
				desc, reason = descExpired, "expired"
			}
			rec.RecordUnauthenticated(r, audit.Event{Name: audit.AccessTokenRejected, Outcome: audit.Failure, Reason: reason})
			writeError(w, http.StatusUnauthorized, challenge, "invalid_token", desc)
			return
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
