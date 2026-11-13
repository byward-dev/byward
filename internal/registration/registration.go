// Package registration is client registration (CONTEXT.md "Client registration"): looking up MCP
// clients, the redirect URI policy (ADR-0009) and client authentication at /token (ADR-0008 §5-6).
// Static clients come first (slice 1.2); CIMD and DCR add registries later (slices 2.1, 2.2).
package registration

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// ErrUnknownClient means the client ID is not registered (or expired); the broker answers exactly
// `invalid_client` (ADR-0008 §3).
var ErrUnknownClient = errors.New("registration: unknown client")

// AuthMethod is a token endpoint authentication method.
type AuthMethod string

// Methods (ADR-0008 §5): secrets only for static clients.
const (
	None              AuthMethod = "none"
	PrivateKeyJWT     AuthMethod = "private_key_jwt"
	ClientSecretBasic AuthMethod = "client_secret_basic"
	ClientSecretPost  AuthMethod = "client_secret_post"
)

// TrustLevel is how far the broker vouches for a client on the consent page (ADR-0008 §8).
type TrustLevel string

// Trust levels.
const (
	Verified    TrustLevel = "verified" // static clients, trusted CIMD hosts
	Domain      TrustLevel = "domain"
	NotVerified TrustLevel = "not-verified"
)

// Client is a registered MCP client. Credentials are not exported: use Authenticate.
type Client interface {
	ID() string
	Name() string
	Trust() TrustLevel
	// AuthMethods lists the methods the client may use at /token.
	AuthMethods() []AuthMethod
	// AllowsRefresh reports whether the client registered the refresh_token grant; without it the
	// broker issues no refresh tokens (draft-ietf-oauth-client-id-metadata-document-03 §6).
	AllowsRefresh() bool
	// RedirectAllowed applies ADR-0009 to a redirect URI sent at /authorize or /token. The error
	// says "registered X, sent Y" and is safe to show on the error page.
	RedirectAllowed(redirectURI string) error
	// Authenticate checks the client's credentials in a /token or /revoke request (constant-time
	// for secrets; private_key_jwt: aud = tokenEndpoint, short exp, jti replay check).
	Authenticate(ctx context.Context, form url.Values, header http.Header, tokenEndpoint string, now time.Time) error
}

// Registry finds clients by ID.
type Registry interface {
	// Client returns ErrUnknownClient for an unknown ID.
	Client(ctx context.Context, id string) (Client, error)
}

// JTICache remembers private_key_jwt assertion IDs until they expire (ADR-0008 §6). StoreJTICache
// keeps them in the store, so every replica sees them.
type JTICache interface {
	// Seen records jti and reports whether it was already recorded.
	Seen(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
}
