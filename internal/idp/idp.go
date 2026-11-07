// Package idp is the broker's view of the IdP: build the login URL, turn the callback into an
// Identity plus IdP tokens, and refresh (ADR-0011). Adapters live in sub-packages; the broker
// depends only on the interfaces here.
package idp

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"
)

// Login is what the broker generated for one sign-in; the adapter puts it in the login URL and
// checks it at the callback.
type Login struct {
	State        string
	Nonce        string
	CodeVerifier string
	// Hints passed through to the IdP when the adapter supports them (ADR-0012 §11).
	LoginHint  string
	DomainHint string
	// SelectAccount sends prompt=select_account.
	SelectAccount bool
	// Silent sends prompt=none: the IdP must not show any page, and answers login_required,
	// interaction_required, consent_required or account_selection_required when it would need to
	// (OIDC Core 1.0 §3.1.2.1, §3.1.2.6). It wins over SelectAccount.
	Silent bool
}

// Identity is the signed-in user as the access gate and the identity assertion see them.
type Identity struct {
	// Subject is the stable user key: `sub` by default, `tid:oid` for Entra.
	Subject string
	Issuer  string
	// Display claims; never used for authorization.
	Name  string
	Email string
	// EmailVerified is true only when the IdP vouches for Email (never for Entra, ADR-0012 §3).
	EmailVerified     bool
	PreferredUsername string
	Roles             []string
	Groups            []string
	// GroupsUnavailable means the IdP left groups out (Entra overage), so a rule that needs groups
	// must deny (ADR-0012 §8).
	GroupsUnavailable bool
	// Claims are the raw ID token claims, for access-gate rules.
	Claims map[string]any
}

// Tokens are IdP tokens. They never appear in logs: every formatting path is redacted.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// String redacts the tokens.
func (t Tokens) String() string {
	return fmt.Sprintf("idp.Tokens{IDToken:%s AccessToken:%s RefreshToken:%s Expiry:%s}",
		redacted(t.IDToken), redacted(t.AccessToken), redacted(t.RefreshToken), t.Expiry.Format(time.RFC3339))
}

// GoString redacts the tokens for %#v.
func (t Tokens) GoString() string { return t.String() }

// LogValue redacts the tokens for slog.
func (t Tokens) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id_token", redacted(t.IDToken)),
		slog.String("access_token", redacted(t.AccessToken)),
		slog.String("refresh_token", redacted(t.RefreshToken)),
		slog.Time("expiry", t.Expiry),
	)
}

func redacted(s string) string {
	if s == "" {
		return `""`
	}
	return "<redacted>"
}

// Authenticator signs users in at the IdP.
type Authenticator interface {
	// AuthCodeURL is the IdP login URL for l.
	AuthCodeURL(ctx context.Context, l Login) (string, error)
	// Callback handles the IdP's redirect to /callback/{idp}: an error response becomes an *Error,
	// a code is exchanged and the ID token validated against l.
	Callback(ctx context.Context, query url.Values, l Login) (Identity, Tokens, error)
}

// Readiness is for the readiness probe: nil once the IdP's discovery has succeeded (ADR-0011 §7).
// Until then the adapter's other calls fail as well.
type Readiness interface {
	Ready(ctx context.Context) error
}

// Refresher renews IdP tokens.
//   - Tokens.RefreshToken is empty when the IdP kept the old one; the caller keeps it.
//   - Tokens.Expiry is zero when the IdP sent no expires_in.
//   - Identity is nil when the IdP returned no new ID token. When it is not nil, the caller must
//     check that Subject and Issuer equal the grant's (OIDC Core §12.2) before re-running the
//     access gate.
type Refresher interface {
	Refresh(ctx context.Context, refreshToken string) (*Identity, Tokens, error)
}

type requestIDKey struct{}

// WithRequestID attaches the caller's request ID; adapters send it to the IdP where supported
// (Entra: client-request-id), so IdP logs correlate with ours.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request ID from ctx, if any.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
