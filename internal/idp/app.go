package idp

import (
	"errors"
	"time"
)

// App is an app-only caller (ADR-0022): a service principal that got its token with its own
// credential, with no user behind it.
type App struct {
	Tenant   string // tid
	ObjectID string // oid: the service principal
	// ClientID is azp: the caller's application (client) ID, never ours.
	ClientID string
	// Roles are the app roles assigned to the service principal on our app.
	Roles []string
	// TokenID is the IdP's identifier of this token (Entra's uti), for audit deduplication.
	TokenID  string
	IssuedAt time.Time
	Expiry   time.Time
}

// Key is the app's principal key: tid:oid, shaped like an Entra user key.
func (a App) Key() string { return a.Tenant + ":" + a.ObjectID }

// App-only token refusals that the caller reports apart from the rest, together with
// ErrKeysUnavailable (the IdP's keys could not be fetched); every other refusal is just invalid.
var (
	ErrAppTokenExpired = errors.New("idp: app-only token expired")
	// ErrNotAppOnly is a validly signed delegated token (a user's), which the app-only path never
	// accepts (ADR-0022 §3).
	ErrNotAppOnly = errors.New("idp: the token is delegated, not app-only")
)
