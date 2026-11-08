package broker

import (
	"context"
	"errors"
	"time"
)

// ErrNoIdPAccessToken: the grant holds no IdP access token to present On-Behalf-Of.
var ErrNoIdPAccessToken = errors.New("broker: the grant holds no IdP access token")

// IdPAccessToken returns the grant's stored IdP access token (Entra's access_as_user token, the
// On-Behalf-Of assertion, ADR-0012 §3) and until when it may be used: its own expiry or the
// grant's, whichever comes first. The token is sealed in the store; only this broker knows the
// format.
func (b *Broker) IdPAccessToken(ctx context.Context, grantID string) (string, time.Time, error) {
	g, err := b.cfg.Store.Grant(ctx, grantID)
	if err != nil {
		return "", time.Time{}, err
	}
	s, err := b.openSecrets(g.IdPTokens)
	if err != nil {
		return "", time.Time{}, err
	}
	if s.Tokens.AccessToken == "" {
		return "", time.Time{}, ErrNoIdPAccessToken
	}
	// The grant may end first: Store.Grant does not check its ExpiresAt, and an asker without a
	// request (a stdio process's token socket) has no access token capped at it.
	exp := s.Tokens.Expiry
	if !g.ExpiresAt.IsZero() && (exp.IsZero() || g.ExpiresAt.Before(exp)) {
		exp = g.ExpiresAt
	}
	return s.Tokens.AccessToken, exp, nil
}
