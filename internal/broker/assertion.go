package broker

import (
	"context"
	"errors"
	"time"
)

// ErrNoIdPAccessToken: the grant holds no IdP access token to present On-Behalf-Of.
var ErrNoIdPAccessToken = errors.New("broker: the grant holds no IdP access token")

// IdPAccessToken returns the grant's stored IdP access token (Entra's access_as_user token, the
// On-Behalf-Of assertion, ADR-0012 §3) and its expiry. The token is sealed in the store; only this
// broker knows the format.
func (b *Broker) IdPAccessToken(ctx context.Context, grantID string) (string, time.Time, error) {
	g, err := b.cfg.Store.Grant(ctx, grantID)
	if err != nil {
		return "", time.Time{}, err
	}
	plain, err := b.cfg.IdPTokenBox.Open(string(g.IdPTokens))
	if err != nil {
		return "", time.Time{}, err
	}
	s, err := unmarshalSecrets(plain)
	if err != nil {
		return "", time.Time{}, err
	}
	if s.Tokens.AccessToken == "" {
		return "", time.Time{}, ErrNoIdPAccessToken
	}
	return s.Tokens.AccessToken, s.Tokens.Expiry, nil
}
