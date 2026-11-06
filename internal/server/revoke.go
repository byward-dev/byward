package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/store"
)

// ErrNotAUserKey is RevokeUser's answer to a key that is not an IdP user key.
var ErrNotAUserKey = errors.New("not a user key: want tid:oid, the tenant and object IDs of the Entra user")

// Operator revocation reasons on the audit stream (ADR-0006 §9).
const (
	reasonRevokeUser = "operator revoke-user"
	reasonRevokeAll  = "operator revoke-all"
)

// RevokeUser is the operator's revoke-user (ADR-0006 §9, ADR-0010 §11): it deletes the user's grants
// and records a cut-off, so every proxy using the same store refuses the user's access tokens at
// its next deny-list sync and their refresh tokens at once. It runs beside a running proxy (SQLite
// serializes the writers). It returns the canonical user key it revoked.
func RevokeUser(ctx context.Context, cfg *config.Config, log *slog.Logger, key string) (string, error) {
	user, ok := entra.UserKey(key)
	if !ok {
		return "", ErrNotAUserKey
	}
	return user, revoke(ctx, cfg, log, audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: reasonRevokeUser, UserKey: user},
		func(st store.Grants, now time.Time) error { return st.RevokeSubject(ctx, user, now, now) })
}

// RevokeAll is the operator's revoke-all, for incident response: the same as RevokeUser for every
// user at once. Everyone signs in again.
func RevokeAll(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return revoke(ctx, cfg, log, audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: reasonRevokeAll},
		func(st store.Grants, now time.Time) error { return st.RevokeAll(ctx, now, now) })
}

// revoke opens the configured store, runs do with the current time, and audits e once it is stored.
func revoke(ctx context.Context, cfg *config.Config, log *slog.Logger, e audit.Event, do func(store.Grants, time.Time) error) error {
	if cfg.NoAuth {
		return errors.New("revocation needs the broker's store; it is off with BYWARD_INSECURE_NO_AUTH")
	}
	rec := audit.New(log, nil, time.Now)
	st, err := openStore(cfg, log, rec)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := do(st, time.Now()); err != nil {
		return fmt.Errorf("revoking: %w", err)
	}
	rec.Record(nil, e)
	log.Info("revocation stored; proxies using this store refuse the tokens at their next deny-list sync, within seconds",
		"reason", e.Reason)
	return nil
}
