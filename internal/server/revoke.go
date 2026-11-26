package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp/oidc"
	"github.com/byward-dev/byward/internal/store"
)

// ErrNeedsAuthentication is RevokeUser's, RevokeAll's and NewEpoch's answer without authentication,
// a configuration error: the broker's store is off then.
var ErrNeedsAuthentication = errors.New("the broker's store is off with BYWARD_INSECURE_NO_AUTH, so there is nothing to revoke and no store epoch to start")

// ErrNoStore is the operator commands' answer when the configured store is not there (L152): a
// mistyped setting, which the command refuses before creating or writing anything.
var ErrNoStore = store.ErrNoStore

// ErrNotAUserKey is RevokeUser's answer to a key that is not a user key of the configured IdP.
var ErrNotAUserKey = errors.New("not a user key: with Entra, tid:oid, the tenant and object IDs of the user; with an oidc IdP, the value of its subject claim (BYWARD_OIDC_SUBJECT_CLAIM, default sub; a sub is at most " +
	strconv.Itoa(oidc.MaxSubject) + " printable ASCII characters), as the audit records' user_key shows it")

// ConfigError is an operator command's answer to settings it cannot build from, such as an IdP
// credential file that holds no key: the error server.New gives for the same settings, which the
// command reports as a configuration error, as startup does (ADR-0020 §5).
type ConfigError struct{ Err error }

func (e ConfigError) Error() string { return e.Err.Error() }

// Operator revocation reasons on the audit stream (ADR-0006 §9).
const (
	reasonRevokeUser = "operator revoke-user"
	reasonRevokeAll  = "operator revoke-all"
)

// operatorRevocationEvent is the audit record of an operator revocation: the revoking command
// writes it to its own output, and each proxy writes the same record to its audit stream when its
// deny-list sync first finds the revocation (#337). It carries the reason and, for revoke-user, the
// user key; never a grant ID or a token.
// A revocation of any other kind is none: ok is false, so a new kind is never recorded under
// another's reason.
func operatorRevocationEvent(r store.Revocation) (e audit.Event, ok bool) {
	switch {
	case r.GrantID != "":
		return audit.Event{}, false
	case r.All:
		return audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: reasonRevokeAll}, true
	case r.Subject != "":
		return audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: reasonRevokeUser, UserKey: r.Subject}, true
	}
	return audit.Event{}, false
}

// RevokeUser is the operator's revoke-user (ADR-0006 §9, ADR-0010 §11): it deletes the user's grants
// and records a cut-off, so every proxy using the same store refuses the user's access tokens at
// its next deny-list sync and their refresh tokens at once. It runs beside a running proxy (the store
// serializes the writers). It returns the canonical user key it revoked and the store it revoked
// them in (storeName).
func RevokeUser(ctx context.Context, cfg *config.Config, log *slog.Logger, key string) (user, where string, err error) {
	if cfg.NoAuth { // before the IdP, which is not configured then
		return "", "", ErrNeedsAuthentication
	}
	ip, err := newIdentityProvider(cfg, nil) // settings only; nothing is fetched
	if err != nil {
		return "", "", ConfigError{err} // as server.New reports it at startup (L174)
	}
	user, ok := ip.userKey(key)
	if !ok {
		return "", "", ErrNotAUserKey
	}
	e, _ := operatorRevocationEvent(store.Revocation{Subject: user})
	where, err = revoke(ctx, cfg, log, e,
		func(st store.Grants, now time.Time) error { return st.RevokeSubject(ctx, user, now, now) })
	return user, where, err
}

// RevokeAll is the operator's revoke-all, for incident response: the same as RevokeUser for every
// user at once. Everyone signs in again. It returns the store it revoked them in (storeName).
func RevokeAll(ctx context.Context, cfg *config.Config, log *slog.Logger) (where string, err error) {
	if cfg.NoAuth {
		return "", ErrNeedsAuthentication
	}
	e, _ := operatorRevocationEvent(store.Revocation{All: true})
	return revoke(ctx, cfg, log, e,
		func(st store.Grants, now time.Time) error { return st.RevokeAll(ctx, now, now) })
}

// revoke opens the configured store, which must exist (openExistingStore), runs do with the current
// time, audits e once it is stored, and names the store.
func revoke(ctx context.Context, cfg *config.Config, log *slog.Logger, e audit.Event, do func(store.Grants, time.Time) error) (string, error) {
	rec := audit.New(log, nil, time.Now)
	st, err := openExistingStore(cfg, log, rec)
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	if err := do(st, time.Now()); err != nil {
		return "", fmt.Errorf("revoking: %w", err)
	}
	rec.Record(nil, e)
	log.Info("revocation stored; proxies using this store refuse the tokens at their next deny-list sync, within seconds",
		"reason", e.Reason)
	return storeName(cfg, st), nil
}
