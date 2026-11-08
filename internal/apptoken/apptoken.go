// Package apptoken admits app-only callers at the MCP endpoint (CONTEXT.md "App-only token",
// ADR-0022): a headless caller's IdP-issued token is verified by the IdP adapter, judged by the app
// gate on every request, and checked against revoke-user's cut-offs, without the broker.
package apptoken

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/gate"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/resource"
)

// Verifier checks an app-only token's signature and claims (entra.Provider).
type Verifier interface {
	VerifyApp(ctx context.Context, raw string) (idp.App, error)
}

// Gate judges an app-only caller (gate.AppGate); a refusal is a *gate.Denied.
type Gate interface {
	Allow(idp.App) error
}

// DenyList is revoke-user's cut-offs (denylist.List): an app has no grant, so only the subject
// and every-subject cut-offs apply.
type DenyList interface {
	Denied(grantID, subject string, issuedAt time.Time) (bool, error)
}

// Outcomes, for the counter and the audit reason.
const (
	Accepted        = "accepted"
	Expired         = "expired"
	Invalid         = "invalid"
	Delegated       = "delegated"
	KeysUnavailable = "keys_unavailable"
	Revoked         = "revoked"
	DenyListStale   = "deny_list_stale"
	// The gate's refusals are "denied_" and the rule: denied_role, denied_client, denied_tenant.
	deniedPrefix = "denied_"
)

// MaxTracked bounds the token IDs remembered for first-use audit records. While that many are
// tracked, each request with an untracked token is recorded, until tracked tokens expire: more
// records, never fewer.
const MaxTracked = 10_000

// Config is the validator's input.
type Config struct {
	Verifier Verifier
	Gate     Gate
	Deny     DenyList
	// IdP names the adapter in audit records ("entra").
	IdP string
	// Count is told every outcome (metrics.AppToken); nil counts nothing.
	Count func(outcome string)
	Now   func() time.Time
}

// Validator is the app-only path's resource.Validator.
type Validator struct {
	cfg Config

	mu       sync.Mutex
	seen     map[string]time.Time // token ID → expiry
	prunedAt time.Time            // the last sweep of a full seen, at most one a second
}

var _ resource.Validator = (*Validator)(nil)

// New returns the validator; Verifier, Gate and Deny are required.
func New(cfg Config) (*Validator, error) {
	if cfg.Verifier == nil || cfg.Gate == nil || cfg.Deny == nil {
		return nil, errors.New("apptoken: a verifier, a gate and a deny list are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Count == nil {
		cfg.Count = func(string) {}
	}
	return &Validator{cfg: cfg, seen: map[string]time.Time{}}, nil
}

// Validate implements resource.Validator. Refusals are *resource.Rejection with an
// app_token_rejected record: ErrExpired, ErrInvalid, or ErrForbidden when the gate refuses.
func (v *Validator) Validate(ctx context.Context, raw string) (resource.Identity, error) {
	app, err := v.cfg.Verifier.VerifyApp(ctx, raw)
	if err != nil {
		switch {
		case errors.Is(err, idp.ErrAppTokenExpired):
			return v.reject(resource.ErrExpired, Expired, nil)
		case errors.Is(err, idp.ErrNotAppOnly):
			return v.reject(resource.ErrInvalid, Delegated, nil)
		case errors.Is(err, idp.ErrKeysUnavailable):
			return v.reject(resource.ErrInvalid, KeysUnavailable, nil)
		}
		return v.reject(resource.ErrInvalid, Invalid, nil)
	}
	if err := v.cfg.Gate.Allow(app); err != nil {
		rule := "unknown"
		if d := (*gate.Denied)(nil); errors.As(err, &d) {
			rule = d.Rule
		}
		return v.reject(resource.ErrForbidden, deniedPrefix+rule, &app)
	}
	switch denied, err := v.cfg.Deny.Denied("", app.Key(), app.IssuedAt); {
	case err != nil:
		return v.reject(resource.ErrInvalid, DenyListStale, &app)
	case denied:
		return v.reject(resource.ErrInvalid, Revoked, &app)
	}
	v.cfg.Count(Accepted)
	id := resource.Identity{Subject: app.Key(), ClientID: app.ClientID, PrincipalType: resource.PrincipalClient, Roles: app.Roles}
	if v.firstUse(app) {
		id.Audit = &audit.Event{Name: audit.AppTokenAccepted, Outcome: audit.Success, UserKey: app.Key(), ClientID: app.ClientID, IdP: v.cfg.IdP}
	}
	return id, nil
}

// reject counts outcome and returns the refusal; app, once the token passed its own checks, names
// the caller in the record.
func (v *Validator) reject(err error, outcome string, app *idp.App) (resource.Identity, error) {
	v.cfg.Count(outcome)
	ev := audit.Event{Name: audit.AppTokenRejected, Outcome: audit.Failure, Reason: outcome, IdP: v.cfg.IdP}
	if app != nil {
		ev.UserKey, ev.ClientID = app.Key(), app.ClientID
	}
	return resource.Identity{}, &resource.Rejection{Err: err, Event: ev}
}

// firstUse reports whether app's token has not been seen before, remembering it until it
// expires. A token without an ID, or one arriving while MaxTracked live tokens are remembered, is
// always a first use.
func (v *Validator) firstUse(app idp.App) bool {
	if app.TokenID == "" {
		return true
	}
	now := v.cfg.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if exp, ok := v.seen[app.TokenID]; ok && now.Before(exp.Add(idp.Leeway)) {
		return false
	}
	if len(v.seen) >= MaxTracked {
		if now.Sub(v.prunedAt) < time.Second {
			return true
		}
		v.prunedAt = now
		for id, exp := range v.seen {
			if !now.Before(exp.Add(idp.Leeway)) {
				delete(v.seen, id)
			}
		}
		if len(v.seen) >= MaxTracked {
			return true
		}
	}
	v.seen[app.TokenID] = app.Expiry
	return true
}
