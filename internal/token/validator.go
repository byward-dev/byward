package token

import (
	"context"
	"errors"
	"time"

	"github.com/byward-dev/byward/internal/resource"
)

// Leeway is the clock skew allowed on `iat` and `exp` (ADR-0014 §2).
const Leeway = 30 * time.Second

// DenyList is the in-memory revocation list the broker keeps (ADR-0006 §3).
type DenyList interface {
	// Denied reports whether the grant is revoked or the subject's tokens issued at or before
	// issuedAt are cut off. An error, such as a list more than 30 s stale, rejects the token
	// (fail closed).
	Denied(grantID, subject string, issuedAt time.Time) (bool, error)
}

// Validator checks access tokens for the resource server (resource.Validator). It reads no store.
type Validator struct {
	sealer *Sealer
	deny   DenyList
	now    func() time.Time
}

// NewValidator returns a Validator; now defaults to time.Now.
func NewValidator(s *Sealer, deny DenyList, now func() time.Time) (*Validator, error) {
	if s == nil || deny == nil {
		return nil, errors.New("token: a validator needs a sealer and a deny list")
	}
	if now == nil {
		now = time.Now
	}
	return &Validator{sealer: s, deny: deny, now: now}, nil
}

var _ resource.Validator = (*Validator)(nil)

// Validate implements resource.Validator. Only an expired token is reported as
// resource.ErrExpired; every other failure, cryptographic or not, is resource.ErrInvalid.
func (v *Validator) Validate(_ context.Context, tok string) (resource.Identity, error) {
	c, err := v.sealer.Open(Access, tok)
	if err != nil {
		return resource.Identity{}, resource.ErrInvalid
	}
	now := v.now()
	if c.IssuedAt.After(now.Add(Leeway)) {
		return resource.Identity{}, resource.ErrInvalid
	}
	if now.After(c.ExpiresAt.Add(Leeway)) {
		return resource.Identity{}, resource.ErrExpired
	}
	denied, err := v.deny.Denied(c.GrantID, c.Subject, c.IssuedAt)
	if err != nil || denied {
		return resource.Identity{}, resource.ErrInvalid
	}
	return resource.Identity{Subject: c.Subject}, nil
}
