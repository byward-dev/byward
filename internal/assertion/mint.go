package assertion

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/byward-dev/byward/internal/resource"
)

// Lifetime is how long an assertion is valid (ADR-0016 §1); with a per-upstream `aud` it bounds
// replay, so the proxy keeps no replay cache (§9).
const Lifetime = 60 * time.Second

// JWKSCache is how long verifiers may cache the JWKS (ADR-0016 §3).
const JWKSCache = 300 * time.Second

// Type is the JWT `typ` of an assertion (RFC 9068 §2.1).
const Type = "at+jwt"

// Minter signs identity assertions for one upstream.
type Minter struct {
	signer   jose.Signer
	issuer   string
	audience string
	now      func() time.Time
}

// NewMinter signs with the keys' signing key. issuer is the broker's issuer; audience is the
// upstream's URL exactly as configured, which verifiers must expect.
func NewMinter(keys *Keys, issuer, audience string, now func() time.Time) (*Minter, error) {
	if keys == nil || issuer == "" || audience == "" {
		return nil, errors.New("assertion: a minter needs keys, an issuer and an audience")
	}
	if now == nil {
		now = time.Now
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: keys.signing.key},
		(&jose.SignerOptions{}).WithType(Type).WithHeader(jose.HeaderKey("kid"), keys.signing.id))
	if err != nil {
		return nil, err
	}
	return &Minter{signer: signer, issuer: issuer, audience: audience, now: now}, nil
}

// claims is the assertion's payload: the RFC 9068 claims, then ours (only ever added to).
type claims struct {
	Issuer   string           `json:"iss"`
	Audience string           `json:"aud"`
	Subject  string           `json:"sub"`
	ClientID string           `json:"client_id"`
	IssuedAt *jwt.NumericDate `json:"iat"`
	Expiry   *jwt.NumericDate `json:"exp"`
	ID       string           `json:"jti"`
	// PrincipalType is user, or client for an app-only caller (ADR-0016 §1, ADR-0022 §5).
	PrincipalType string   `json:"principal_type"`
	Roles         []string `json:"roles,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Email         string   `json:"email,omitempty"`
	// EmailVerified is set exactly when Email is: the upstream sees whether the IdP vouched for it.
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

var errNoIdentity = errors.New("assertion: no subject, client or principal type to assert")

// Mint signs an assertion for id. Claims id does not carry are left out, never sent empty.
func (m *Minter) Mint(id resource.Identity) (string, error) {
	// Never a default principal type: an app asserted as a user would be a confused deputy.
	if id.Subject == "" || id.ClientID == "" || (id.PrincipalType != resource.PrincipalUser && id.PrincipalType != resource.PrincipalClient) {
		return "", errNoIdentity
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	now := m.now().Truncate(time.Second)
	var verified *bool
	if id.Email != "" {
		verified = &id.EmailVerified
	}
	return jwt.Signed(m.signer).Claims(claims{
		Issuer: m.issuer, Audience: m.audience, Subject: id.Subject, ClientID: id.ClientID,
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(Lifetime)),
		ID: base64.RawURLEncoding.EncodeToString(jti[:]), PrincipalType: id.PrincipalType,
		Roles: id.Roles, Groups: id.Groups, Email: id.Email, EmailVerified: verified, Name: id.Name,
	}).Serialize()
}
