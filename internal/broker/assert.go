package broker

import (
	"slices"

	"github.com/byward-dev/byward/internal/idp"
)

// Asserted selects the optional identity claims sealed into access tokens and asserted to the
// upstream (ADR-0016 §1). The access token carries them, so an MCP request needs no store read
// (ADR-0014 §2); they are as fresh as the token, at most one access-token lifetime old, as the
// access gate is.
type Asserted struct {
	Roles, Groups, Email, Name bool
	// UnverifiedEmail also asserts an email the IdP does not vouch for (every Entra email); without
	// it only a verified email is asserted.
	UnverifiedEmail bool
}

// assertedClaims are the claims kept with a grant's IdP tokens, sealed at rest, so that /token
// can seal them into the first access token; every refresh replaces them from the IdP.
type assertedClaims struct {
	Roles  []string `json:"rol,omitempty"`
	Groups []string `json:"grp,omitempty"`
	Email  string   `json:"eml,omitempty"`
	// EmailVerified: the IdP vouches for Email.
	EmailVerified bool   `json:"emv,omitempty"`
	Name          string `json:"nam,omitempty"`
}

// claimsOf picks the opted-in claims of a signed-in identity. Groups the IdP left out (Entra
// overage) are not asserted at all, rather than asserted incomplete. It is the one place that
// decides whether an email is asserted, for the assertion and every other copy of it: only one the
// IdP verified, unless the operator opted in to unverified ones.
func (a Asserted) claimsOf(id idp.Identity) assertedClaims {
	var c assertedClaims
	if a.Roles {
		c.Roles = slices.Clone(id.Roles)
	}
	if a.Groups && !id.GroupsUnavailable {
		c.Groups = slices.Clone(id.Groups)
	}
	if a.Email && (id.EmailVerified || a.UnverifiedEmail) {
		c.Email, c.EmailVerified = id.Email, id.EmailVerified && id.Email != ""
	}
	if a.Name {
		c.Name = id.Name
	}
	return c
}
