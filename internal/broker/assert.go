package broker

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/byward-dev/byward/internal/idp"
)

// Asserted selects the optional identity claims sealed into access tokens and asserted to the
// upstream (ADR-0016 §1). The access token carries them, so an MCP request needs no store read
// (ADR-0014 §2); they are as fresh as the token, at most one access-token lifetime old, as the
// access gate is.
type Asserted struct {
	Roles, Groups, Email, Name bool
}

// assertedClaims are the claims kept with a grant's IdP tokens, sealed at rest, so that /token
// can seal them into the first access token; every refresh replaces them from the IdP.
type assertedClaims struct {
	Roles  []string `json:"rol,omitempty"`
	Groups []string `json:"grp,omitempty"`
	Email  string   `json:"eml,omitempty"`
	Name   string   `json:"nam,omitempty"`
}

// claimsOf picks the opted-in claims of a signed-in identity. Groups the IdP left out (Entra
// overage) are not asserted at all, rather than asserted incomplete.
func (a Asserted) claimsOf(id idp.Identity) assertedClaims {
	var c assertedClaims
	if a.Roles {
		c.Roles = slices.Clone(id.Roles)
	}
	if a.Groups && !id.GroupsUnavailable {
		c.Groups = slices.Clone(id.Groups)
	}
	if a.Email {
		c.Email = id.Email
	}
	if a.Name {
		c.Name = id.Name
	}
	return c
}

// grantSecrets is what a grant's sealed IdP-token blob holds. Version 1 added the asserted
// claims; a blob without a version is the IdP tokens alone, as sealed before.
type grantSecrets struct {
	Version int            `json:"v"`
	Tokens  idp.Tokens     `json:"t"`
	Claims  assertedClaims `json:"c"`
}

const grantSecretsVersion = 1

func marshalSecrets(t idp.Tokens, c assertedClaims) []byte {
	b, _ := json.Marshal(grantSecrets{Version: grantSecretsVersion, Tokens: t, Claims: c}) //nolint:gosec // G117: marshalled only to be sealed in the IdP-token box
	return b
}

var errSecrets = errors.New("broker: the grant's IdP-token blob is unreadable")

func unmarshalSecrets(plain []byte) (grantSecrets, error) {
	var s grantSecrets
	if err := json.Unmarshal(plain, &s); err != nil {
		return grantSecrets{}, errSecrets
	}
	switch s.Version {
	case grantSecretsVersion:
		return s, nil
	case 0: // sealed before the asserted claims existed: the IdP tokens alone
		var t idp.Tokens
		if err := json.Unmarshal(plain, &t); err != nil {
			return grantSecrets{}, errSecrets
		}
		return grantSecrets{Tokens: t}, nil
	}
	return grantSecrets{}, errSecrets
}
