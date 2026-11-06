package broker

import (
	"encoding/json"
	"errors"

	"github.com/byward-dev/byward/internal/idp"
)

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
