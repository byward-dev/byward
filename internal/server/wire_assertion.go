package server

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
)

// jwksPath serves the assertion keys (ADR-0016 §3).
const jwksPath = "/.well-known/jwks.json"

// assertionJWKSURI is the public JWKS the authorization-server metadata advertises, when there are
// assertion keys to verify (an HTTP upstream); "" otherwise.
func assertionJWKSURI(cfg *config.Config, parts *authParts) string {
	if parts.assertionKeys == nil {
		return ""
	}
	return strings.TrimSuffix(cfg.Issuer(), "/") + jwksPath
}

// ExportJWKS is `byward jwks`: the public keys of BYWARD_ASSERTION_KEYS_DIR as a JWKS, for an
// upstream that loads them from a file instead of fetching them (ADR-0016 §3). Run it again after
// every key rotation.
func ExportJWKS(cfg *config.Config) ([]byte, error) {
	keys, err := assertion.LoadKeys(cfg.AssertionKeysDir, secretCheck(cfg))
	if err != nil {
		return nil, fmt.Errorf("BYWARD_ASSERTION_KEYS_DIR: %s: %w (see docs/how-to/identity-assertion.md)", cfg.AssertionKeysDir, err)
	}
	return json.MarshalIndent(keys.JWKS(), "", "  ")
}

// assertedClaims maps BYWARD_ASSERTION_CLAIMS to the claims the broker seals into access tokens.
func assertedClaims(cfg *config.Config) broker.Asserted {
	var a broker.Asserted
	for _, c := range cfg.AssertionClaims {
		switch c {
		case "roles":
			a.Roles = true
		case "groups":
			a.Groups = true
		case "email":
			a.Email, a.UnverifiedEmail = true, cfg.AssertionUnverifiedEmail
		case "name":
			a.Name = true
		default: // config.AssertionClaimNames and this switch must list the same names
			panic("server: unhandled assertion claim " + c)
		}
	}
	return a
}

// emailWarnings say, at every start, which emails the identity assertion leaves out or carries
// unverified (ADR-0016, 2026-11-07 amendment).
func emailWarnings(cfg *config.Config, entra bool) []Warning {
	const setting = "BYWARD_ASSERTION_UNVERIFIED_EMAIL"
	switch email := slices.Contains(cfg.AssertionClaims, "email"); {
	case !email && cfg.AssertionUnverifiedEmail:
		return []Warning{{Message: setting + " has no effect", Setting: "BYWARD_ASSERTION_CLAIMS", Fix: "add email to it, or remove " + setting}}
	case email && cfg.AssertionUnverifiedEmail:
		return []Warning{{Message: "the identity assertion carries emails the IdP has not verified, marked email_verified false", Setting: setting,
			Fix: "the upstream must never authorize on email; use sub"}}
	case email && entra:
		return []Warning{{Message: "Entra never verifies an email, so the identity assertion carries none", Setting: setting,
			Fix: "set it to true to assert Entra's email anyway, marked email_verified false; never authorize on it"}}
	case email:
		return []Warning{{Message: "the identity assertion leaves out emails the IdP has not verified (email_verified)", Setting: setting,
			Fix: "set it to true to assert them anyway, marked email_verified false"}}
	}
	return nil
}

// wireAssertion is the identity assertion for an HTTP upstream (ADR-0016): its minter and the
// JWKS of its keys; nothing for a stdio upstream.
func wireAssertion(w *wiring, a *auth) error {
	k := w.parts.assertionKeys
	if k == nil {
		return nil
	}
	var err error
	if a.minter, err = assertion.NewMinter(k, w.cfg.Issuer(), w.cfg.UpstreamURL.String(), time.Now); err != nil {
		return err
	}
	a.jwks = k.JWKSHandler()
	w.log.Info("identity assertion", "reason", "signing with key "+k.SigningKeyID()+", keys "+strings.Join(k.KeyIDs(), " "),
		"setting", "BYWARD_ASSERTION_HEADER", "value", w.cfg.AssertionHeader)
	return nil
}
