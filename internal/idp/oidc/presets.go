package oidc

import (
	"errors"
	"net/url"
	"strings"
)

// Preset is a named set of defaults for the generic adapter (ADR-0011 §2). Presets are data; a
// change to one is a breaking change.
type Preset struct {
	Name string
	// Scopes requested besides openid.
	Scopes []string
	// AuthParams are added to the authorization URL.
	AuthParams url.Values
	// AlsoAcceptIssuer returns an extra `iss` value that identifies the same issuer, or "".
	AlsoAcceptIssuer func(issuer string) string
	// EmailVerifiedAsString accepts "true"/"false" for email_verified.
	EmailVerifiedAsString bool
	// CheckIssuer rejects issuers this IdP does not mean for third-party validation.
	CheckIssuer func(issuer string) error
}

// Presets by name; "" is plain OIDC.
var Presets = map[string]Preset{
	"": {
		Scopes: []string{"profile", "email", "offline_access"},
	},
	// Google: two `iss` forms and string email_verified (ADR-0011); refresh tokens come from
	// access_type=offline, not an offline_access scope (developers.google.com, OAuth 2.0 for web
	// server apps, 2026-11-06).
	"google": {
		Name:       "google",
		Scopes:     []string{"profile", "email"},
		AuthParams: url.Values{"access_type": {"offline"}},
		AlsoAcceptIssuer: func(iss string) string {
			if iss == "https://accounts.google.com" {
				return "accounts.google.com"
			}
			return ""
		},
		EmailVerifiedAsString: true,
	},
	// Okta: only custom authorization servers (https://{domain}/oauth2/{id}) issue tokens meant for
	// our validation (ADR-0011); refresh needs offline_access (developer.okta.com, 2026-11-06).
	"okta": {
		Name:   "okta",
		Scopes: []string{"profile", "email", "offline_access"},
		CheckIssuer: func(iss string) error {
			if !strings.Contains(iss, "/oauth2/") {
				return errors.New("okta: use a custom authorization server issuer (https://{domain}/oauth2/{id}), not the org authorization server")
			}
			return nil
		},
	},
	// Auth0: the issuer ends in a slash (ADR-0011); refresh needs offline_access (auth0.com docs,
	// 2026-11-06).
	"auth0": {
		Name:   "auth0",
		Scopes: []string{"profile", "email", "offline_access"},
		CheckIssuer: func(iss string) error {
			if !strings.HasSuffix(iss, "/") {
				return errors.New("auth0: the issuer ends with a slash, e.g. https://{tenant}.auth0.com/")
			}
			return nil
		},
	},
	// Keycloak: the issuer is {base}/realms/{realm} (ADR-0011).
	"keycloak": {
		Name:   "keycloak",
		Scopes: []string{"profile", "email"},
		CheckIssuer: func(iss string) error {
			if !strings.Contains(iss, "/realms/") {
				return errors.New("keycloak: the issuer is {base}/realms/{realm}")
			}
			return nil
		},
	},
}
