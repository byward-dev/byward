package config

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// OIDCPresets are the IdP values that select the generic OIDC adapter with a preset (ADR-0011 §2);
// "oidc" selects it without one.
var OIDCPresets = []string{"google", "okta", "auth0", "keycloak"}

// OIDCDefaultIssuers are the issuers of presets that have one, used when BYWARD_OIDC_ISSUER is
// unset.
var OIDCDefaultIssuers = map[string]string{"google": "https://accounts.google.com"}

// defaultIssuersHelp lists OIDCDefaultIssuers for the settings help.
func defaultIssuersHelp() string {
	var parts []string
	for _, p := range slices.Sorted(maps.Keys(OIDCDefaultIssuers)) {
		parts = append(parts, p+" defaults to "+OIDCDefaultIssuers[p])
	}
	return strings.Join(parts, ", ")
}

// idp reads the IdP: Entra, or the generic OIDC adapter. The two families' settings never mix: a
// setting of the other family refuses to start, naming it and BYWARD_IDP.
func (c *Config) idp(v *Values) []error {
	c.IdP = v.get("idp")
	oidc := c.IdP == "oidc" || slices.Contains(OIDCPresets, c.IdP)
	if c.IdP != "entra" && !oidc {
		return []error{errorf("BYWARD_IDP: want entra, oidc, %s, got %q", strings.Join(OIDCPresets, ", "), c.IdP)}
	}
	other := "oidc-" // the settings family that must stay unset
	if oidc {
		other = "entra-"
	}
	errs := c.mixedIdPSettings(v, other)
	if oidc {
		return append(errs, c.oidcIdP(v)...)
	}
	return append(errs, c.entraIdP(v)...)
}

// mixedIdPSettings refuses settings of the other IdP family (prefix other), named as the operator
// set them.
func (c *Config) mixedIdPSettings(v *Values, other string) []error {
	var mixed []string
	for _, n := range v.order {
		if val := v.byKey[n]; strings.HasPrefix(n, other) && val.Source != SourceDefault {
			name := val.Setting.Env()
			if val.From != "" {
				name = val.From // the env variable or flag the operator used, with its _FILE or -file suffix
			}
			mixed = append(mixed, name)
		}
	}
	if len(mixed) == 0 {
		return nil
	}
	return []error{errorf("%s cannot be used with BYWARD_IDP=%s: they configure the %s IdP; remove them, or set BYWARD_IDP to match",
		strings.Join(mixed, ", "), c.IdP, strings.TrimSuffix(other, "-"))}
}

// requiredForIdP is an error for each named setting left empty.
func (c *Config) requiredForIdP(v *Values, names ...string) []error {
	var errs []error
	for _, s := range names {
		if v.get(s) == "" {
			env := v.byKey[s].Setting.Env()
			if v.byKey[s].Setting.Secret {
				env += "_FILE"
			}
			errs = append(errs, errorf("%s is required with BYWARD_IDP=%s (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)", env, c.IdP))
		}
	}
	return errs
}

// entraIdP reads the Entra settings (ADR-0012).
func (c *Config) entraIdP(v *Values) []error {
	c.EntraTenant, c.EntraClientID, c.EntraClientSecret = v.get("entra-tenant"), v.get("entra-client-id"), v.get("entra-client-secret")
	c.EntraFederatedTokenFile, c.EntraClientCertificate = v.get("entra-federated-token-file"), v.get("entra-client-certificate")
	errs := c.requiredForIdP(v, "entra-tenant", "entra-client-id")
	secretEnv, tokenEnv := Setting{Name: "entra-client-secret"}.Env()+"_FILE", Setting{Name: "entra-federated-token-file"}.Env()
	certEnv := Setting{Name: "entra-client-certificate"}.Env() + "_FILE"
	var set []string // the Entra app's credentials given: exactly one (ADR-0012 §5)
	for env, v := range map[string]string{secretEnv: c.EntraClientSecret, tokenEnv: c.EntraFederatedTokenFile, certEnv: c.EntraClientCertificate} {
		if v != "" {
			set = append(set, env)
		}
	}
	slices.Sort(set)
	switch {
	case len(set) == 0:
		errs = append(errs, errorf("%s, %s or %s is required with BYWARD_IDP=%s (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)", secretEnv, certEnv, tokenEnv, c.IdP))
	case len(set) > 1:
		errs = append(errs, errorf("%s are set together: Entra gets one credential, so keep only one of them", strings.Join(set, " and ")))
	case c.EntraFederatedTokenFile != "":
		if !filepath.IsAbs(c.EntraFederatedTokenFile) {
			errs = append(errs, errorf("%s: want an absolute path, got %q", tokenEnv, c.EntraFederatedTokenFile))
		}
		if v.get("entra-client-secret-expires-at") != "" {
			errs = append(errs, errorf("%s has no effect with %s: a federated token has no secret to expire; remove it", Setting{Name: "entra-client-secret-expires-at"}.Env(), tokenEnv))
		}
	case c.EntraClientCertificate != "":
		if v.get("entra-client-secret-expires-at") != "" {
			errs = append(errs, errorf("%s has no effect with %s: byward reads the certificate's own end date; remove it", Setting{Name: "entra-client-secret-expires-at"}.Env(), certEnv))
		}
	}
	errs = append(errs, c.secretExpiry(v)...)
	if t := c.EntraTenant; t != "" && !isGUID(t) {
		errs = append(errs, errorf("BYWARD_ENTRA_TENANT: want the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000, got %q", t))
	}
	return errs
}

// oidcIdP reads the generic OIDC adapter's settings (ADR-0011 §2).
func (c *Config) oidcIdP(v *Values) []error {
	var errs []error
	c.OIDCIssuer, c.OIDCClientID = v.get("oidc-issuer"), v.get("oidc-client-id")
	c.OIDCClientSecret, c.OIDCClientKey, c.OIDCClientKeyID = v.get("oidc-client-secret"), v.get("oidc-client-key"), v.get("oidc-client-key-id")
	c.OIDCScopes, c.OIDCSubjectClaim, c.OIDCName = splitList(v.get("oidc-scopes")), v.get("oidc-subject-claim"), v.get("oidc-name")
	if c.OIDCIssuer == "" {
		c.OIDCIssuer = OIDCDefaultIssuers[c.IdP]
	}
	if c.OIDCIssuer == "" {
		errs = append(errs, c.requiredForIdP(v, "oidc-issuer")...)
	}
	errs = append(errs, c.requiredForIdP(v, "oidc-client-id")...)
	secret, key := Setting{Name: "oidc-client-secret"}.Env()+"_FILE", Setting{Name: "oidc-client-key"}.Env()+"_FILE"
	switch {
	case c.OIDCClientSecret == "" && c.OIDCClientKey == "":
		// A public client would let anyone who knows the client ID start the proxy's flow at the IdP.
		errs = append(errs, errorf("%s or %s is required with BYWARD_IDP=%s: the proxy is a confidential client", secret, key, c.IdP))
	case c.OIDCClientSecret != "" && c.OIDCClientKey != "":
		errs = append(errs, errorf("%s and %s are both set; give one of them", secret, key))
	}
	if c.OIDCClientKeyID != "" && c.OIDCClientKey == "" {
		errs = append(errs, errorf("BYWARD_OIDC_CLIENT_KEY_ID is set without %s", key))
	}
	if raw := v.get("oidc-scopes"); raw != "" && len(c.OIDCScopes) == 0 {
		errs = append(errs, errorf("BYWARD_OIDC_SCOPES is set but lists nothing; remove it or give at least one scope"))
	}
	for _, sc := range c.OIDCScopes {
		if strings.ContainsAny(sc, " \\\"") {
			errs = append(errs, errorf("BYWARD_OIDC_SCOPES: %q is not a scope", sc))
		}
	}
	if strings.TrimSpace(c.OIDCSubjectClaim) == "" {
		errs = append(errs, errorf("BYWARD_OIDC_SUBJECT_CLAIM: want a claim name, got %q", c.OIDCSubjectClaim))
	}
	errs = append(errs, checkText("oidc-name", c.OIDCName, 80)...)
	return errs
}

// secretExpiry parses the client secret's end date: a date (midnight UTC) or an RFC 3339 time,
// such as the endDateTime that `az ad app credential list` prints.
func (c *Config) secretExpiry(v *Values) []error {
	raw := v.get("entra-client-secret-expires-at")
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.DateOnly, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			c.EntraClientSecretExpiresAt = t.UTC()
			return nil
		}
	}
	return []error{errorf("%s: want a date such as 2027-11-06 or an RFC 3339 time, got %q", Setting{Name: "entra-client-secret-expires-at"}.Env(), raw)}
}

func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", r):
			return false
		}
	}
	return true
}
