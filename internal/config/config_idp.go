package config

import (
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/host"
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
	var err error
	if c.IdP, err = parseWord(v.value("idp"), append([]string{"entra", "oidc"}, OIDCPresets...)...); err != nil {
		return []error{err}
	}
	oidc := c.IdP == "oidc" || slices.Contains(OIDCPresets, c.IdP)
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
			mixed = append(mixed, spelled(val))
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
		if v.empty(s) {
			env := v.byKey[s].Setting.Env()
			if v.byKey[s].Setting.Secret() {
				env += "_FILE"
			}
			errs = append(errs, errorf("%s is required with BYWARD_IDP=%s (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)", env, c.IdP))
		}
	}
	return errs
}

// entraIdP reads the Entra settings (ADR-0012).
func (c *Config) entraIdP(v *Values) []error {
	c.EntraClientSecret = parseText(v.value("entra-client-secret"))
	c.EntraFederatedTokenFile, c.EntraClientCertificate = parseText(v.value("entra-federated-token-file")), parseText(v.value("entra-client-certificate"))
	var errs []error
	var err error
	if c.EntraTenant, err = parseTenant(v.value("entra-tenant")); err != nil {
		errs = append(errs, err)
	}
	if c.EntraClientID, err = parseEntraClientID(v.value("entra-client-id")); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, c.requiredForIdP(v, "entra-tenant", "entra-client-id")...)
	secretEnv, tokenEnv := Setting{Name: "entra-client-secret"}.Env()+"_FILE", Setting{Name: "entra-federated-token-file"}.Env()
	certEnv := Setting{Name: "entra-client-certificate"}.Env() + "_FILE"
	hasSecret, hasCert := v.given("entra-client-secret"), v.given("entra-client-certificate")
	var set []string // the Entra app's credentials given: exactly one (ADR-0012 §5)
	for env, given := range map[string]bool{secretEnv: hasSecret, tokenEnv: c.EntraFederatedTokenFile != "", certEnv: hasCert} {
		if given {
			set = append(set, env)
		}
	}
	for _, name := range []string{"entra-client-secret", "entra-client-certificate"} {
		if err := v.emptySecretFile(name); err != nil {
			errs = append(errs, err)
		}
	}
	slices.Sort(set)
	switch {
	case len(set) == 0:
		errs = append(errs, errorf("%s, %s or %s is required with BYWARD_IDP=%s (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)", secretEnv, certEnv, tokenEnv, c.IdP))
	case len(set) > 1:
		errs = append(errs, errorf("%s are set together: Entra gets one credential, so keep only one of them", strings.Join(set, " and ")))
	case c.EntraFederatedTokenFile != "":
		if err := absolute("entra-federated-token-file", c.EntraFederatedTokenFile); err != nil {
			errs = append(errs, err)
		}
		if !v.empty("entra-client-secret-expires-at") {
			errs = append(errs, errorf("%s has no effect with %s: a federated token has no secret to expire; remove it", Setting{Name: "entra-client-secret-expires-at"}.Env(), tokenEnv))
		}
	case hasCert:
		if !v.empty("entra-client-secret-expires-at") {
			errs = append(errs, errorf("%s has no effect with %s: byward reads the certificate's own end date; remove it", Setting{Name: "entra-client-secret-expires-at"}.Env(), certEnv))
		}
	}
	if c.EntraClientSecretExpiresAt, err = parseSecretExpiry(v.value("entra-client-secret-expires-at")); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// parseTenant reads BYWARD_ENTRA_TENANT: the tenant ID, a GUID, or nothing (required elsewhere).
func parseTenant(val Value) (string, error) {
	raw := val.Given.raw()
	if raw != "" && !isGUID(raw) {
		return "", refusedForm(val.Setting, whole, raw, "the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, Overview, Tenant ID)", "it is not a GUID")
	}
	return raw, nil
}

// parseEntraClientID reads BYWARD_ENTRA_CLIENT_ID: empty (refused as missing by requiredForIdP) or
// the app registration's GUID, which the Entra adapter also requires. A value refused here is never
// shown: a client secret pasted in its place is the likely mistake.
func parseEntraClientID(val Value) (string, error) {
	raw := val.Given.raw()
	if raw != "" && !isGUID(raw) {
		return "", refusedForm(val.Setting, whole, raw, "the application (client) ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, App registrations, your app, Overview, Application (client) ID)", "it is not a GUID")
	}
	return raw, nil
}

// protocolClaims are ID token claims about the sign-in itself, never a user's roles or groups: the
// registered claims of RFC 7519 §4.1 and the ID token claims of OpenID Connect Core 1.0 (§2, §3),
// plus sid, the session ID an IdP adds for logout. amr is an array of strings, so it would
// otherwise be read as roles without an error.
var protocolClaims = []string{"iss", "sub", "aud", "azp", "exp", "iat", "nbf", "jti", "nonce", "auth_time", "acr", "amr", "sid", "at_hash", "c_hash"}

// oidcIdP reads the generic OIDC adapter's settings (ADR-0011 §2).
func (c *Config) oidcIdP(v *Values) []error {
	var errs []error
	issuer, issuerErr := parseIssuer(v.value("oidc-issuer"))
	if issuerErr != nil {
		errs = append(errs, issuerErr)
	}
	c.OIDCIssuer, c.OIDCClientID = issuer, parseText(v.value("oidc-client-id"))
	c.OIDCClientSecret, c.OIDCClientKey = parseText(v.value("oidc-client-secret")), parseText(v.value("oidc-client-key"))
	c.OIDCClientKeyID = parseText(v.value("oidc-client-key-id"))
	var scopeErrs []error
	c.OIDCScopes, scopeErrs = parseOIDCScopes(v.value("oidc-scopes"))
	errs = append(errs, scopeErrs...)
	var err error
	if c.OIDCSubjectClaim, err = parseClaimName(v.value("oidc-subject-claim"), "sub"); err != nil {
		errs = append(errs, err)
	}
	if c.OIDCRolesClaim, err = parseGateClaimName(v.value("oidc-roles-claim"), "https://example.com/roles"); err != nil {
		errs = append(errs, err)
	}
	if c.OIDCGroupsClaim, err = parseGateClaimName(v.value("oidc-groups-claim"), "https://example.com/groups"); err != nil {
		errs = append(errs, err)
	}
	if c.OIDCName, err = parseWording(v.value("oidc-name"), 80); err != nil {
		errs = append(errs, err)
	}
	if c.OIDCIssuer == "" {
		c.OIDCIssuer = OIDCDefaultIssuers[c.IdP]
	}
	if c.OIDCIssuer == "" {
		errs = append(errs, c.requiredForIdP(v, "oidc-issuer")...)
	}
	if u, err := url.Parse(c.OIDCIssuer); issuerErr == nil && c.Dev && err == nil && u.Scheme == "http" && host.LoopbackAsWritten(u.Hostname()) {
		// --dev lets the oidc adapter use an http issuer on a loopback host, and http endpoints on
		// loopback with it (AllowLoopbackHTTP); every relaxation is logged (security invariant 12, #355).
		c.OIDCLoopbackHTTP = true
		c.Relaxations = append(c.Relaxations, "http IdP issuer on loopback ("+v.display("oidc-issuer")+"): discovery over http, and the IdP's sign-in page, token endpoint and signing keys over http too where it lists them on loopback")
	}
	errs = append(errs, c.requiredForIdP(v, "oidc-client-id")...)
	secret, key := Setting{Name: "oidc-client-secret"}.Env()+"_FILE", Setting{Name: "oidc-client-key"}.Env()+"_FILE"
	hasSecret, hasKey := v.given("oidc-client-secret"), v.given("oidc-client-key")
	for _, name := range []string{"oidc-client-secret", "oidc-client-key"} {
		if err := v.emptySecretFile(name); err != nil {
			errs = append(errs, err)
		}
	}
	switch {
	case !hasSecret && !hasKey:
		// A public client would let anyone who knows the client ID start the proxy's flow at the IdP.
		errs = append(errs, errorf("%s or %s is required with BYWARD_IDP=%s: the proxy is a confidential client", secret, key, c.IdP))
	case hasSecret && hasKey:
		errs = append(errs, errorf("%s and %s are both set; give one of them", secret, key))
	}
	if c.OIDCClientKeyID != "" && !hasKey {
		errs = append(errs, errorf("BYWARD_OIDC_CLIENT_KEY_ID is set without %s", key))
	}
	if !v.empty("oidc-client-key-alg") && !hasKey {
		errs = append(errs, errorf("BYWARD_OIDC_CLIENT_KEY_ALG is set without %s", key))
	} else if c.OIDCClientKeyAlg, err = parseKeyAlg(v.value("oidc-client-key-alg")); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// parseKeyAlg reads BYWARD_OIDC_CLIENT_KEY_ALG: PS256, RS256 or ES256, or nothing.
func parseKeyAlg(val Value) (string, error) {
	raw := val.Given.raw()
	if raw != "" && !slices.Contains([]string{"PS256", "RS256", "ES256"}, raw) {
		return "", refusedForm(val.Setting, whole, raw, "PS256 or RS256 (an RSA key) or ES256 (an EC P-256 key)", "it is not one of them")
	}
	return raw, nil
}

// parseClaimName reads a claim name, matched exactly: a blank or padded one would never match.
func parseClaimName(val Value, example string) (string, error) {
	raw := val.Given.raw()
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", refusedForm(val.Setting, whole, raw, "a claim name such as "+example, "it is blank or has white space at an end")
	}
	return raw, nil
}

// parseGateClaimName reads the claim the gate reads roles or groups from: a claim name, and never one
// of the sign-in itself (protocolClaims), which is shown, since it is one of that fixed list.
func parseGateClaimName(val Value, example string) (string, error) {
	name, err := parseClaimName(val, example)
	if err == nil && slices.Contains(protocolClaims, name) {
		// aud holds our client ID, so a gate on it would admit every user of the IdP.
		return "", refusedMeaning(val.Setting, whole, name, "a claim name such as "+example,
			"it is a claim of the sign-in itself, not roles or groups; name the claim the IdP sends them in")
	}
	return name, err
}

// parseSecretExpiry reads the client secret's end date: a date (midnight UTC) or an RFC 3339 time,
// such as the endDateTime that `az ad app credential list` prints, or nothing.
func parseSecretExpiry(val Value) (time.Time, error) {
	raw := val.Given.raw()
	if raw == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.DateOnly, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, refusedForm(val.Setting, whole, raw, "a date such as 2027-11-06 or an RFC 3339 time", "it is neither")
}

// isGUID is idp.IsGUID; config keeps its own copy so it does not import idp (and go-jose).
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

// parseIssuer reads BYWARD_OIDC_ISSUER as given; empty means a preset's issuer or none. It refuses,
// before the startup log lists the settings, every issuer the oidc adapter would refuse for its form,
// and one with a user name or password, a query or a fragment, which an issuer never has (OpenID
// Connect Discovery 1.0 §3, RFC 8414 §2) and which the adapter accepts on an https issuer: no absolute
// http(s) URL with a host. A refused issuer is never shown (ADR-0031 §1), where the adapter's error
// would show its path. An http issuer off loopback, which the adapter always refuses, is refused here
// as the parser read it, by its scheme alone; whether http on loopback is allowed (only with --dev)
// stays the adapter's.
func parseIssuer(val Value) (string, error) {
	s, raw := val.Setting, val.Given.raw()
	if raw == "" {
		return "", nil
	}
	const want = "the issuer URL, exactly as the IdP's discovery document states it, such as https://idp.example.com/realms/mcp"
	u, reason := parseHTTPURL(raw)
	if reason == "" && strings.ContainsAny(raw, "?#") {
		reason = "it has a query or a fragment, which an issuer never has"
	}
	if reason != "" {
		return "", refusedForm(s, whole, raw, want, reason)
	}
	if u.Scheme == "http" && !host.LoopbackAsWritten(u.Hostname()) { // the adapter's own rule (oidc.checkURL)
		return "", refusedMeaning(s, whole, "http on a host that is not loopback", want, "give https; an issuer is http only on a loopback host, with --dev")
	}
	return raw, nil
}

// parseOIDCScopes reads BYWARD_OIDC_SCOPES: comma-separated scopes, none with a space, a backslash or
// a double quote. A refused scope is never shown (ADR-0031 §1).
func parseOIDCScopes(val Value) ([]string, []error) {
	s := val.Setting
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	var errs []error
	for i, sc := range list {
		if !isScopeToken(sc) {
			errs = append(errs, refusedForm(s, at(i), sc, "a scope such as openid or email", scopeCharsReason))
		}
	}
	return list, errs
}
