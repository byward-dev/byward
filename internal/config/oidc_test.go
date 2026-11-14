package config

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// oidcBase is a complete configuration for a Keycloak IdP.
var oidcBase = []string{
	"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp",
	"BYWARD_UPSTREAM_URL=http://upstream:9000/mcp",
	"BYWARD_IDP=keycloak",
	"BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme",
	"BYWARD_OIDC_CLIENT_ID=byward",
	"BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc",
}

func oidcFiles(p string) ([]byte, error) {
	switch p {
	case "/run/secrets/oidc":
		return []byte("s3cret-oidc\n"), nil
	case "/run/secrets/key.pem":
		return []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), nil
	}
	return os.ReadFile(p) //nolint:gosec // G304: only the test's own paths
}

func loadOIDC(t *testing.T, change func([]string) []string) (*Config, error) {
	t.Helper()
	env := slices.Clone(oidcBase)
	if change != nil {
		env = change(env)
	}
	c, _, err := Load(nil, env, oidcFiles)
	return c, err
}

// without drops the settings named by prefix from env.
func without(prefixes ...string) func([]string) []string {
	return func(env []string) []string {
		return slices.DeleteFunc(env, func(kv string) bool {
			for _, p := range prefixes {
				if strings.HasPrefix(kv, p+"=") {
					return true
				}
			}
			return false
		})
	}
}

func with(kv ...string) func([]string) []string {
	return func(env []string) []string { return append(env, kv...) }
}

func TestAnOIDCIdPIsReadFromItsSettings(t *testing.T) {
	c, err := loadOIDC(t, with("BYWARD_OIDC_SCOPES=groups, roles", "BYWARD_OIDC_NAME=Acme SSO"))
	if err != nil {
		t.Fatal(err)
	}
	if c.IdP != "keycloak" || c.OIDCIssuer != "https://sso.example.com/realms/acme" || c.OIDCClientID != "byward" || c.OIDCClientSecret != "s3cret-oidc" ||
		!slices.Equal(c.OIDCScopes, []string{"groups", "roles"}) || c.OIDCSubjectClaim != "sub" || c.OIDCName != "Acme SSO" || c.EntraClientID != "" {
		t.Fatalf("config %+v", c)
	}
}

// Google needs no issuer: the preset knows it. Every other IdP needs one.
func TestGoogleDefaultsItsIssuer(t *testing.T) {
	c, err := loadOIDC(t, func(env []string) []string {
		return with("BYWARD_IDP=google")(without("BYWARD_IDP", "BYWARD_OIDC_ISSUER")(env))
	})
	if err != nil || c.OIDCIssuer != OIDCDefaultIssuers["google"] {
		t.Fatalf("google without an issuer: %v, %v", c, err)
	}
}

func TestAnOIDCIdPWithMissingOrConflictingSettingsRefusesToStart(t *testing.T) {
	for name, tc := range map[string]struct {
		change func([]string) []string
		want   string
	}{
		"an unknown IdP":                  {with("BYWARD_IDP=github"), `BYWARD_IDP: want entra, oidc, google, okta, auth0, keycloak, got "github"`},
		"no issuer":                       {without("BYWARD_OIDC_ISSUER"), "BYWARD_OIDC_ISSUER is required with BYWARD_IDP=keycloak"},
		"no client ID":                    {without("BYWARD_OIDC_CLIENT_ID"), "BYWARD_OIDC_CLIENT_ID is required with BYWARD_IDP=keycloak"},
		"a public client":                 {without("BYWARD_OIDC_CLIENT_SECRET_FILE"), "BYWARD_OIDC_CLIENT_SECRET_FILE or BYWARD_OIDC_CLIENT_KEY_FILE is required"},
		"a secret and a key":              {with("BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem"), "are both set; give one of them"},
		"a key ID with no key":            {with("BYWARD_OIDC_CLIENT_KEY_ID=k1"), "BYWARD_OIDC_CLIENT_KEY_ID is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		"blank scopes":                    {with("BYWARD_OIDC_SCOPES= ,"), "BYWARD_OIDC_SCOPES is set but lists nothing"},
		"a scope with a quote":            {with(`BYWARD_OIDC_SCOPES=a"b`), `BYWARD_OIDC_SCOPES: "a\"b" is not a scope`},
		"a scope with a backslash":        {with(`BYWARD_OIDC_SCOPES=a\b`), `BYWARD_OIDC_SCOPES: "a\\b" is not a scope`},
		"a scope with a space":            {with("BYWARD_OIDC_SCOPES=a b"), `BYWARD_OIDC_SCOPES: "a b" is not a scope`},
		"a blank subject claim":           {with("BYWARD_OIDC_SUBJECT_CLAIM= "), "BYWARD_OIDC_SUBJECT_CLAIM: want a claim name"},
		"an empty roles claim":            {with("BYWARD_OIDC_ROLES_CLAIM="), `BYWARD_OIDC_ROLES_CLAIM: want a claim name such as https://example.com/roles, got ""`},
		"a padded roles claim":            {with("BYWARD_OIDC_ROLES_CLAIM= roles"), `BYWARD_OIDC_ROLES_CLAIM: want a claim name such as https://example.com/roles, got " roles"`},
		"sub as the groups claim":         {with("BYWARD_OIDC_GROUPS_CLAIM=sub"), `BYWARD_OIDC_GROUPS_CLAIM: "sub" is a claim of the sign-in itself, not roles or groups; name the claim the IdP sends them in, such as https://example.com/groups`},
		"a roles claim padded at the end": {with("BYWARD_OIDC_ROLES_CLAIM=roles\t"), `BYWARD_OIDC_ROLES_CLAIM: want a claim name such as https://example.com/roles, got "roles\t"`},
		"a blank groups claim":            {with("BYWARD_OIDC_GROUPS_CLAIM= "), `BYWARD_OIDC_GROUPS_CLAIM: want a claim name such as https://example.com/groups, got " "`},
		"a name too long":                 {with("BYWARD_OIDC_NAME=" + strings.Repeat("n", 81)), "BYWARD_OIDC_NAME"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadOIDC(t, tc.change)
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a configuration error containing %q", err, tc.want)
			}
		})
	}
}

// Entra and OIDC settings never mix: either way round, startup names the stray settings and
// BYWARD_IDP, so the operator sees both sides of the conflict.
func TestMixingEntraAndOIDCSettingsNamesBothSides(t *testing.T) {
	_, err := loadOIDC(t, with("BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001", "BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/oidc",
		"BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=2027-11-06"))
	// A secret read from a file is named as the operator set it, with _FILE.
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_ENTRA_TENANT, BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT cannot be used with BYWARD_IDP=keycloak") ||
		!strings.Contains(err.Error(), "the entra IdP") {
		t.Fatalf("Entra settings with keycloak: %v", err)
	}
	_, err = load(t, nil, "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_SUBJECT_CLAIM=email")
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_OIDC_ISSUER, BYWARD_OIDC_SUBJECT_CLAIM cannot be used with BYWARD_IDP=entra") ||
		!strings.Contains(err.Error(), "the oidc IdP") {
		t.Fatalf("OIDC settings with entra: %v", err)
	}
}

// The roles and groups claims are roles and groups for every OIDC IdP unless the operator names
// others (#286).
func TestTheRolesAndGroupsClaimsDefaultToRolesAndGroupsForEveryOIDCIdP(t *testing.T) {
	for _, idp := range append([]string{"oidc"}, OIDCPresets...) {
		t.Run(idp, func(t *testing.T) {
			c, err := loadOIDC(t, func(env []string) []string { return with("BYWARD_IDP=" + idp)(without("BYWARD_IDP")(env)) })
			if err != nil {
				t.Fatal(err)
			}
			if c.OIDCRolesClaim != "roles" || c.OIDCGroupsClaim != "groups" {
				t.Fatalf("roles claim %q, groups claim %q; want roles and groups", c.OIDCRolesClaim, c.OIDCGroupsClaim)
			}
		})
	}
}

// Named claims are read as the operator gives them, a namespaced URL included.
func TestTheRolesAndGroupsClaimSettingsAreReadAsNamed(t *testing.T) {
	c, err := loadOIDC(t, with("BYWARD_OIDC_ROLES_CLAIM=https://byward.dev/roles", "BYWARD_OIDC_GROUPS_CLAIM=https://byward.dev/groups"))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDCRolesClaim != "https://byward.dev/roles" || c.OIDCGroupsClaim != "https://byward.dev/groups" {
		t.Fatalf("roles claim %q, groups claim %q; want the named claims", c.OIDCRolesClaim, c.OIDCGroupsClaim)
	}
}

// A claim about the sign-in itself is never roles: aud and azp hold the proxy's client ID, so a
// gate on either would admit every user of the IdP. The list is the test's own, not the code's.
func TestAClaimOfTheSignInItselfIsRefusedAsTheRolesClaim(t *testing.T) {
	for _, claim := range []string{"iss", "sub", "aud", "azp", "exp", "iat", "nbf", "jti", "nonce", "auth_time", "acr", "amr", "sid", "at_hash", "c_hash"} {
		t.Run(claim, func(t *testing.T) {
			_, err := loadOIDC(t, with("BYWARD_OIDC_ROLES_CLAIM="+claim))
			if want := `BYWARD_OIDC_ROLES_CLAIM: "` + claim + `" is a claim of the sign-in itself`; !isConfigError(err) || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a configuration error containing %q", err, want)
			}
		})
	}
}

// Entra's roles and groups claims are fixed, so naming others with Entra refuses to start, even
// when the name is the default (#286).
func TestTheRolesAndGroupsClaimSettingsAreRefusedWithEntra(t *testing.T) {
	_, err := load(t, nil, "BYWARD_OIDC_ROLES_CLAIM=roles", "BYWARD_OIDC_GROUPS_CLAIM=https://byward.dev/groups")
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_OIDC_ROLES_CLAIM, BYWARD_OIDC_GROUPS_CLAIM cannot be used with BYWARD_IDP=entra") {
		t.Fatalf("the claim settings with entra: %v", err)
	}
}

// The default stays Entra, so existing deployments and the five-key quickstart are unchanged.
func TestEntraIsTheDefaultIdP(t *testing.T) {
	c, err := load(t, nil)
	if err != nil || c.IdP != "entra" || c.OIDCIssuer != "" {
		t.Fatalf("default IdP: %+v, %v", c, err)
	}
}

// A PEM key instead of a secret is read from its file, with its key ID.
func TestAnOIDCClientKeyIsReadFromItsFile(t *testing.T) {
	c, err := loadOIDC(t, func(env []string) []string {
		return with("BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem", "BYWARD_OIDC_CLIENT_KEY_ID=k1")(without("BYWARD_OIDC_CLIENT_SECRET_FILE")(env))
	})
	if err != nil || !strings.Contains(c.OIDCClientKey, "BEGIN PRIVATE KEY") || c.OIDCClientKeyID != "k1" || c.OIDCClientSecret != "" {
		t.Fatalf("config %+v, %v", c, err)
	}
}

// --dev accepts an http IdP issuer on a loopback host, relaxing the oidc adapter (OIDCLoopbackHTTP)
// only together with a relaxation, so it is logged at startup (security invariant 12, #355); an
// https issuer, an issuer of another scheme, an http issuer elsewhere and no --dev relax and record
// nothing.
func TestDevRecordsAnHTTPIdPIssuerOnLoopbackAsARelaxation(t *testing.T) {
	for _, tc := range []struct {
		name, issuer string
		dev, want    bool
	}{
		{"localhost over http", "http://localhost:8180/realms/byward", true, true},
		{"127.0.0.1 over http", "http://127.0.0.1:8180/realms/byward", true, true},
		{"[::1] over http", "http://[::1]:8180/realms/byward", true, true},
		{"127.0.0.2 over http", "http://127.0.0.2:8180/realms/byward", true, true}, // any loopback address, as the adapter has it
		{"https", "https://sso.example.com/realms/acme", true, false},
		{"https on localhost", "https://localhost:8443/realms/byward", true, false},
		{"another scheme on localhost", "ftp://localhost/realms/byward", true, false},
		{"http on a private address", "http://10.0.0.5:8180/realms/byward", true, false},
		{"an issuer that does not parse", "http://[::1", true, false}, // the adapter refuses it; config must not panic
		{"http on another host", "http://sso.example.com/realms/acme", true, false},
		{"http on localhost without --dev", "http://localhost:8180/realms/byward", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kv := []string{"BYWARD_OIDC_ISSUER=" + tc.issuer}
			if tc.dev {
				kv = append(kv, "BYWARD_DEV=true")
			}
			c, err := loadOIDC(t, func(env []string) []string { return with(kv...)(without("BYWARD_OIDC_ISSUER")(env)) })
			if err != nil {
				t.Fatal(err)
			}
			want := "http IdP issuer on loopback (" + tc.issuer + "): discovery over http, and the IdP's sign-in page, token endpoint and signing keys over http too where it lists them on loopback"
			if got := slices.Contains(c.Relaxations, want); got != tc.want || c.OIDCLoopbackHTTP != tc.want {
				t.Fatalf("relaxations %q, adapter relaxed %v; want listed and relaxed = %v (%q)", c.Relaxations, c.OIDCLoopbackHTTP, tc.want, want)
			}
		})
	}
}

// --dev accepts an inline secret and records it as a relaxation naming the setting (security
// invariant 12, #355's audit); without --dev it refuses to start.
func TestDevRecordsAnInlineSecretAsARelaxation(t *testing.T) {
	inline := func(env []string) []string {
		return with("BYWARD_OIDC_CLIENT_SECRET=s3cret")(without("BYWARD_OIDC_CLIENT_SECRET_FILE")(env))
	}
	c, err := loadOIDC(t, func(env []string) []string { return with("BYWARD_DEV=true")(inline(env)) })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.Relaxations, "inline secrets accepted: BYWARD_OIDC_CLIENT_SECRET") {
		t.Fatalf("with --dev: relaxations %v; want the inline secret recorded", c.Relaxations)
	}
	if _, err := loadOIDC(t, inline); !isConfigError(err) {
		t.Fatalf("without --dev: %v, want a configuration error", err)
	}
}
