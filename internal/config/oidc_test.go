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
		"an unknown IdP":           {with("BYWARD_IDP=github"), `BYWARD_IDP: want entra, oidc, google, okta, auth0, keycloak, got "github"`},
		"no issuer":                {without("BYWARD_OIDC_ISSUER"), "BYWARD_OIDC_ISSUER is required with BYWARD_IDP=keycloak"},
		"no client ID":             {without("BYWARD_OIDC_CLIENT_ID"), "BYWARD_OIDC_CLIENT_ID is required with BYWARD_IDP=keycloak"},
		"a public client":          {without("BYWARD_OIDC_CLIENT_SECRET_FILE"), "BYWARD_OIDC_CLIENT_SECRET_FILE or BYWARD_OIDC_CLIENT_KEY_FILE is required"},
		"a secret and a key":       {with("BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem"), "are both set; give one of them"},
		"a key ID with no key":     {with("BYWARD_OIDC_CLIENT_KEY_ID=k1"), "BYWARD_OIDC_CLIENT_KEY_ID is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		"blank scopes":             {with("BYWARD_OIDC_SCOPES= ,"), "BYWARD_OIDC_SCOPES is set but lists nothing"},
		"a scope with a quote":     {with(`BYWARD_OIDC_SCOPES=a"b`), `BYWARD_OIDC_SCOPES: "a\"b" is not a scope`},
		"a scope with a backslash": {with(`BYWARD_OIDC_SCOPES=a\b`), `BYWARD_OIDC_SCOPES: "a\\b" is not a scope`},
		"a scope with a space":     {with("BYWARD_OIDC_SCOPES=a b"), `BYWARD_OIDC_SCOPES: "a b" is not a scope`},
		"a blank subject claim":    {with("BYWARD_OIDC_SUBJECT_CLAIM= "), "BYWARD_OIDC_SUBJECT_CLAIM: want a claim name"},
		"a name too long":          {with("BYWARD_OIDC_NAME=" + strings.Repeat("n", 81)), "BYWARD_OIDC_NAME"},
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
