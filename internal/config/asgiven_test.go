package config

import (
	"slices"
	"strings"
	"testing"
)

// A refusal of settings given together, or of one given without another, names each given setting
// as the operator gave it, flag or variable (#619): the message points at what the operator wrote.
func TestARefusalBetweenSettingsNamesEachGivenOneAsGiven(t *testing.T) {
	withoutOIDCSecret := without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase))
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		files readFileFunc
		want  string
	}{
		{"an OIDC secret and key, by env", nil, append(slices.Clone(oidcBase), "BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem"), oidcFiles,
			"BYWARD_OIDC_CLIENT_SECRET_FILE and BYWARD_OIDC_CLIENT_KEY_FILE are both set; give one of them"},
		{"an OIDC secret and key, by flag", []string{"--oidc-client-secret-file=/run/secrets/oidc", "--oidc-client-key-file=/run/secrets/key.pem"}, withoutOIDCSecret, oidcFiles,
			"--oidc-client-secret-file and --oidc-client-key-file are both set; give one of them"},
		{"an OIDC key ID without a key, by env", nil, append(slices.Clone(oidcBase), "BYWARD_OIDC_CLIENT_KEY_ID=k1"), oidcFiles,
			"BYWARD_OIDC_CLIENT_KEY_ID is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an OIDC key ID without a key, by flag", []string{"--oidc-client-key-id=k1"}, slices.Clone(oidcBase), oidcFiles,
			"--oidc-client-key-id is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an OIDC key algorithm without a key, by flag", []string{"--oidc-client-key-alg=ES256"}, slices.Clone(oidcBase), oidcFiles,
			"--oidc-client-key-alg is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an inline Entra secret and a certificate, by env", nil, withoutSecret("BYWARD_ENTRA_CLIENT_SECRET=abc", "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=/run/secrets/entra"), baseFiles,
			"BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE and BYWARD_ENTRA_CLIENT_SECRET are set together"},
		{"an inline OIDC secret and a key, by env", nil, append(slices.Clone(withoutOIDCSecret), "BYWARD_OIDC_CLIENT_SECRET=abc", "BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem"), oidcFiles,
			"BYWARD_OIDC_CLIENT_SECRET and BYWARD_OIDC_CLIENT_KEY_FILE are both set"},
		{"two Entra credentials, by env", nil, append(slices.Clone(base), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE=/run/secrets/token"), baseFiles,
			"BYWARD_ENTRA_CLIENT_SECRET_FILE and BYWARD_ENTRA_FEDERATED_TOKEN_FILE are set together"},
		{"two Entra credentials, by flag", []string{"--entra-federated-token-file=/run/secrets/token"}, slices.Clone(base), baseFiles,
			"--entra-federated-token-file and BYWARD_ENTRA_CLIENT_SECRET_FILE are set together"},
		{"a secret expiry with a federated token, by flag", []string{"--entra-federated-token-file=/run/secrets/token", "--entra-client-secret-expires-at=2030-01-01"}, withoutSecret(), baseFiles,
			"--entra-client-secret-expires-at has no effect with --entra-federated-token-file"},
		{"a secret expiry with a certificate, by flag", []string{"--entra-client-certificate-file=/run/secrets/entra", "--entra-client-secret-expires-at=2030-01-01"}, withoutSecret(), baseFiles,
			"--entra-client-secret-expires-at has no effect with --entra-client-certificate-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(tc.args, tc.env, tc.files)
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// NameAsGiven names a setting as the operator gave it: its file flag or file variable for a secret, its
// variable to set when it is left at its default or there are no values, and panics for an unknown name.
func TestNameAsGivenNamesASettingAsTheOperatorGaveIt(t *testing.T) {
	withoutOIDCSecret := without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase))
	load := func(args, env []string) *Values {
		t.Helper()
		c, _, err := Load(args, env, oidcFiles)
		if err != nil {
			t.Fatal(err)
		}
		return c.Values
	}
	for _, tc := range []struct {
		name string
		v    *Values
		want string
	}{
		{"by flag", load([]string{"--oidc-client-key-file=/run/secrets/key.pem"}, withoutOIDCSecret), "--oidc-client-key-file"},
		{"by env", load(nil, append(slices.Clone(withoutOIDCSecret), "BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem")), "BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"left at its default", load(nil, slices.Clone(oidcBase)), "BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"no values", nil, "BYWARD_OIDC_CLIENT_KEY_FILE"},
	} {
		if got := tc.v.NameAsGiven("oidc-client-key"); got != tc.want {
			t.Errorf("%s: NameAsGiven = %q, want %q", tc.name, got, tc.want)
		}
	}
	defer func() {
		if r, want := recover(), "config: no setting oidc-client-keys"; r != want {
			t.Fatalf("recovered %v, want %q", r, want)
		}
	}()
	(*Values)(nil).NameAsGiven("oidc-client-keys")
}

// Values resolved over a registry of their own name a setting from it, given or left at its default,
// and a setting only the global registry holds from that: lookup alone holds neither probe (#631).
func TestNameAsGivenNamesASettingFromTheRegistryItsValuesWereResolvedOver(t *testing.T) {
	probe := Setting{Name: "probe-secret", shape: secretShape, Group: GroupKeysAndStore}
	for _, tc := range []struct {
		name, setting string
		args          []string
		want          string
	}{
		{"its own setting left at its default", "probe-secret", nil, "BYWARD_PROBE_SECRET_FILE"},
		{"its own setting given", "probe-secret", []string{"--probe-secret-file=/run/secrets/p"}, "--probe-secret-file"},
		{"a setting it does not hold", "public-url", nil, "BYWARD_PUBLIC_URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := resolve([]Setting{probe}, tc.args, nil, func(string) ([]byte, error) { return []byte("p"), nil }, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := v.NameAsGiven(tc.setting); got != tc.want {
				t.Errorf("NameAsGiven(%q) = %q, want %q", tc.setting, got, tc.want)
			}
		})
	}
}
