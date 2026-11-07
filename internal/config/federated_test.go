package config

import (
	"strings"
	"testing"
)

// withoutSecret is base with a federated token file in place of the client secret.
func withoutSecret(extra ...string) []string {
	var env []string
	for _, kv := range base {
		if !strings.HasPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE=") {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

func TestAFederatedTokenFileReplacesTheEntraClientSecret(t *testing.T) {
	c, _, err := Load(nil, withoutSecret("BYWARD_ENTRA_FEDERATED_TOKEN_FILE=/var/run/secrets/azure/tokens/azure-identity-token"), baseFiles)
	if err != nil {
		t.Fatal(err)
	}
	if c.EntraFederatedTokenFile != "/var/run/secrets/azure/tokens/azure-identity-token" || c.EntraClientSecret != "" {
		t.Fatalf("token file %q, secret set %v", c.EntraFederatedTokenFile, c.EntraClientSecret != "")
	}
}

// Entra gets exactly one credential, named by an absolute path, and no secret expiry without a
// secret.
func TestEntraCredentialSettingsRefuseWhatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   []string
		inErr string
	}{
		{"neither", withoutSecret(), "BYWARD_ENTRA_CLIENT_SECRET_FILE or BYWARD_ENTRA_FEDERATED_TOKEN_FILE is required with BYWARD_IDP=entra"},
		{"both", append(append([]string{}, base...), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE=/run/token"),
			"BYWARD_ENTRA_CLIENT_SECRET_FILE and BYWARD_ENTRA_FEDERATED_TOKEN_FILE are both set: Entra gets one credential"},
		{"a relative path", withoutSecret("BYWARD_ENTRA_FEDERATED_TOKEN_FILE=run/token"), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE: want an absolute path"},
		{"a secret expiry", withoutSecret("BYWARD_ENTRA_FEDERATED_TOKEN_FILE=/run/token", "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=2027-11-06"),
			"BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT has no effect with BYWARD_ENTRA_FEDERATED_TOKEN_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(nil, tc.env, baseFiles); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}
