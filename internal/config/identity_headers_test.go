package config

import (
	"strings"
	"testing"
)

func TestPlainIdentityHeadersAreOffUntilSetTrue(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentityHeaders {
		t.Fatal("plain identity headers are on by default")
	}
	if c, err = load(t, nil, "BYWARD_IDENTITY_HEADERS=true"); err != nil || !c.IdentityHeaders {
		t.Fatalf("BYWARD_IDENTITY_HEADERS=true: on %v, err %v", c != nil && c.IdentityHeaders, err)
	}
}

// The plain identity headers need an authenticated user and an HTTP upstream, and a boolean.
func TestPlainIdentityHeadersRefuseWhatCannotWork(t *testing.T) {
	entra := []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001",
		"BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002", "BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra"}
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		inErr string
	}{
		{"without authentication", nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
			"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_IDENTITY_HEADERS=true"},
			"BYWARD_INSECURE_NO_AUTH cannot be combined with BYWARD_IDENTITY_HEADERS: remove one of them"},
		{"a stdio upstream", []string{"--", "/usr/local/bin/server"}, append(entra, "BYWARD_IDENTITY_HEADERS=true"),
			"BYWARD_IDENTITY_HEADERS is for an HTTP upstream; a stdio upstream gets the user in its environment"},
		{"not a boolean", nil, append(append([]string{}, base...), "BYWARD_IDENTITY_HEADERS=yes please"),
			"BYWARD_IDENTITY_HEADERS: want true or false, got \"yes please\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(tc.args, tc.env, baseFiles); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}

// The plain identity headers' names are reserved whether or not they are on: the assertion and the
// credential cannot use them, in any spelling (ADR-0016 §5).
func TestNoOtherSettingMayUseAPlainIdentityHeader(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   []string
		inErr string
	}{
		{"the assertion, headers off", []string{"BYWARD_ASSERTION_HEADER=X-Byward-Roles"},
			"BYWARD_ASSERTION_HEADER: X-Byward-Roles is one of the plain identity headers the proxy sets"},
		{"the assertion, headers on", []string{"BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_HEADER=x-byward-subject"},
			"BYWARD_ASSERTION_HEADER: X-Byward-Subject is one of the plain identity headers"},
		{"the credential, another spelling", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X_Byward_Email"},
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER: X_byward_email is one of the plain identity headers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadCred(t, nil, "k-123", tc.env...); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}
