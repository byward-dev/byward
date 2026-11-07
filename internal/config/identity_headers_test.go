package config

import (
	"strings"
	"testing"
)

func TestPlainIdentityHeadersAreOffByDefault(t *testing.T) {
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

func TestPlainIdentityHeadersNeedAuthentication(t *testing.T) {
	_, _, err := Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_INSECURE_NO_AUTH=true",
		"BYWARD_IDENTITY_HEADERS=true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "BYWARD_IDENTITY_HEADERS") {
		t.Fatalf("err = %v", err)
	}
}

func TestPlainIdentityHeadersTakeTrueOrFalse(t *testing.T) {
	if _, err := load(t, nil, "BYWARD_IDENTITY_HEADERS=yes please"); err == nil || !strings.Contains(err.Error(), "BYWARD_IDENTITY_HEADERS: want true or false") {
		t.Fatalf("err = %v", err)
	}
}
