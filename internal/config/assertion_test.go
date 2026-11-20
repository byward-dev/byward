package config

import (
	"slices"
	"strings"
	"testing"
)

func TestAssertionSettingsDefaultToAuthorizationWithRolesInTheDataDirectory(t *testing.T) {
	c, err := load(t, nil, "BYWARD_DATA_DIR=/srv/byward")
	if err != nil {
		t.Fatal(err)
	}
	if c.AssertionHeader != "Authorization" || !slices.Equal(c.AssertionClaims, []string{"roles"}) || c.AssertionKeysDir != "/srv/byward/assertion-keys" {
		t.Fatalf("header %q claims %v keys %q", c.AssertionHeader, c.AssertionClaims, c.AssertionKeysDir)
	}
}

func TestAssertionClaimsAndHeaderAreRead(t *testing.T) {
	for _, tc := range []struct {
		env    []string
		header string
		claims []string
	}{
		{[]string{"BYWARD_ASSERTION_CLAIMS=none"}, "Authorization", nil},
		{[]string{"BYWARD_ASSERTION_CLAIMS=Email, roles,groups,name,roles"}, "Authorization", []string{"email", "roles", "groups", "name"}},
		{[]string{"BYWARD_ASSERTION_HEADER=x-byward-identity"}, "X-Byward-Identity", []string{"roles"}},
	} {
		t.Run(strings.Join(tc.env, " "), func(t *testing.T) {
			c, err := load(t, nil, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			if c.AssertionHeader != tc.header || !slices.Equal(c.AssertionClaims, tc.claims) {
				t.Fatalf("header %q claims %v", c.AssertionHeader, c.AssertionClaims)
			}
		})
	}
}

func TestAssertionSettingsRefuseWhatCannotWork(t *testing.T) {
	for env, inErr := range map[string]string{
		"BYWARD_ASSERTION_HEADER=":                 "BYWARD_ASSERTION_HEADER: want a header name",
		"BYWARD_ASSERTION_HEADER=X Identity":       "BYWARD_ASSERTION_HEADER: want a header name",
		"BYWARD_ASSERTION_HEADER=Host":             "got Host: the proxy, the transport or MCP relies on it",
		"BYWARD_ASSERTION_HEADER=mcp-session-id":   "got Mcp-Session-Id: the proxy, the transport or MCP relies on it",
		"BYWARD_ASSERTION_HEADER=X-Forwarded-User": "got a header starting X-Forwarded-: the proxy, the transport or MCP relies on it",
		"BYWARD_ASSERTION_HEADER=Sec-Fetch-Site":   "got a header starting Sec-: the proxy, the transport or MCP relies on it",
		"BYWARD_ASSERTION_CLAIMS=roles,phone":      "BYWARD_ASSERTION_CLAIMS: want claims from roles, groups, email or name, or none; got entry 2 of 2 (5 characters, not shown): it is not one of them",
		"BYWARD_ASSERTION_CLAIMS=,":                "BYWARD_ASSERTION_CLAIMS: want at least one entry; got a list of none",
	} {
		t.Run(env, func(t *testing.T) {
			if _, err := load(t, nil, env); err == nil || !strings.Contains(err.Error(), inErr) {
				t.Fatalf("err = %v, want %q", err, inErr)
			}
		})
	}
}
