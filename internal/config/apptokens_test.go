package config

import (
	"slices"
	"strings"
	"testing"
)

// App-only tokens are off unless turned on, and on they carry the app gate.
func TestAppOnlyTokensAreOffByDefaultAndReadTheirGateWhenOn(t *testing.T) {
	c, err := load(t, nil)
	if err != nil || c.AppTokens != "off" || c.AppRoles != nil {
		t.Fatalf("default: %q %v, %v", c.AppTokens, c.AppRoles, err)
	}
	c, err = load(t, nil, "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=MCP.Invoke, MCP.Admin", "BYWARD_APP_CLIENT_IDS=00000000-0000-0000-0000-00000000000a")
	if err != nil || c.AppTokens != "entra" || !slices.Equal(c.AppRoles, []string{"MCP.Invoke", "MCP.Admin"}) ||
		!slices.Equal(c.AppClientIDs, []string{"00000000-0000-0000-0000-00000000000a"}) {
		t.Fatalf("on: %+v, %v", c, err)
	}
}

func TestAppOnlyTokenSettingsThatCannotWorkRefuseToStart(t *testing.T) {
	for name, tc := range map[string]struct {
		env  []string
		oidc bool
		want string
	}{
		"no app role":            {env: []string{"BYWARD_APP_TOKENS=entra"}, want: "BYWARD_APP_ROLES is required with BYWARD_APP_TOKENS=entra"},
		"a blank role list":      {env: []string{"BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES= , "}, want: "BYWARD_APP_ROLES is required"},
		"a blank client ID list": {env: []string{"BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=r", "BYWARD_APP_CLIENT_IDS=,"}, want: "BYWARD_APP_CLIENT_IDS is set but lists nothing"},
		"an unknown value":       {env: []string{"BYWARD_APP_TOKENS=google"}, want: `BYWARD_APP_TOKENS: want off or entra, got "google"`},
		"roles while off":        {env: []string{"BYWARD_APP_ROLES=r", "BYWARD_APP_CLIENT_IDS=x"}, want: "BYWARD_APP_ROLES, BYWARD_APP_CLIENT_IDS set while BYWARD_APP_TOKENS=off"},
		"an OIDC IdP":            {env: []string{"BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=r"}, oidc: true, want: "BYWARD_APP_TOKENS=entra cannot be used with BYWARD_IDP=keycloak"},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if tc.oidc {
				_, err = loadOIDC(t, with(tc.env...))
			} else {
				_, err = load(t, nil, tc.env...)
			}
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a configuration error containing %q", err, tc.want)
			}
		})
	}
}
