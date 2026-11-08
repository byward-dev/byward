package config

import (
	"slices"
	"strings"
	"testing"
)

// ADR-0017: On-Behalf-Of is off by default, and its scopes are full URIs of one downstream API.
func TestOnBehalfOfSettings(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.OBOScopes) != 0 || c.OBOHeader != "X-Byward-Downstream-Token" {
		t.Fatalf("defaults: scopes %q, header %q, want off and X-Byward-Downstream-Token", c.OBOScopes, c.OBOHeader)
	}
	for name, scopes := range map[string][]string{
		"Microsoft Graph":         {"https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/Mail.Read"},
		"an API of one's own":     {"api://00000000-0000-0000-0000-0000000000aa/Files.Read"},
		"the resource's .default": {"https://graph.microsoft.com/.default"},
		// #196: Entra's first-party APIs are addressed by app ID, e.g. AKS's server app.
		"an app ID's .default":   {"6dae42f8-4368-4678-94ff-3960e28e3630/.default"},
		"an app ID's two scopes": {"2a72489c-aab2-4b65-b93a-a91edccf33b8/a", "2a72489c-aab2-4b65-b93a-a91edccf33b8/b"},
		"an app ID's scope":      {"2a72489c-aab2-4b65-b93a-a91edccf33b8/user_impersonation"},
	} {
		t.Run(name, func(t *testing.T) {
			const header = "X-Downstream" // set in lower case, canonicalised
			c, err := load(t, nil, "BYWARD_OBO_SCOPES="+strings.Join(scopes, " "), "BYWARD_OBO_HEADER=x-downstream")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.OBOScopes, scopes) || c.OBOHeader != header {
				t.Fatalf("got scopes %q header %q, want %q %q", c.OBOScopes, c.OBOHeader, scopes, header)
			}
		})
	}
}

// #195: most Entra-protected MCP servers read the user's token from Authorization, so the
// downstream token may go there once the assertion and the upstream credential use other headers.
func TestOnBehalfOfMayUseAuthorizationOnceTheAssertionHasMoved(t *testing.T) {
	c, err := load(t, nil, "BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_ASSERTION_HEADER=X-Byward-Assertion", "BYWARD_OBO_HEADER=authorization")
	if err != nil {
		t.Fatal(err)
	}
	if c.OBOHeader != "Authorization" || c.AssertionHeader != "X-Byward-Assertion" {
		t.Fatalf("OBO header %q, assertion header %q, want Authorization and X-Byward-Assertion", c.OBOHeader, c.AssertionHeader)
	}
}

func TestOnBehalfOfSettingsAreRefusedWhenTheyCannotWork(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"offline_access", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read offline_access"}, "offline_access is a sign-in scope"},
		{"openid", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read openid"}, "openid is a sign-in scope"},
		{"profile", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read profile"}, "profile is a sign-in scope"},
		{"email", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read email"}, "email is a sign-in scope"},
		{"a bare scope", []string{"BYWARD_OBO_SCOPES=User.Read"}, "is not a scope URI"},
		{"no scope after the API", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/"}, "is not a scope URI"},
		{"two APIs", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read api://00000000-0000-0000-0000-0000000000aa/Files.Read"}, "different APIs"},
		{"set but empty", []string{"BYWARD_OBO_SCOPES= "}, "lists nothing"},
		{"the assertion's header", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_ASSERTION_HEADER=X-Byward-Identity", "BYWARD_OBO_HEADER=x-byward-identity"}, "already carries"},
		{"Authorization while the assertion uses it", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_OBO_HEADER=Authorization"}, "already carries the identity assertion"},
		{"a header MCP relies on", []string{"BYWARD_OBO_HEADER=Mcp-Session-Id"}, "relies on"},
		{"not a header name", []string{"BYWARD_OBO_HEADER=a b"}, "want a header name"},
		{"a forwarding header", []string{"BYWARD_OBO_HEADER=X-Forwarded-For"}, "relies on"},
		{"a proxy header", []string{"BYWARD_OBO_HEADER=Proxy-Authorization"}, "relies on"},
		{"a fetch metadata header", []string{"BYWARD_OBO_HEADER=Sec-Fetch-Mode"}, "relies on"},
		{"a CORS header", []string{"BYWARD_OBO_HEADER=Access-Control-Allow-Origin"}, "relies on"},
		{"the assertion's header spelled with _", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_ASSERTION_HEADER=X-Byward-Identity", "BYWARD_OBO_HEADER=X_Byward_Identity"}, "already carries"},
		{"a plain identity header", []string{"BYWARD_OBO_HEADER=X-Byward-Subject"}, "plain identity headers"},
		{"plain http", []string{"BYWARD_OBO_SCOPES=http://graph.microsoft.com/User.Read"}, "is not a scope URI"},
		{"a scheme alone", []string{"BYWARD_OBO_SCOPES=api://x"}, "is not a scope URI"},
		{"an app ID and another API", []string{"BYWARD_OBO_SCOPES=6dae42f8-4368-4678-94ff-3960e28e3630/.default https://graph.microsoft.com/User.Read"}, "different APIs"},
		// Whether Entra counts api://<app ID> and <app ID> as one resource is unverified, so they do not mix.
		{"an app ID and its api:// form", []string{"BYWARD_OBO_SCOPES=6dae42f8-4368-4678-94ff-3960e28e3630/.default api://6dae42f8-4368-4678-94ff-3960e28e3630/x"}, "different APIs"},
		{"an api:// API and another app ID", []string{"BYWARD_OBO_SCOPES=api://2a72489c-aab2-4b65-b93a-a91edccf33b8/x 6dae42f8-4368-4678-94ff-3960e28e3630/.default"}, "different APIs"},
		{"two app IDs", []string{"BYWARD_OBO_SCOPES=6dae42f8-4368-4678-94ff-3960e28e3630/.default 2a72489c-aab2-4b65-b93a-a91edccf33b8/.default"}, "different APIs"},
		{"an app ID without a scope", []string{"BYWARD_OBO_SCOPES=6dae42f8-4368-4678-94ff-3960e28e3630/"}, "is not a scope URI"},
		{"an app ID with a path", []string{"BYWARD_OBO_SCOPES=6dae42f8-4368-4678-94ff-3960e28e3630/a/b"}, "is not a scope URI"},
		{"not an app ID", []string{"BYWARD_OBO_SCOPES=6dae42f8-4368-4678-94ff/.default"}, "is not a scope URI"},
		{"an API without a scope", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com"}, "is not a scope URI"},
		{"a host without a scope", []string{"BYWARD_OBO_SCOPES=https://graph"}, "is not a scope URI"},
		{"a scope without an API", []string{"BYWARD_OBO_SCOPES=https:///User.Read"}, "is not a scope URI"},
		{"an API without a host", []string{"BYWARD_OBO_SCOPES=https:///x/User.Read"}, "is not a scope URI"},
		{"an app ID URI without a host", []string{"BYWARD_OBO_SCOPES=api:///x/Files.Read"}, "is not a scope URI"},
		{"an empty path segment", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com//User.Read"}, "is not a scope URI"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, nil, c.env...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
	t.Run("an IdP other than Entra", func(t *testing.T) {
		_, err := loadOIDC(t, with("BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read"))
		if err == nil || !strings.Contains(err.Error(), "needs BYWARD_IDP=entra") {
			t.Fatalf("err = %v, want On-Behalf-Of refused with the OIDC IdP", err)
		}
	})
	t.Run("the upstream credential's header", func(t *testing.T) {
		_, err := loadCred(t, nil, "k-123", "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credFile, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key",
			"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_OBO_HEADER=x-api-key")
		if err == nil || !strings.Contains(err.Error(), "operator's upstream credential") {
			t.Fatalf("err = %v, want the credential's header refused", err)
		}
	})
	t.Run("Authorization while the upstream credential uses it", func(t *testing.T) {
		_, err := loadCred(t, nil, "k-123", "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credFile, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=Authorization",
			"BYWARD_ASSERTION_HEADER=X-Byward-Assertion", "BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_OBO_HEADER=Authorization")
		if err == nil || !strings.Contains(err.Error(), "operator's upstream credential") {
			t.Fatalf("err = %v, want the credential's header refused", err)
		}
	})
	t.Run("a stdio upstream", func(t *testing.T) {
		_, _, err := Load(nil, stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`, "BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read"), baseFiles)
		if err == nil || !strings.Contains(err.Error(), "HTTP upstream only") {
			t.Fatalf("err = %v, want On-Behalf-Of refused with a stdio upstream", err)
		}
	})
}
