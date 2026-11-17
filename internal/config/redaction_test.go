package config

import (
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// The loaders a row refuses a value with: the test base, and a working OIDC configuration (whose
// issuer a row replaces), so a value config fails to refuse loads and the row fails.
func withConfig(t *testing.T) func(kv ...string) error {
	return func(kv ...string) error {
		_, err := load(t, nil, append([]string{"BYWARD_CIMD=true"}, kv...)...)
		return err
	}
}

func withOIDC(t *testing.T) func(kv ...string) error {
	return func(kv ...string) error { _, err := loadOIDC(t, with(kv...)); return err }
}

// L167: a refused setting never prints a password or token it holds, in its user information, query
// or fragment, whatever it was refused for, and still names the setting (security invariant 2). The
// refusal reaches stderr at startup, check and doctor: the container log.
func TestARefusedSettingNeverShowsACredentialItHolds(t *testing.T) {
	const secret = "s3cretPW"
	urls := []string{
		"https://user:" + secret + "@up.example/x",
		"https://:" + secret + "@up.example/x",    // a password with no user name
		"https://user:" + secret + "@up stream/x", // not a URL Go parses
		"ftp://user:" + secret + "@up.example/x",
		"https://user:" + secret + "@",
		"user:" + secret + "@up.example/x", // no scheme
		"htp://up.example/x?token=" + secret,
		"https:/up.example/x?token=" + secret, // a mistyped scheme separator
		"up.example/x?token=" + secret,
		"up.example/x#" + secret,
	}
	origins := []string{
		"https://user:" + secret + "@app.example",
		"https://:" + secret + "@app.example",
		"https://user:" + secret + "@ap p.example",
		"https://app.example?token=" + secret,
		"https://app.example#" + secret,
		"user:" + secret + "@app.example",
		"app.example?token=" + secret,
		"app.example#" + secret,
	}
	hosts := []string{"user:" + secret + "@app.example", "user:" + secret + "@app.example:8443",
		"user:" + secret + "@bücher.example", "https://user:" + secret + "@bücher.example", "app.example?token=" + secret}
	denylist := append([]string{"https://user:" + secret + "@app.example/c.json", "https://:" + secret + "@app.example/c.json", "https://app.example/c.json?token=" + secret,
		"https://app.example/c.json#" + secret, "https://user:" + secret + "@ap p.example/c.json"}, hosts...)
	issuers := []string{
		"https://user:" + secret + "@idp.example",
		"https://:" + secret + "@idp.example",
		"http://user:" + secret + "@127.0.0.1:8081",
		"https://user:" + secret + "@id p.example",     // not a URL Go parses
		"https://user:" + secret + "@idp.example:port", // an invalid port
		"https://idp.example:port?token=" + secret,
		"https://idp.example:port#" + secret,
		"https:/user:" + secret + "@idp.example", // no host
		"https:user:" + secret + "@idp.example",  // opaque
		"user:" + secret + "@idp.example",        // no scheme
		"https:/idp.example?token=" + secret,
		"//idp.example?token=" + secret,                       // no scheme, though Go finds a host
		"http://idp.example/r?api_key=" + secret,              // the adapter refuses http; the query was logged before
		"https://sso.example.com/notrealms?api_key=" + secret, // the keycloak preset refuses its path
		"https://sso.example.com/realms/acme#" + secret,
		"htps://u:8443/" + secret + "@idp.example", // a mistyped scheme: refused for its scheme, not its host
		"ftp://idp.example/u:" + secret + "@x",
		"//idp.example/u:" + secret + "@x", // no scheme, though Go finds a host
	}
	oidcScopes := []string{"https://user:" + secret + "@api.example/read x"}
	obo := []string{"https://user:" + secret + "@graph.microsoft.com", "api:" + secret + "@x",
		"https://graph.microsoft.com/User.Read https://user:" + secret + "@other.example/x",
		"https://u:" + secret + "@graph.example/User.Read https://other.example/x",
		"api://app/x https://u:" + secret + "/rest@h.example", // a password holding a /: the API part scopeSlash cuts ends inside the password
		"https://u:" + secret + "/rest@h.example api://app/x"}
	proxies := []string{"https://user:" + secret + "@10.0.0.1", "10.0.0.1?token=" + secret}
	for _, tc := range []struct {
		env    string
		values []string
		load   func(kv ...string) error
		extra  []string
	}{
		{"BYWARD_UPSTREAM_URL", urls, withConfig(t), nil},
		{"BYWARD_PUBLIC_URL", urls, withConfig(t), nil},
		{"BYWARD_RESOURCE_DOCUMENTATION", urls, withConfig(t), nil},
		{"BYWARD_ALLOWED_ORIGINS", origins, withConfig(t), nil},
		{"BYWARD_ALLOWED_HOSTS", hosts, withConfig(t), nil},
		{"BYWARD_CIMD_TRUSTED_HOSTS", hosts, withConfig(t), nil},
		{"BYWARD_CIMD_ALLOWED_HOSTS", hosts, withConfig(t), nil},
		{"BYWARD_CLIENT_DENYLIST", denylist, withConfig(t), nil},
		{"BYWARD_OBO_SCOPES", obo, withConfig(t), nil},
		{"BYWARD_TRUSTED_PROXIES", proxies, withConfig(t), nil},
		{"BYWARD_OIDC_SCOPES", oidcScopes, withOIDC(t), nil},
		{"BYWARD_OIDC_ISSUER", issuers, withOIDC(t), nil},
		{"BYWARD_OIDC_ISSUER", issuers, withOIDC(t), []string{"BYWARD_DEV=true"}}, // its relaxation line quotes the issuer
	} {
		for _, v := range tc.values {
			err := tc.load(append(tc.extra, tc.env+"="+v)...)
			switch {
			case err == nil:
				t.Errorf("%s=%s %v loaded, want it refused", tc.env, v, tc.extra)
			case strings.Contains(err.Error(), secret):
				t.Errorf("%s=%s %v: the error shows the secret: %v", tc.env, v, tc.extra, err)
			case !strings.Contains(err.Error(), tc.env+": "):
				t.Errorf("%s=%s %v: the error does not name the setting: %v", tc.env, v, tc.extra, err)
			}
		}
	}
	// Controls: the OIDC configuration the issuer rows change loads, with an http loopback issuer
	// under --dev, and an @ in the path of an absolute http(s) issuer or a CIMD denylist entry, which
	// is the IdP's or the client's to have, loads too.
	for _, tc := range []struct {
		load func(kv ...string) error
		kv   []string
	}{
		{withOIDC(t), []string{"BYWARD_DEV=true", "BYWARD_OIDC_ISSUER=http://127.0.0.1:8081"}},
		{withOIDC(t), []string{"BYWARD_OIDC_ISSUER=https://sso.example.com/realms/a@b"}},
		{withOIDC(t), []string{"BYWARD_OIDC_ISSUER=http://sso.example.com/realms/a@b"}},
		{withOIDC(t), []string{"BYWARD_DEV=true", "BYWARD_OIDC_ISSUER=http://127.0.0.1:8081/realms/a@b"}},
		{withConfig(t), []string{"BYWARD_CLIENT_DENYLIST=https://app.example/u@x.example/c.json"}},
	} {
		if err := tc.load(tc.kv...); err != nil {
			t.Errorf("%v: %v, want it to load", tc.kv, err)
		}
	}
}

// What a refusal still shows, so the operator can find the value: the setting, a URL's scheme, host
// and path, and config's reason; text holding no credential, whole; a value that is neither, not at
// all.
func TestARefusedURLShowsItsSchemeHostAndPathAndWhy(t *testing.T) {
	for _, tc := range []struct {
		env  string
		load func(kv ...string) error
		want []string
	}{
		{"BYWARD_UPSTREAM_URL=https://user:pw@up.example/x", withConfig(t), []string{`BYWARD_UPSTREAM_URL: want an absolute http(s) URL without a user name or password, got "https://up.example/x"`}},
		{"BYWARD_PUBLIC_URL=https://user:pw@mcp.example.com/mcp", withConfig(t), []string{`BYWARD_PUBLIC_URL: want an absolute http(s) URL without a user name or password, got "https://mcp.example.com/mcp"`}},
		{"BYWARD_UPSTREAM_URL=ftp://up.example/x?k=pw", withConfig(t), []string{`BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got "ftp://up.example/x"`}},
		{"BYWARD_UPSTREAM_URL=up.example/x", withConfig(t), []string{`BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got "up.example/x"`}},
		{"BYWARD_UPSTREAM_URL=https://user:pw@up stream/x", withConfig(t), []string{`BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got ` + logging.Hidden}},
		{"BYWARD_ALLOWED_ORIGINS=https://user:pw@app.example", withConfig(t), []string{`BYWARD_ALLOWED_ORIGINS: "https://app.example"`, `is not an origin (scheme://host[:port]): it has a user name or password`}},
		{"BYWARD_ALLOWED_ORIGINS=https://app.example?t=pw", withConfig(t), []string{`BYWARD_ALLOWED_ORIGINS: "https://app.example"`, `is not an origin (scheme://host[:port]): it has a query or a fragment`}},
		{"BYWARD_CLIENT_DENYLIST=https://user:pw@app.example/c.json", withConfig(t), []string{`BYWARD_CLIENT_DENYLIST: "https://app.example/c.json"`, `is not a CIMD client ID: it has a user name or password`}},
		{"BYWARD_CLIENT_DENYLIST=https://app.example/c.json?v=pw", withConfig(t), []string{`BYWARD_CLIENT_DENYLIST: "https://app.example/c.json"`, `is not a CIMD client ID: it has a query or a fragment`}},
		{"BYWARD_CLIENT_DENYLIST=https://app.example/%zz@x", withConfig(t), []string{`BYWARD_CLIENT_DENYLIST: ` + logging.Hidden + ` is not a CIMD client ID: it is not an absolute URL`}},
		{"BYWARD_ALLOWED_HOSTS=ü:pw@app.example", withConfig(t), []string{`BYWARD_ALLOWED_HOSTS: ` + logging.Hidden + ` has a host that is not ASCII`}},
		{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read https://user:pw@other.example/x", withConfig(t), []string{`BYWARD_OBO_SCOPES: "https://graph.microsoft.com" and "https://other.example/x"`, `are for different APIs`}},
		{"BYWARD_OIDC_ISSUER=https://user:pw@idp.example", withOIDC(t), []string{`BYWARD_OIDC_ISSUER: want the issuer URL without a user name or password, got "https://idp.example"`}},
		{"BYWARD_OIDC_ISSUER=http://user:pw@127.0.0.1:8081", withOIDC(t), []string{`BYWARD_OIDC_ISSUER: want the issuer URL without a user name or password, got "http://127.0.0.1:8081"`}},
		{"BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme?k=pw", withOIDC(t), []string{`BYWARD_OIDC_ISSUER: want the issuer URL without a query or fragment, as an issuer has none, got "https://sso.example.com/realms/acme"`}},
		{"BYWARD_OIDC_ISSUER=https:/user:pw@idp.example", withOIDC(t), []string{`BYWARD_OIDC_ISSUER: want an absolute http(s) URL with a host, got ` + logging.Hidden}},
		{"BYWARD_OIDC_ISSUER=ftp://idp.example/realms/a@b", withOIDC(t), []string{`BYWARD_OIDC_ISSUER: want an absolute http(s) URL with a host, got ` + logging.Hidden}},
		{"BYWARD_OBO_SCOPES=User.Read", withConfig(t), []string{`BYWARD_OBO_SCOPES: "User.Read" is not a scope URI`}},
	} {
		err := tc.load(tc.env)
		for _, want := range tc.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v, want %q", tc.env, err, want)
			}
		}
	}
}

// A stray argument is quoted as a setting is: a value pasted after a space, as in
// --upstream-url= https://user:pw@host, never shows its password.
func TestAStrayArgumentNeverShowsACredentialItHolds(t *testing.T) {
	_, err := load(t, []string{"--upstream-url=", "https://user:s3cretPW@up.example/mcp"})
	if err == nil || strings.Contains(err.Error(), "s3cretPW") || !strings.Contains(err.Error(), `unexpected argument "https://up.example/mcp"`) {
		t.Fatalf("Load = %v, want the stray argument refused and shown without its password", err)
	}
}

// ParseUpstreamURL, for init: an http(s) URL with a host is taken, anything else refused by the name
// BYWARD_UPSTREAM_URL, as the proxy refuses it.
func TestParseUpstreamURLAcceptsAnHTTPURLAndRefusesAnyOtherByTheSettingsName(t *testing.T) {
	if u, err := ParseUpstreamURL("http://127.0.0.1:9000/mcp"); err != nil || u.Host != "127.0.0.1:9000" {
		t.Fatalf("ParseUpstreamURL = %v, %v", u, err)
	}
	for raw, want := range map[string]string{
		"":                             "BYWARD_UPSTREAM_URL is required",
		"ftp://up.example/x":           `BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got "ftp://up.example/x"`,
		"/mcp":                         `BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got "/mcp"`,
		"https://user:pw@up.example/x": `BYWARD_UPSTREAM_URL: want an absolute http(s) URL without a user name or password, got "https://up.example/x"`,
	} {
		if _, err := ParseUpstreamURL(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseUpstreamURL(%q) = %v, want %q", raw, err, want)
		}
	}
}
