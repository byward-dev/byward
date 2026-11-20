package config

import (
	"flag"
	"strings"
	"testing"
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

// L167: a refused setting never prints a password or token it holds, in its user information, path
// parameters, query or fragment, whatever it was refused for, and still names the setting (security
// invariant 2). The refusal reaches stderr at startup, check and doctor: the container log.
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
		"https:/up.example/x;k=" + secret, // a mistyped scheme separator and path parameters (#470)
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
		"https:/app.example/x;k=" + secret,   // a mistyped scheme separator and path parameters (#470)
		"https:://app.example/x;k=" + secret, // a doubled colon before the ://
	}
	hosts := []string{"user:" + secret + "@app.example", "user:" + secret + "@app.example:8443",
		"user:" + secret + "@bücher.example", "https://user:" + secret + "@bücher.example", "app.example?token=" + secret,
		"https:/app.example/x;k=" + secret, "HTTPS:/bücher.example/;" + secret, "https:://app.example/x;k=" + secret}
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
	oidcScopes := []string{"https://user:" + secret + "@api.example/read x", "https:/api.example/r;" + secret + " x"}
	obo := []string{"https://user:" + secret + "@graph.microsoft.com", "api:" + secret + "@x",
		"https://graph.microsoft.com/User.Read https://user:" + secret + "@other.example/x",
		"https://u:" + secret + "@graph.example/User.Read https://other.example/x",
		"api://app/x https://u:" + secret + "/rest@h.example", // a password holding a /: the API part scopeSlash cuts ends inside the password
		"https://u:" + secret + "/rest@h.example api://app/x", "https:/graph.example/x;" + secret}
	proxies := []string{"https://user:" + secret + "@10.0.0.1", "10.0.0.1?token=" + secret, "https:/10.0.0.1/;" + secret}
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

// A URL or host refused for its form is never shown, in part or whole (ADR-0031 §1): the refusal names
// the setting, the entry's place and length, and config's reason, so the operator can still find the
// value and fix it.
func TestARefusedURLIsNeverShownButSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		env  string
		load func(kv ...string) error
		want string
	}{
		{"BYWARD_UPSTREAM_URL=https://user:pw@up.example/x", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (28 characters, not shown): it holds a user name or password (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_PUBLIC_URL=https://user:pw@mcp.example.com/mcp", withConfig(t), `BYWARD_PUBLIC_URL: want an absolute http(s) URL; got a value (35 characters, not shown): it holds a user name or password`},
		// url.Parse reads host:port without a scheme as a scheme and an opaque port: refused as no scheme.
		{"BYWARD_UPSTREAM_URL=upstream:9000", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (13 characters, not shown): it has no scheme such as https:// (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_UPSTREAM_URL=upstream:9000/mcp", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (17 characters, not shown): it has no scheme such as https:// (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_UPSTREAM_URL=https:8443", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (10 characters, not shown): it has no "//" after its scheme (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_UPSTREAM_URL=http:8080", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (9 characters, not shown): it has no "//" after its scheme (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_ALLOWED_ORIGINS=localhost:3000", withConfig(t), `BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (14 characters, not shown): it has no scheme such as https://`},
		{"BYWARD_UPSTREAM_URL=mailto:up@up.example", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (20 characters, not shown): it has a scheme other than http or https (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_UPSTREAM_URL=ftp://up.example/x?k=pw", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (23 characters, not shown): it has a scheme other than http or https (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_UPSTREAM_URL=up.example/x", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (12 characters, not shown): it has no scheme such as https:// (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_UPSTREAM_URL=https://user:pw@up stream/x", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (27 characters, not shown): it does not parse as a URL (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_ALLOWED_ORIGINS=https://user:pw@app.example", withConfig(t), `BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (27 characters, not shown): it holds a user name or password`},
		{"BYWARD_ALLOWED_ORIGINS=https://app.example?t=pw", withConfig(t), `BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (24 characters, not shown): it has a query or a fragment`},
		{"BYWARD_CLIENT_DENYLIST=https://user:pw@app.example/c.json", withConfig(t), `BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (34 characters, not shown): it is a CIMD client ID with a user name or password`},
		{"BYWARD_CLIENT_DENYLIST=https://app.example/c.json?v=pw", withConfig(t), `BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (31 characters, not shown): it is a CIMD client ID with a query or a fragment`},
		{"BYWARD_CLIENT_DENYLIST=https://app.example/%zz@x", withConfig(t), `BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (25 characters, not shown): it is not an absolute URL`},
		{"BYWARD_ALLOWED_HOSTS=ü:pw@app.example", withConfig(t), `BYWARD_ALLOWED_HOSTS: want a host[:port] such as mcp.example.com or 127.0.0.1:8080; got entry 1 of 1 (16 characters, not shown): it holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send`},
		{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read https://user:pw@other.example/x", withConfig(t), `BYWARD_OBO_SCOPES: want scope URIs of one API such as https://graph.microsoft.com/User.Read, api://<app>/<scope> or <app ID>/<scope>; got entries 1 and 2 of 2: they are for different APIs; Entra issues a token for one API per request`},
		{"BYWARD_OIDC_ISSUER=https://user:pw@idp.example", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (27 characters, not shown): it holds a user name or password`},
		{"BYWARD_OIDC_ISSUER=http://user:pw@127.0.0.1:8081", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (29 characters, not shown): it holds a user name or password`},
		{"BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme?k=pw", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (40 characters, not shown): it has a query or a fragment, which an issuer never has`},
		{"BYWARD_OIDC_ISSUER=https:/user:pw@idp.example", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (26 characters, not shown): it has no host`},
		{"BYWARD_OIDC_ISSUER=ftp://idp.example/realms/a@b", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (28 characters, not shown): it has a scheme other than http or https`},
		{"BYWARD_OIDC_ISSUER=https://user:pw@idp.example/?q", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (30 characters, not shown): it holds a user name or password`},
		{"BYWARD_UPSTREAM_URL=https:up.example/x", withConfig(t), `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (18 characters, not shown): it has no "//" after its scheme (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
		{"BYWARD_OIDC_ISSUER=https://[::1", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (12 characters, not shown): it does not parse as a URL`},
		{"BYWARD_OIDC_ISSUER=https:/idp.example/realms/pw", withOIDC(t), `BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it; got a value (28 characters, not shown): it has no host`},
		{"BYWARD_OBO_SCOPES=User.Read", withConfig(t), `BYWARD_OBO_SCOPES: want scope URIs of one API such as https://graph.microsoft.com/User.Read, api://<app>/<scope> or <app ID>/<scope>; got entry 1 of 1 (9 characters, not shown): it is not a scope URI`},
	} {
		err := tc.load(tc.env)
		if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "pw") {
			t.Errorf("%s: %v, want %q, and never the password", tc.env, err, tc.want)
		}
	}
}

// A stray argument is never shown: a value pasted after a space, as in
// --upstream-url= https://user:pw@host, is named by its length only.
func TestAStrayArgumentNeverShowsACredentialItHolds(t *testing.T) {
	_, err := load(t, []string{"--upstream-url=", "https://user:s3cretPW@up.example/mcp"})
	if err == nil || strings.Contains(err.Error(), "s3cretPW") || strings.Contains(err.Error(), "up.example") || !strings.Contains(err.Error(), "got an unexpected argument (36 characters, not shown)") {
		t.Fatalf("Load = %v, want the stray argument refused by its length, none of it shown", err)
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
		"ftp://up.example/x":           `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (18 characters, not shown): it has a scheme other than http or https`,
		"/mcp":                         `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (4 characters, not shown): it has no scheme such as https://`,
		"https://user:pw@up.example/x": `BYWARD_UPSTREAM_URL: want an absolute http(s) URL; got a value (28 characters, not shown): it holds a user name or password`,
	} {
		if _, err := ParseUpstreamURL(raw); err == nil || err.Error() != want {
			t.Errorf("ParseUpstreamURL(%q) = %v, want exactly %q", raw, err, want)
		}
	}
}

// #478: a URL whose scheme is mistyped in any of its seven ways, with a token in its path parameters,
// is refused by each URL and host setting, the OIDC issuer, the trusted proxies, the OBO scopes and the
// listen addresses, without any of it shown: neither the token nor the host. (BYWARD_OIDC_SCOPES takes
// any text without white space, a backslash or a double quote: #512.)
func TestAURLWithAMistypedSchemeIsRefusedWithoutAnyOfItShown(t *testing.T) {
	forms := []string{"https;//h.example/;tok=", "https//h.example/;tok=", "https: //h.example/;tok=", `https:\h.example/;tok=`,
		"//h.example/;tok=", "https:h.example/;tok=", "https:/h.example/;tok="}
	settings := map[string]func(kv ...string) error{"BYWARD_OIDC_ISSUER": withOIDC(t)}
	for _, env := range []string{"BYWARD_PUBLIC_URL", "BYWARD_UPSTREAM_URL", "BYWARD_RESOURCE_DOCUMENTATION", "BYWARD_ALLOWED_ORIGINS",
		"BYWARD_ALLOWED_HOSTS", "BYWARD_CLIENT_DENYLIST", "BYWARD_CIMD_TRUSTED_HOSTS", "BYWARD_CIMD_ALLOWED_HOSTS", "BYWARD_TRUSTED_PROXIES",
		"BYWARD_OBO_SCOPES", "BYWARD_LISTEN", "BYWARD_INTERNAL_LISTEN"} {
		settings[env] = withConfig(t)
	}
	for env, load := range settings {
		for _, form := range forms {
			value := form + canaryText
			err := load(env + "=" + value)
			// BYWARD_OBO_SCOPES splits at white space, so the form with a space is two refused entries.
			if !isConfigError(err) || !strings.Contains(err.Error(), env+": want ") || !strings.Contains(err.Error(), " characters, not shown): ") ||
				holdsCanary(err.Error()) || strings.Contains(err.Error(), "h.example") {
				t.Errorf("%s=%s: %v, want it refused by its length, and neither its token nor its host shown", env, value, err)
			}
		}
	}
}

// The flag package's own refusals quote the argument or the value given to a flag; config names
// them without it (ADR-0031 §1).
func TestAFlagTheFlagPackageRefusesIsNeverShown(t *testing.T) {
	version := func(fs *flag.FlagSet) { fs.Bool("version", false, "") }
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a bad flag syntax", []string{"---upstream-url=https://h.example/x?k=" + canaryText}, "want flags as --name=value; got an argument with a bad flag syntax (48 characters, not shown)"},
		{"a flag with no name", []string{"--=" + canaryText}, "want flags as --name=value; got an argument with a bad flag syntax (13 characters, not shown)"},
		{"a value given to an action flag", []string{"--version=" + canaryText}, "--version: want true, false or no value; got a value it does not take (not shown)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolve(registry, tc.args, base, baseFiles, version)
			if !isConfigError(err) || err.Error() != tc.want || holdsCanary(err.Error()) {
				t.Fatalf("got %v, want the configuration error %q", err, tc.want)
			}
		})
	}
}
