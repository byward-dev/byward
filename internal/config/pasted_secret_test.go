package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// pasted stands for a secret an operator pasted into a setting that is not secret.
const pasted = "Xq9-S3CRETPW~value"

// readReal is the test base's files, and any other path read from the disk as the proxy reads it,
// so an error carries the *fs.PathError a real read gives (baseFiles' carries no path).
func readReal(p string) ([]byte, error) {
	if p == "/run/secrets/entra" {
		return baseFiles(p)
	}
	return os.ReadFile(p) //nolint:gosec // G304: a test reads the relative path a row gives, which does not exist
}

// refusedLines loads the test base with env and returns the error's lines; the load must fail.
func refusedLines(t *testing.T, env ...string) []string {
	t.Helper()
	_, _, err := Load(nil, append(append([]string{}, base...), env...), readReal)
	if !isConfigError(err) {
		t.Fatalf("err = %v, want a configuration error", err)
	}
	return strings.Split(err.Error(), "\n")
}

// #461, #466 and their siblings: a value config refuses is never shown, only its place, its length and
// a fixed reason, so a secret an operator pasted where a path, a header name, a command or any other
// value belongs appears in no line; each message is pinned whole (security invariant 2).
func TestARefusedSettingNeverShowsASecretPastedIntoIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"a secret's file, given the secret", []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + pasted},
			"BYWARD_ENTRA_CLIENT_SECRET_FILE: want the path of a file holding the secret, such as /run/secrets/entra-client-secret; got a value (18 characters, not shown): it cannot be read: no such file or directory; it is a relative path, read from the working directory"},
		{"the PostgreSQL DSN's file, given the DSN", []string{"BYWARD_STORE_POSTGRES_DSN_FILE=postgres://byward:" + pasted + "@db.example/byward"},
			"BYWARD_STORE_POSTGRES_DSN_FILE: want the path of a file holding the secret, such as /run/secrets/store-postgres-dsn; got a value (54 characters, not shown): it cannot be read: no such file or directory; it is a relative path, read from the working directory"},
		{"a path setting, given the secret", []string{"BYWARD_TLS_KEY_FILE=" + pasted, "BYWARD_TLS_CERT_FILE=/etc/byward/tls.crt"},
			"BYWARD_TLS_KEY_FILE: want an absolute path, one starting with /; got a relative one: no path is relative to the working directory (ADR-0007 §6)"},
		{"a header to strip, given a header line", []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-Key: " + pasted},
			"BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got entry 1 of 1 (29 characters, not shown): it holds a \":\", as a header line does: give only the header's name, the part before the \":\""},
		{"a header family to strip, given a header line", []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-*: " + pasted},
			"BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got entry 1 of 1 (27 characters, not shown): it has a *: list each header of a family by name"},
		{"a client denylist URL with its scheme in capitals, which config refuses", []string{"BYWARD_CLIENT_DENYLIST=HTTPS://a.example/x;k=" + pasted},
			`BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (40 characters, not shown): it breaks the host name rule: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"a client denylist URL with its scheme in capitals and a host that is not ASCII", []string{"BYWARD_CLIENT_DENYLIST=HTTPS://bücher.example/x;k=" + pasted},
			`BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (45 characters, not shown): it holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send`},
		{"a client denylist URL with its scheme in capitals and a password split across its host", []string{"BYWARD_CLIENT_DENYLIST=HTTPS://u:8443/" + pasted + "@a.example/x"},
			`BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (45 characters, not shown): it breaks the host name rule: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"an allowed host, given a URL with path parameters", []string{"BYWARD_ALLOWED_HOSTS=https://a.example/x;k=" + pasted},
			`BYWARD_ALLOWED_HOSTS: want a host[:port] such as mcp.example.com or 127.0.0.1:8080; got entry 1 of 1 (40 characters, not shown): it holds a "/" or a space; give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone`},
		{"an allowed host, given a URL with path parameters and a host that is not ASCII", []string{"BYWARD_ALLOWED_HOSTS=HTTPS://bücher.example/;" + pasted},
			`BYWARD_ALLOWED_HOSTS: want a host[:port] such as mcp.example.com or 127.0.0.1:8080; got entry 1 of 1 (42 characters, not shown): it holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send`},
		{"a CIMD allowed host, given a URL with path parameters", []string{"BYWARD_CIMD_ALLOWED_HOSTS=https://a.example/x;k=" + pasted},
			`BYWARD_CIMD_ALLOWED_HOSTS: want a host name such as claude.ai; got entry 1 of 1 (40 characters, not shown): it breaks the host name rule: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"a CIMD trusted host, given a URL with path parameters and a host that is not ASCII", []string{"BYWARD_CIMD_TRUSTED_HOSTS=HTTPS://bücher.example/;" + pasted},
			`BYWARD_CIMD_TRUSTED_HOSTS: want a host name such as claude.ai; got entry 1 of 1 (42 characters, not shown): it holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send`},
		{"an allowed origin, given a URL with path parameters", []string{"BYWARD_ALLOWED_ORIGINS=https://a.example/x;k=" + pasted},
			`BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (40 characters, not shown): it has a path`},
		{"an allowed origin, given a URL with a mistyped scheme and path parameters", []string{"BYWARD_ALLOWED_ORIGINS=https:/a.example/x;k=" + pasted},
			`BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (39 characters, not shown): it has no host`},
		{"a client denylist URL with a mistyped scheme and path parameters", []string{"BYWARD_CLIENT_DENYLIST=https:/a.example/x;k=" + pasted},
			`BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 (39 characters, not shown): it breaks the host name rule: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"a header to strip whose name holds an @", []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X@" + pasted},
			"BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got entry 1 of 1 (20 characters, not shown): it is not a header name"},
		{"a header to strip with nothing before its colon", []string{"BYWARD_UPSTREAM_STRIP_HEADERS=: " + pasted},
			"BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got entry 1 of 1 (20 characters, not shown): it holds a \":\", as a header line does: give only the header's name, the part before the \":\""},
		{"a header to strip that holds a query", []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Key?k=" + pasted},
			"BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got entry 1 of 1 (26 characters, not shown): it is not a header name"},
		{"the assertion's header holding a query", []string{"BYWARD_ASSERTION_HEADER=X-Key?k=" + pasted},
			"BYWARD_ASSERTION_HEADER: want a header name such as Authorization or X-Byward-Identity; got a value (26 characters, not shown): it is not a header name"},
		{"the assertion's header with nothing before its colon", []string{"BYWARD_ASSERTION_HEADER=:" + pasted},
			"BYWARD_ASSERTION_HEADER: want a header name such as Authorization or X-Byward-Identity; got a value (19 characters, not shown): it holds a \":\", as a header line does: give only the header's name, the part before the \":\""},
		{"a stdio command, malformed, with a token argument", []string{"BYWARD_UPSTREAM_URL=", `BYWARD_UPSTREAM_COMMAND=["/usr/local/bin/server","--token","` + pasted + `"`},
			`BYWARD_UPSTREAM_COMMAND: want a JSON array of strings whose first element is the program, such as ["/usr/local/bin/server","--flag"]; got a value (55 characters, not shown): it is not one`},
		{"the Entra tenant", []string{"BYWARD_ENTRA_TENANT=" + pasted}, "BYWARD_ENTRA_TENANT: want the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, Overview, Tenant ID); got a value (18 characters, not shown): it is not a GUID"},
		{"the Entra client ID, given the client secret", []string{"BYWARD_ENTRA_CLIENT_ID=" + pasted}, "BYWARD_ENTRA_CLIENT_ID: want the application (client) ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, App registrations, your app, Overview, Application (client) ID); got a value (18 characters, not shown): it is not a GUID"},
		{"the client secret's end date", []string{"BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=" + pasted}, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT: want a date such as 2027-11-06 or an RFC 3339 time; got a value (18 characters, not shown): it is neither"},
		{"the scope", []string{"BYWARD_SCOPE=a " + pasted}, "BYWARD_SCOPE: want one scope token, such as mcp; got a value (20 characters, not shown): it has a character a scope token cannot hold: white space, a double quote, a backslash or one that is not printable ASCII"},
		{"a rate limit's endpoint", []string{"BYWARD_OAUTH_RATE_LIMITS=" + pasted + "=5"}, "BYWARD_OAUTH_RATE_LIMITS: want endpoint=per-minute entries such as token=60, the endpoint authorize, consent, callback, token, revoke or register and the limit a whole number from 1 to 10000; got entry 1 of 1 (20 characters, not shown): it is not endpoint=per-minute for one of the endpoints"},
		{"a rate limit's number", []string{"BYWARD_OAUTH_RATE_LIMITS=authorize=" + pasted}, "BYWARD_OAUTH_RATE_LIMITS: want endpoint=per-minute entries such as token=60, the endpoint authorize, consent, callback, token, revoke or register and the limit a whole number from 1 to 10000; got entry 1 of 1 (28 characters, not shown): its limit is not a whole number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := refusedLines(t, tc.env...)
			if !slices.Contains(lines, tc.want) {
				t.Errorf("error lines %q, want the line %q", lines, tc.want)
			}
			for _, l := range lines {
				if strings.Contains(l, "S3CRETPW") {
					t.Errorf("the line %q shows the pasted secret", l)
				}
			}
		})
	}
}

// A secret's file is read at the path as given, by its _FILE variable or its -file flag, absolute or
// relative (os.ReadFile reads a relative one from the working directory). A path that cannot be read
// is refused by its length, never shown, and a relative one is also named as relative; the refusal
// names the variable or the flag, whichever was given. Each readable path holds its own secret, so a
// row passes only if its path is the one read.
func TestASecretFileIsReadWhereItIsGivenAndARefusalNamesHowItWasGiven(t *testing.T) {
	secrets := map[string]string{"secrets/entra": "relative-secret", "/run/secrets/given": "absolute-secret"}
	readSecrets := func(p string) ([]byte, error) {
		if v, ok := secrets[p]; ok {
			return []byte(v + "\n"), nil
		}
		return os.ReadFile(p) //nolint:gosec // G304: a test reads a path that does not exist
	}
	env := slices.DeleteFunc(append([]string{}, base...), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE=") })
	for _, by := range []struct {
		name string
		load func(path string) (*Config, error)
		as   string // how a refusal names it
	}{
		{"its _FILE variable", func(path string) (*Config, error) {
			c, _, err := Load(nil, append(slices.Clone(env), "BYWARD_ENTRA_CLIENT_SECRET_FILE="+path), readSecrets)
			return c, err
		}, "BYWARD_ENTRA_CLIENT_SECRET_FILE"},
		{"its flag", func(path string) (*Config, error) {
			c, _, err := Load([]string{"--entra-client-secret-file", path}, env, readSecrets)
			return c, err
		}, "--entra-client-secret-file"},
	} {
		for path, secret := range secrets {
			t.Run(by.name+", "+path, func(t *testing.T) {
				c, err := by.load(path)
				if err != nil {
					t.Fatalf("err = %v; want %q, the secret at %s", err, secret, path)
				}
				if c.EntraClientSecret != secret {
					t.Fatalf("read %q; want %q, the secret at %s", c.EntraClientSecret, secret, path)
				}
			})
		}
		for _, tc := range []struct{ name, path, why string }{
			{"an unreadable relative path", pasted, "(18 characters, not shown): it cannot be read: no such file or directory; it is a relative path, read from the working directory"},
			{"an unreadable absolute path", "/nonexistent/" + pasted, "(31 characters, not shown): it cannot be read: no such file or directory"},
		} {
			t.Run(by.name+", "+tc.name, func(t *testing.T) {
				want := by.as + ": want the path of a file holding the secret, such as /run/secrets/entra-client-secret; got a value " + tc.why
				if _, err := by.load(tc.path); !isConfigError(err) || err.Error() != want {
					t.Fatalf("err = %v\nwant %s", err, want)
				}
			})
		}
	}
}

// #466: a header line pasted into any setting that names a header the proxy sets (headerSettings)
// is refused by its length, never shown; the message is pinned whole.
func TestAHeaderLinePastedIntoAHeaderSettingIsNeverShown(t *testing.T) {
	for _, s := range headerSettings {
		for _, sep := range []struct{ sep, reason string }{
			{": ", `it holds a ":", as a header line does: give only the header's name, the part before the ":"`},
			{"\t", "it is not a header name"}, // a tab, unlike a colon, is no header line's
		} {
			t.Run(s.env+strings.ReplaceAll(sep.sep, "\t", "<tab>"), func(t *testing.T) {
				_, err := loadCred(t, nil, "k-123", append(s.extra, s.env+"=X-Identity"+sep.sep+pasted)...)
				want := s.env + ": want a header name such as Authorization or " + s.example + "; got a value (" + strconv.Itoa(len("X-Identity"+sep.sep+pasted)) + " characters, not shown): " + sep.reason
				if err == nil || !slices.Contains(strings.Split(err.Error(), "\n"), want) || strings.Contains(err.Error(), "S3CRETPW") {
					t.Fatalf("err = %v, want the line %q and never the secret", err, want)
				}
			})
		}
	}
}

// #458: a URL setting is shown in the startup log and --print-config as logging.MarkedURL shows it,
// with a marker for each part left out, while the proxy keeps the whole URL.
func TestAURLSettingIsShownWithoutItsQueryButUsedWhole(t *testing.T) {
	c, err := load(t, nil, "BYWARD_UPSTREAM_URL=https://up.example/mcp?api_key="+pasted,
		"BYWARD_RESOURCE_DOCUMENTATION=https://docs.example/mcp;s="+pasted+"?k="+pasted+"#"+pasted)
	if err != nil {
		t.Fatal(err)
	}
	shown := map[string]string{}
	for _, v := range c.Values.Effective() {
		shown[v.Setting.Name] = v.Display()
	}
	for name, want := range map[string]string{
		"upstream-url":           "https://up.example/mcp?…",
		"resource-documentation": "https://docs.example/mcp;…?…#…",
		"public-url":             "https://mcp.example.com/mcp",
		"oidc-issuer":            "", // unset: shown empty, as every unset setting is
	} {
		if shown[name] != want {
			t.Errorf("%s is shown as %q, want %q", name, shown[name], want)
		}
	}
	if got := c.UpstreamURL.String(); got != "https://up.example/mcp?api_key="+pasted {
		t.Errorf("the proxy's upstream URL is %q, want it whole", got)
	}
	if c.ResourceDocumentation != "https://docs.example/mcp;s="+pasted+"?k="+pasted+"#"+pasted {
		t.Errorf("the resource documentation is %q, want it whole", c.ResourceDocumentation)
	}
	// The public URL and the issuer refuse a query and a fragment, but take path parameters.
	c, err = load(t, nil, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp;s="+pasted)
	if err != nil {
		t.Fatal(err)
	}
	if got := displayed(c, "public-url"); got != "https://mcp.example.com/mcp;…" || c.PublicURL.String() != "https://mcp.example.com/mcp;s="+pasted {
		t.Errorf("public-url is shown as %q and used as %q, want https://mcp.example.com/mcp;… and the whole URL", got, c.PublicURL)
	}
	c, err = loadOIDC(t, with("BYWARD_OIDC_ISSUER=https://idp.example/realms/acme;k="+pasted))
	if err != nil {
		t.Fatal(err)
	}
	if got := displayed(c, "oidc-issuer"); got != "https://idp.example/realms/acme;…" || c.OIDCIssuer != "https://idp.example/realms/acme;k="+pasted {
		t.Errorf("oidc-issuer is shown as %q and used as %q, want https://idp.example/realms/acme;… and the whole URL", got, c.OIDCIssuer)
	}
}

// A URL that config accepts but whose credentials split across its host and path (a password holding
// an unescaped /) shows as Hidden, never its path: as the OIDC issuer, and as a client denylist entry,
// whose other entries show as URLs do.
func TestAURLWithAPasswordSplitAcrossItsHostIsHidden(t *testing.T) {
	const split = "https://alice:8443/" + pasted + "@idp.example"
	c, err := loadOIDC(t, with("BYWARD_OIDC_ISSUER="+split))
	if err != nil {
		t.Fatal(err)
	}
	if got := displayed(c, "oidc-issuer"); got != "the value (not shown: it may hold a password)" {
		t.Errorf("oidc-issuer %s is shown as %q", split, got)
	}
	c, err = load(t, nil, "BYWARD_CLIENT_DENYLIST="+split+"/c.json, https://app.example/c.json;s="+pasted+", bad.example")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := displayed(c, "client-denylist"), "the value (not shown: it may hold a password), https://app.example/c.json;…, bad.example"; got != want {
		t.Errorf("client-denylist is shown as %q, want %q", got, want)
	}
}

// displayed is the setting name's value as the startup log and --print-config show it.
func displayed(c *Config, name string) string {
	for _, v := range c.Values.Effective() {
		if v.Setting.Name == name {
			return v.Display()
		}
	}
	return "(not set)"
}

// Every URL setting is shown as logging.MarkedURL shows it, whatever it is.
func TestEveryURLSettingIsShownWithoutTheParts(t *testing.T) {
	const raw, shown = "https://h.example/p;s=" + pasted + "?k=" + pasted + "#" + pasted, "https://h.example/p;…?…#…"
	for _, s := range registry {
		var got, want string
		switch s.shape {
		case urlShape:
			got, want = (Value{Setting: s, Given: NewOpaque(raw)}).Display(), shown
		case urlListShape: // each URL entry as a URL, any other as given
			got, want = (Value{Setting: s, Given: NewOpaque(raw + ", app.example")}).Display(), shown+", app.example"
		default:
			continue
		}
		if got != want {
			t.Errorf("%s is shown as %q, want %q", s.Name, got, want)
		}
	}
}

// Every setting config reads as a URL has a URL shape, so a new one cannot print its query: a setting
// read through parseURL by name must have urlShape, and every other net/url Parse, ParseRequestURI or
// JoinPath call, and every call of parseHTTPURL (url.Parse with its reason), in the package (in a
// function or a package-level var), by its owner and argument, is
// listed here once with the setting whose value it reads (which must have urlShape, or urlListShape
// for a list) or "" for one that refuses a query, a fragment and path parameters, reads no setting,
// or whose reads are listed or checked by name elsewhere (parseHTTPURL's callers, parseURL's
// settings). A new call fails until it is listed, and so does every read urlReadsOf cannot follow.
func TestEverySettingReadAsAURLHasAURLShape(t *testing.T) {
	byName := map[string]Setting{}
	for _, s := range registry {
		byName[s.Name] = s
	}
	listed := map[string]string{
		"parseHTTPURL raw":     "",                // url.Parse for the three below, which are listed by what they read
		"parseURL raw":         "",                // the settings read by name, checked below
		"parseIssuer raw":      "oidc-issuer",     // URL
		"parseOrigin o":        "",                // an origin: no path, query or fragment
		"oidcIdP c.OIDCIssuer": "oidc-issuer",     // URL
		"denylistReason e":     "client-denylist", // URLs
		"checkNoAuth o":        "",                // the same origins, again
	}
	seen := map[string]int{}
	named := map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		reads, err := urlReadsOf(f, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range reads.unfollowed {
			t.Errorf("%s: %s", f, p)
		}
		for _, name := range reads.named {
			named[name] = true
			if byName[name].shape != urlShape {
				t.Errorf("%s: reads %s as a URL, but the setting's shape is not urlShape", f, name)
			}
		}
		for _, key := range reads.parsed {
			seen[key]++
			switch name, ok := listed[key]; {
			case !ok:
				t.Errorf("%s: parses %q with net/url: give the setting it reads urlShape (or urlListShape) and list it here, or list it as one that reads no setting", f, key)
			case name != "" && byName[name].shape != urlShape && byName[name].shape != urlListShape:
				t.Errorf("%s: %q parses %s's value, but the setting's shape is not urlShape or urlListShape", f, key, name)
			}
		}
	}
	for key := range listed {
		if seen[key] != 1 {
			t.Errorf("%q occurs %d times, want once: list each call", key, seen[key])
		}
	}
	for _, name := range []string{"public-url", "upstream-url", "resource-documentation"} {
		if !named[name] {
			t.Errorf("found no read of %s through parseURL: the scan has stopped finding reads, or the setting is read another way", name)
		}
	}
}

// Each way of reading a URL past the list above is caught by urlReadsOf, and the packages config
// parses other values with are not taken for a URL.
func TestEachWayOfReadingAURLIsCaught(t *testing.T) {
	cases := []struct {
		name, imports, code string
		want                urlReads
	}{
		{name: "url.Parse is listed by its owner and argument", imports: `"net/url"`, code: `func f() { url.Parse(raw) }`, want: urlReads{parsed: []string{"f raw"}}},
		{name: "url.ParseRequestURI too", imports: `"net/url"`, code: `func f() { url.ParseRequestURI(raw) }`, want: urlReads{parsed: []string{"f raw"}}},
		{name: "url.JoinPath too", imports: `"net/url"`, code: `func f() { url.JoinPath(raw, "x") }`, want: urlReads{parsed: []string{"f raw"}}},
		{name: "in parentheses", imports: `"net/url"`, code: `func f() { (url.Parse)(raw) }`, want: urlReads{parsed: []string{"f raw"}}},
		{name: "under another import name", imports: `u "net/url"`, code: `func f() { u.Parse(raw) }`, want: urlReads{parsed: []string{"f raw"}}},
		{name: "in a package-level var", imports: `"net/url"`, code: `var v, _ = url.Parse(raw)`, want: urlReads{parsed: []string{"v raw"}}},
		{name: "parseHTTPURL is listed by its owner and argument", code: `func f() { parseHTTPURL(raw) }`, want: urlReads{parsed: []string{"f raw"}}},
		{name: "parseHTTPURL taken as a value", code: `func f() { p := parseHTTPURL; p(raw) }`, want: urlReads{unfollowed: []string{"f takes parseHTTPURL as a value; call it where its argument can be listed"}}},
		{name: "parseURL with a setting name", code: `func f() { parseURL("public-url") }`, want: urlReads{named: []string{"public-url"}}},
		{name: "url.Parse taken as a value", imports: `"net/url"`, code: `func f() { p := url.Parse; p(raw) }`, want: urlReads{unfollowed: []string{"f takes url.Parse as a value; call it where its argument can be listed"}}},
		{name: "url.Parse taken as a value in a var", imports: `"net/url"`, code: `var p = url.Parse`, want: urlReads{unfollowed: []string{"p takes url.Parse as a value; call it where its argument can be listed"}}},
		{name: "parseURL taken as a value", code: `func f() { g := parseURL; g("public-url") }`, want: urlReads{unfollowed: []string{"f takes parseURL as a value; call it where its argument can be listed"}}},
		{name: "parseURL with a name that is not a literal", code: `func f() { parseURL(name) }`, want: urlReads{unfollowed: []string{"f calls parseURL with a setting name that is not a literal"}}},
		{name: "a URL's Parse method", code: `func f() { base.Parse(raw) }`, want: urlReads{unfollowed: []string{"f calls base.Parse, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "a URL's JoinPath method", code: `func f() { base.JoinPath(raw) }`, want: urlReads{unfollowed: []string{"f calls base.JoinPath, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "a URL's ResolveReference method", code: `func f() { base.ResolveReference(ref) }`, want: urlReads{unfollowed: []string{"f calls base.ResolveReference, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "a URL's UnmarshalBinary method", code: `func f() { u.UnmarshalBinary(b) }`, want: urlReads{unfollowed: []string{"f calls u.UnmarshalBinary, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "a URL method taken as a value", imports: `"net/url"`, code: `func f() { p := new(url.URL).Parse; p(raw) }`, want: urlReads{unfollowed: []string{"f takes new(url.URL).Parse as a value; call it where its argument can be listed"}}},
		{name: "a URL method expression", imports: `"net/url"`, code: `func f() { (*url.URL).Parse(base, raw) }`, want: urlReads{unfollowed: []string{"f calls (*url.URL).Parse, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "the other parsers are not URL reads", imports: `"time"; "strconv"; "net"; "net/netip"; "github.com/byward-dev/byward/internal/host"`, code: `func f() { time.ParseDuration(s); strconv.ParseBool(s); net.ParseIP(s); netip.ParsePrefix(s); fs.Parse(args); host.ParseIPv4(s); host.Parse(s, "") }`},
		{name: "internal/host under another import name", imports: `h "github.com/byward-dev/byward/internal/host"`, code: `func f() { h.Parse(s, ""); host.ResolveReference(ref) }`, want: urlReads{unfollowed: []string{"f calls host.ResolveReference, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "a URL named host, in a file that does not import internal/host", code: `func f() { host.ResolveReference(ref) }`, want: urlReads{unfollowed: []string{"f calls host.ResolveReference, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
		{name: "a file that does not import net/url has no url.Parse", code: `func f() { url.Parse(raw) }`, want: urlReads{unfollowed: []string{"f calls url.Parse, a URL method: read the URL with url.Parse, where its argument can be listed"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package config\n"
			if c.imports != "" {
				src += "import (" + c.imports + ")\n"
			}
			got, err := urlReadsOf("x.go", src+c.code+"\n")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// urlReads is what urlReadsOf finds in one file.
type urlReads struct {
	named      []string // the settings read through parseURL by name
	parsed     []string // each url.Parse, ParseRequestURI, JoinPath or parseHTTPURL call, as its owner and argument
	unfollowed []string // each read that cannot be listed by its argument, as a message
}

// urlReadsOf scans the Go file name (its source src, or read from the disk if src is nil) for the
// URLs it reads, in its functions and package-level vars. A read it cannot follow to a listed
// argument is unfollowed: url.Parse, parseURL or parseHTTPURL taken as a value, parseURL with a name
// that is not a literal, or a URL method (Parse*, JoinPath, ResolveReference, UnmarshalBinary) called
// or taken as a value on anything but the packages config parses other values with (time, netip,
// net, strconv, internal/host, and its flag set fs).
func urlReadsOf(name string, src any) (urlReads, error) {
	var reads urlReads
	file, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		return reads, err
	}
	urlPkg, hostPkg := "", "" // net/url's and internal/host's names in the file, if it imports them
	for _, imp := range file.Imports {
		switch imp.Path.Value {
		case `"net/url"`:
			urlPkg = "url"
			if imp.Name != nil {
				urlPkg = imp.Name.Name
			}
		case `"github.com/byward-dev/byward/internal/host"`:
			hostPkg = "host"
			if imp.Name != nil {
				hostPkg = imp.Name.Name
			}
		}
	}
	isParse := func(e ast.Expr) (*ast.SelectorExpr, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return nil, false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return sel, ok && urlPkg != "" && pkg.Name == urlPkg && (strings.HasPrefix(sel.Sel.Name, "Parse") || sel.Sel.Name == "JoinPath")
	}
	otherParsers := map[string]bool{"time": true, "netip": true, "net": true, "strconv": true, "fs": true}
	urlMethod := func(e ast.Expr) (*ast.SelectorExpr, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return nil, false
		}
		switch n := sel.Sel.Name; {
		case strings.HasPrefix(n, "Parse"), n == "JoinPath", n == "ResolveReference", n == "UnmarshalBinary":
		default:
			return nil, false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return sel, !ok || pkg.Name != urlPkg && !otherParsers[pkg.Name] && (hostPkg == "" || pkg.Name != hostPkg)
	}
	unfollowed := func(format string, args ...any) {
		reads.unfollowed = append(reads.unfollowed, fmt.Sprintf(format, args...))
	}
	// check walks node, owned by the function or var owner, and lists its URL reads.
	check := func(owner string, node ast.Node) {
		called := map[ast.Expr]bool{}
		var refs []ast.Expr
		ast.Inspect(node, func(n ast.Node) bool {
			if sel, ok := isParse(asExpr(n)); ok {
				refs = append(refs, sel)
			} else if sel, ok := urlMethod(asExpr(n)); ok {
				refs = append(refs, sel)
			}
			if id, ok := n.(*ast.Ident); ok && (id.Name == "parseURL" || id.Name == "parseHTTPURL") {
				refs = append(refs, id)
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun := ast.Unparen(call.Fun)
			called[fun] = true
			if _, ok := isParse(fun); !ok {
				if sel, ok := urlMethod(fun); ok {
					unfollowed("%s calls %s, a URL method: read the URL with url.Parse, where its argument can be listed", owner, types.ExprString(sel))
					return true
				}
			}
			if len(call.Args) == 0 {
				return true
			}
			if id, ok := fun.(*ast.Ident); ok && id.Name == "parseURL" {
				lit, ok := call.Args[0].(*ast.BasicLit)
				name, err := "", error(nil)
				if ok {
					name, err = strconv.Unquote(lit.Value)
				}
				if !ok || err != nil {
					unfollowed("%s calls parseURL with a setting name that is not a literal", owner)
					return true
				}
				reads.named = append(reads.named, name)
				return true
			}
			if id, ok := fun.(*ast.Ident); ok && id.Name == "parseHTTPURL" { // url.Parse, with its reason
				reads.parsed = append(reads.parsed, owner+" "+types.ExprString(call.Args[0]))
			}
			if _, ok := isParse(fun); ok {
				reads.parsed = append(reads.parsed, owner+" "+types.ExprString(call.Args[0]))
			}
			return true
		})
		for _, ref := range refs {
			if !called[ref] {
				unfollowed("%s takes %s as a value; call it where its argument can be listed", owner, types.ExprString(ref))
			}
		}
	}
	for _, d := range file.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				check(d.Name.Name, d.Body)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					check(vs.Names[0].Name, vs)
				}
			}
		}
	}
	return reads, nil
}

// asExpr is n as an expression, or nil.
func asExpr(n ast.Node) ast.Expr {
	e, _ := n.(ast.Expr)
	return e
}

// The upstream command is shown by its program and how many arguments follow, never the arguments,
// which can be a token; the proxy runs it whole. Given as JSON or after --, it shows the same.
func TestTheUpstreamCommandIsShownByItsProgramAndArgumentCount(t *testing.T) {
	argv := []string{"/usr/local/bin/server", "--token", pasted}
	for _, tc := range []struct {
		name string
		args []string
		env  string
	}{
		{"as JSON", nil, `BYWARD_UPSTREAM_COMMAND=["/usr/local/bin/server","--token","` + pasted + `"]`},
		{"after --", append([]string{"--"}, argv...), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{"BYWARD_UPSTREAM_URL="}
			if tc.env != "" {
				env = append(env, tc.env)
			}
			c, _, err := Load(tc.args, append(append([]string{}, base...), env...), baseFiles)
			if err != nil {
				t.Fatal(err)
			}
			if got := displayed(c, "upstream-command"); got != "/usr/local/bin/server (2 arguments not shown)" {
				t.Errorf("the command is shown as %q", got)
			}
			if !slices.Equal(c.UpstreamCommand, argv) {
				t.Errorf("the proxy runs %q, want %q", c.UpstreamCommand, argv)
			}
		})
	}
	for raw, want := range map[string]string{`["/bin/srv"]`: "/bin/srv", `["/bin/srv","-v"]`: "/bin/srv (1 argument not shown)",
		`["/bin/a\nB=1","-v"]`:             `"/bin/a\nB=1" (1 argument not shown)`,
		`["/bin/a\nB=1"]`:                  `"/bin/a\nB=1"`,
		`["/bin/a\nB=1","-v","-w"]`:        `"/bin/a\nB=1" (2 arguments not shown)`,
		`["/bin/a\u001b[2J","-v"]`:         `"/bin/a\x1b[2J" (1 argument not shown)`,
		`["/opt/my server","-v"]`:          "/opt/my server (1 argument not shown)",
		"[\"/bin/a\u202egnp.exe\",\"-v\"]": `"/bin/a\u202egnp.exe" (1 argument not shown)`, // not printable, yet no control character
		"[\"/bin/a\u00a0B\",\"-v\"]":       `"/bin/a\u00a0B" (1 argument not shown)`,       // a space, but not one strconv prints
		"[\"/bin/a\u2028B\",\"-v\"]":       `"/bin/a\u2028B" (1 argument not shown)`,       // a line separator, which some log viewers break on
		"[\"/bin/a\u007fB\",\"-v\"]":       `"/bin/a\x7fB" (1 argument not shown)`,         // DEL
		"not JSON":                         "the value (not shown: it may hold a password)",
		"[]":                               "the value (not shown: it may hold a password)", // no program
		"null":                             "the value (not shown: it may hold a password)"} {
		if got := (Value{Setting: Setting{shape: commandShape}, Given: NewOpaque(raw)}).Display(); got != want {
			t.Errorf("%s is shown as %q, want %q", raw, got, want)
		}
	}
}

// The relaxation lines the startup log, check and doctor print name a URL setting as
// logging.MarkedURL does too: the --dev loopback issuer, and the public URL without authentication.
func TestARelaxationLineShowsAURLSettingWithoutItsParts(t *testing.T) {
	c, err := loadOIDC(t, with("BYWARD_DEV=true", "BYWARD_OIDC_ISSUER=http://127.0.0.1:8180/realms/acme;k="+pasted))
	if err != nil {
		t.Fatal(err)
	}
	want := "http IdP issuer on loopback (http://127.0.0.1:8180/realms/acme;…): discovery over http"
	if !slices.ContainsFunc(c.Relaxations, func(r string) bool { return strings.HasPrefix(r, want) }) || strings.Contains(strings.Join(c.Relaxations, "\n"), "S3CRETPW") {
		t.Errorf("relaxations %q, want one starting %q and never the secret", c.Relaxations, want)
	}
	c, _, err = Load(nil, noAuthEnv("BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp;k="+pasted), nil)
	if err != nil {
		t.Fatal(err)
	}
	want = "AUTHENTICATION IS OFF: anyone who can reach http://127.0.0.1:8080/mcp;… can use the upstream, and the upstream receives no identity"
	if !slices.Contains(c.Relaxations, want) || strings.Contains(strings.Join(c.Relaxations, "\n"), "S3CRETPW") {
		t.Errorf("relaxations %q, want %q and never the secret", c.Relaxations, want)
	}
}
