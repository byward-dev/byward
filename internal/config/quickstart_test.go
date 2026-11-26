package config

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/host"
)

func TestSecretExpiresAtAcceptsADateOrRFC3339(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Time
	}{
		{"", time.Time{}},
		{"2027-11-06", time.Date(2027, 11, 6, 0, 0, 0, 0, time.UTC)},
		{"2027-11-06T10:30:00Z", time.Date(2027, 11, 6, 10, 30, 0, 0, time.UTC)},
		{"2027-11-06T12:30:00+02:00", time.Date(2027, 11, 6, 10, 30, 0, 0, time.UTC)},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			c, err := load(t, nil, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT="+tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.EntraClientSecretExpiresAt; !got.Equal(tc.want) || got.Location() != time.UTC {
				t.Fatalf("expires %v, want %v", c.EntraClientSecretExpiresAt, tc.want)
			}
		})
	}
}

func TestSecretExpiresAtRejectsOtherForms(t *testing.T) {
	for _, raw := range []string{"06/11/2027", "next year", "2027-13-01", "1 year"} {
		t.Run(raw, func(t *testing.T) {
			_, err := load(t, nil, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT="+raw)
			want := "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT: want a date such as 2027-11-06 or an RFC 3339 time; got a value (" + strconv.Itoa(len(raw)) + " characters, not shown): it is neither"
			if !isConfigError(err) || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}

func TestPublicURLAcceptsHTTPSOrLoopbackAndNamesTheRuleABadOneBreaks(t *testing.T) {
	// An IP address, IPv6 included, is a valid host though the host name rule would refuse it (#344),
	// and any port from 1 to 65535 is accepted (#353) but the scheme's default (#484), which http's 443
	// and https's 80 are not. A last label that is not a number (10x) makes a name; "_" is a host name
	// character (ADR-0032 §3).
	for _, raw := range []string{"https://mcp.example.com/mcp", "http://127.0.0.1:8080/mcp", "http://localhost:8080/team/mcp", "http://[::1]:8080/mcp", "https://[2001:db8::1]/mcp",
		"http://localhost:443/mcp", "https://mcp.example.com:80/mcp", "https://my_mcp.example/mcp", "https://mcp.example.com:8443/mcp", "https://mcp.example.com:1/mcp", "https://mcp.example.com:65535/mcp", "https://[2001:db8::1]:8443/mcp",
		"https://[::ffff:a00:1]/mcp", "https://10.0.0.1/mcp", "https://0.0.0.0/mcp", "https://mcp.example.10x/mcp"} {
		u, err := ParsePublicURL(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		// Class P (ADR-0032 §2): an accepted public URL's host and port are already in the form
		// internal/host gives them, the form browsers write, since byward never rewrites it.
		if h, err := host.Parse(u.Host, u.Scheme); err != nil || h.String() != u.Host {
			t.Errorf("%s: accepted, but its host and port read as %q, %v", raw, h.String(), err)
		}
	}
	// Each error is pinned whole.
	for raw, want := range map[string]string{
		"": "BYWARD_PUBLIC_URL is required",
		// A browser rewrites these hosts (10.0.0.1, 8.0.0.1) or refuses them (a name ending in a number,
		// #473), so a browser sign-in could never come back to the public URL.
		"https://10.1/mcp":      `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (16 characters, not shown): its host is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as 10.0.0.1`,
		"https://010.0.0.1/mcp": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (21 characters, not shown): its host is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as 8.0.0.1, reading a part with a leading 0 as octal`,
		// The address browsers read is named, not given as the form to write: 010.0.0.1 was likely meant
		// as 10.0.0.1 (#480).
		"https://10.010.0.1:8443/mcp": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (27 characters, not shown): its host is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as 10.8.0.1, reading a part with a leading 0 as octal`,
		"https://0x7f.0.0.1/mcp":      `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (22 characters, not shown): its host is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as 127.0.0.1`,
		"https://0X7f.0.0.1/mcp":      `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (22 characters, not shown): its host is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as 127.0.0.1`,
		// A scheme's default port, which browsers drop from the URL they hold, so the issuer and resource
		// would not match theirs (#484). It is refused, not dropped: the IdP redirect URI is registered as
		// written.
		"https://mcp.example.com:443/mcp": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its port as browsers write it, such as https://mcp.example.com/mcp; got a value (31 characters, not shown): its port 443 is https's default, which browsers drop; write the URL without :443`,
		"http://localhost:80/mcp":         `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its port as browsers write it, such as https://mcp.example.com/mcp; got a value (23 characters, not shown): its port 80 is http's default, which browsers drop; write the URL without :80`,
		"https://[::1]:443/mcp":           `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its port as browsers write it, such as https://mcp.example.com/mcp; got a value (21 characters, not shown): its port 443 is https's default, which browsers drop; write the URL without :443`,
		// The default port's refusal joins those after it.
		"https://mcp.example.com:443/mcp/": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its port as browsers write it, such as https://mcp.example.com/mcp; got a value (32 characters, not shown): its port 443 is https's default, which browsers drop; write the URL without :443; BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`,
		// The URL rule refuses first, so the default port's own refusal never joins its reasons (#605,
		// #522): a port out of range, the default port written with a leading zero, and a URL with a
		// user name on the default port each get the URL rule's reason alone.
		"https://mcp.example.com:99999/mcp": `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (33 characters, not shown): it has a port that is not a number from 1 to 65535 without a sign or leading zero`,
		"https://mcp.example.com:0443/mcp":  `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (32 characters, not shown): it has a port that is not a number from 1 to 65535 without a sign or leading zero`,
		"https://u@mcp.example.com:443/mcp": `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (33 characters, not shown): it holds a user name or password`,
		// An IPv6 zone that ends in a dot is refused as a zone, not as a host name's empty label.
		"https://[fe80::1%25a.]/mcp":             `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (26 characters, not shown): it has an IPv6 zone, which a URL cannot carry; give the address without its %zone`,
		"https://MCP.example.com:443/mcp":        `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (31 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do; BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its port as browsers write it, such as https://mcp.example.com/mcp; got a value (31 characters, not shown): its port 443 is https's default, which browsers drop; write the URL without :443`,
		"https://mcp.10/mcp":                     `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (18 characters, not shown): its host is not an IPv4 address but ends in a number, so browsers refuse it`,
		"https://mcp.0x0123456789abcdef0123/mcp": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (38 characters, not shown): its host is not an IPv4 address but ends in a number, so browsers refuse it`,
		// An IPv6 address only as browsers write it, since the public URL is also the issuer and the
		// resource browser clients compare (#447); the message names that form.
		"https://[2001:DB8:0:0::1]/mcp":       `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (29 characters, not shown): its IPv6 address is not in the form browsers write it; write it as [2001:db8::1]`,
		"https://[::ffff:127.0.0.1]:8443/mcp": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (35 characters, not shown): its IPv6 address is not in the form browsers write it; write it as [::ffff:7f00:1]`,
		"https://[0:0::1]/mcp":                `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (20 characters, not shown): its IPv6 address is not in the form browsers write it; write it as [::1]`,
		"https://[1:0:0:0:2:0:0:3]/mcp":       `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (29 characters, not shown): its IPv6 address is not in the form browsers write it; write it as [1::2:0:0:3]`,
		"https://[2001:DB8::1]/mcp":           `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (25 characters, not shown): its IPv6 address is not in the form browsers write it; write it as [2001:db8::1]`,
		// A host name only in lower case, as browsers write it (#472). The host is not shown, not even in
		// lower case, since a token is a valid host name. LOCALHOST over http is loopback, so no https
		// error joins it.
		"https://MCP.Example.com/mcp":       `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (27 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do`,
		"https://mcp.example.coM:8443/mcp":  `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (32 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do`,
		"http://LOCALHOST:8080/mcp":         `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (25 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do`,
		"https://xn--Bcher-kva.example/mcp": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (33 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do`,
		// The trailing-slash error's example is fixed, whichever host rule the URL broke.
		"https://MCP.Example.com:8443/mcp/": `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (33 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do; BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`,
		"https://127.1:8443/mcp/":           `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (23 characters, not shown): its host is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as 127.0.0.1; BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`,
		"https://[0:0::1]/mcp/":             `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (21 characters, not shown): its IPv6 address is not in the form browsers write it; write it as [::1]; BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`,
		// The other rules.
		"https://bücher.example/mcp":     `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value (26 characters, not shown): its host:port holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send`,
		"http://mcp.example.com/mcp":     `BYWARD_PUBLIC_URL: want https (http only on a loopback host, with --dev), such as https://mcp.example.com/mcp; got http: give https, or a loopback host`,
		"https://mcp.example.com":        `BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`,
		"https://mcp.example.com/mcp?x=": `BYWARD_PUBLIC_URL: want a URL without a query or fragment, such as https://mcp.example.com/mcp; got a query or fragment, not shown: remove it`,
		"ftp://mcp.example.com/mcp":      `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (25 characters, not shown): it has a scheme other than http or https`,
	} {
		if _, err := ParsePublicURL(raw); err == nil || err.Error() != want {
			t.Errorf("%q: err = %v, want exactly %q", raw, err, want)
		}
	}
}

func TestRedirectURLIsTheIssuerCallback(t *testing.T) {
	u, err := ParsePublicURL("https://mcp.example.com:8443/team/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got := RedirectURL(u, "entra"); got != "https://mcp.example.com:8443/callback/entra" {
		t.Fatalf("redirect %q", got)
	}
}

// envLines are the NAME=value lines of an env file, comments left out.
func envLines(file string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(file), "\n") {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// ADR-0020 §8: the Entra quickstart needs at most five settings, and they are enough to load.
func TestQuickstartEnvFileHasAtMostFiveSettingsThatLoad(t *testing.T) {
	lines := envLines(Quickstart{PublicURL: "https://mcp.example.com/mcp", UpstreamURL: "http://u/mcp", Tenant: "00000000-0000-0000-0000-000000000001",
		ClientID: "00000000-0000-0000-0000-000000000002", SecretFile: "/run/secrets/entra"}.EnvFile())
	if len(lines) > 5 {
		t.Fatalf("the quickstart needs %d settings, ADR-0020 §8 allows five: %q", len(lines), lines)
	}
	files := func(string) ([]byte, error) { return []byte("s3cret"), nil }
	if _, _, err := Load(nil, append(lines, "BYWARD_DATA_DIR=/var/lib/byward"), files); err != nil {
		t.Fatalf("the quickstart settings do not load: %v", err)
	}
}

// Values are written as given, so the shell fills in init's variables; an empty value gets a
// comment saying what goes there; the optional expiry is a sixth line only when given.
func TestQuickstartEnvFileKeepsValuesAndExplainsTheEmptyOne(t *testing.T) {
	file := Quickstart{PublicURL: "$PUBLIC_URL", Tenant: "$TENANT_ID", ClientID: "$APP_ID", SecretFile: "$SECRET_FILE", SecretExpiresAt: "$SECRET_EXPIRES_AT"}.EnvFile()
	want := []string{"BYWARD_PUBLIC_URL=$PUBLIC_URL", "BYWARD_UPSTREAM_URL=", "BYWARD_ENTRA_TENANT=$TENANT_ID", "BYWARD_ENTRA_CLIENT_ID=$APP_ID",
		"BYWARD_ENTRA_CLIENT_SECRET_FILE=$SECRET_FILE", "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=$SECRET_EXPIRES_AT"}
	if got := envLines(file); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("settings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(file, "# BYWARD_UPSTREAM_URL: ") || !strings.Contains(file, "\nBYWARD_UPSTREAM_URL=\n") ||
		strings.Index(file, "# BYWARD_UPSTREAM_URL: ") > strings.Index(file, "\nBYWARD_UPSTREAM_URL=\n") {
		t.Fatalf("the empty upstream URL has no comment above it:\n%s", file)
	}
	if strings.Count(Quickstart{PublicURL: "x"}.EnvFile(), "EXPIRES_AT") != 0 {
		t.Fatal("the expiry line is written although no date was given")
	}
}
