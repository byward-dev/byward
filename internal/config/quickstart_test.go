package config

import (
	"strings"
	"testing"
	"time"
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
			if !c.EntraClientSecretExpiresAt.Equal(tc.want) {
				t.Fatalf("expires %v, want %v", c.EntraClientSecretExpiresAt, tc.want)
			}
		})
	}
}

func TestSecretExpiresAtRejectsOtherForms(t *testing.T) {
	for _, raw := range []string{"06/11/2027", "next year", "2027-13-01", "1 year"} {
		t.Run(raw, func(t *testing.T) {
			_, err := load(t, nil, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT="+raw)
			if err == nil || !strings.Contains(err.Error(), "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT: want a date such as 2027-11-06") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPublicURLAcceptsHTTPSOrLoopbackAndNamesTheRuleABadOneBreaks(t *testing.T) {
	// An IP address, IPv6 included, is a valid host though the host name rule would refuse it (#344),
	// and any port from 1 to 65535 is accepted (#353). A last label that is not a number (10x) makes a
	// name.
	for _, raw := range []string{"https://mcp.example.com/mcp", "http://127.0.0.1:8080/mcp", "http://localhost:8080/team/mcp", "http://[::1]:8080/mcp", "https://[2001:db8::1]/mcp",
		"https://mcp.example.com:443/mcp", "https://mcp.example.com:8443/mcp", "https://mcp.example.com:1/mcp", "https://mcp.example.com:65535/mcp", "https://[2001:db8::1]:8443/mcp",
		"https://[::ffff:a00:1]/mcp", "https://10.0.0.1/mcp", "https://0.0.0.0/mcp", "https://mcp.example.10x/mcp"} {
		if _, err := ParsePublicURL(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for raw, inErr := range map[string]string{
		"":                               "BYWARD_PUBLIC_URL is required",
		"https://mcp.example.com":        "without a trailing slash",
		"https://mcp.example.com/mcp/":   "without a trailing slash",
		"https://mcp.example.com/mcp?x=": "query or fragment",
		"http://mcp.example.com/mcp":     "must use https",
		"https://bücher.example/mcp":     `the host "bücher.example" is not ASCII`,
		"ftp://mcp.example.com/mcp":      "absolute http(s) URL",
		// A browser rewrites these hosts (10.0.0.1, 8.0.0.1) or refuses them, so a browser sign-in could
		// never come back to the public URL.
		"https://10.1/mcp":                       `BYWARD_PUBLIC_URL: "10.1" is not an IPv4 address in dotted decimal, the only form browsers send`,
		"https://010.0.0.1/mcp":                  `"010.0.0.1" is not an IPv4 address in dotted decimal`,
		"https://mcp.10/mcp":                     `"mcp.10" is not an IPv4 address in dotted decimal`,
		"https://mcp.0x0123456789abcdef0123/mcp": `"mcp.0x0123456789abcdef0123" is not an IPv4 address in dotted decimal`, // a hex number too large for 64 bits is still a number
		// An IPv6 address only as browsers write it, since the public URL is also the issuer and the
		// resource browser clients compare (#447); the message names that form.
		"https://[2001:DB8:0:0::1]/mcp":       "BYWARD_PUBLIC_URL: the IPv6 address [2001:DB8:0:0::1] is not in the form browsers write it; write it as [2001:db8::1]",
		"https://[::ffff:127.0.0.1]:8443/mcp": "the IPv6 address [::ffff:127.0.0.1] is not in the form browsers write it; write it as [::ffff:7f00:1]",
		"https://[0:0::1]/mcp":                "write it as [::1]",
		"https://[1:0:0:0:2:0:0:3]/mcp":       "the IPv6 address [1:0:0:0:2:0:0:3] is not in the form browsers write it; write it as [1::2:0:0:3]",
		"https://[2001:DB8::1]/mcp":           "the IPv6 address [2001:DB8::1] is not in the form browsers write it; write it as [2001:db8::1]",
	} {
		if _, err := ParsePublicURL(raw); err == nil || !strings.Contains(err.Error(), inErr) {
			t.Errorf("%q: err = %v, want %q", raw, err, inErr)
		}
	}
	// A host name only in lower case, as browsers write it, since the public URL is also the issuer
	// browser clients compare (#472). The whole error is pinned: LOCALHOST over http is loopback, so no
	// https error joins it, and the trailing-slash error's example names the host as browsers write it,
	// whichever host rule it broke: a name in lower case, IPv4 in dotted decimal, IPv6 in short form.
	for raw, want := range map[string]string{
		"https://MCP.Example.com/mcp":       "BYWARD_PUBLIC_URL: the host name MCP.Example.com is not in the form browsers write it; write it as mcp.example.com",
		"https://mcp.example.coM:8443/mcp":  "BYWARD_PUBLIC_URL: the host name mcp.example.coM is not in the form browsers write it; write it as mcp.example.com",
		"http://LOCALHOST:8080/mcp":         "BYWARD_PUBLIC_URL: the host name LOCALHOST is not in the form browsers write it; write it as localhost",
		"https://xn--Bcher-kva.example/mcp": "BYWARD_PUBLIC_URL: the host name xn--Bcher-kva.example is not in the form browsers write it; write it as xn--bcher-kva.example",
		"https://MCP.Example.com:8443/mcp/": "BYWARD_PUBLIC_URL: the host name MCP.Example.com is not in the form browsers write it; write it as mcp.example.com; " +
			"BYWARD_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://mcp.example.com:8443/mcp",
		"https://127.1:8443/mcp/": `BYWARD_PUBLIC_URL: "127.1" is not an IPv4 address in dotted decimal, the only form browsers send; ` +
			"BYWARD_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://127.0.0.1:8443/mcp",
		"https://[0:0::1]/mcp/": "BYWARD_PUBLIC_URL: the IPv6 address [0:0::1] is not in the form browsers write it; write it as [::1]; " +
			"BYWARD_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://[::1]/mcp",
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
