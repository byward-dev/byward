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
	// and any port from 1 to 65535 is accepted (#353).
	for _, raw := range []string{"https://mcp.example.com/mcp", "http://127.0.0.1:8080/mcp", "http://localhost:8080/team/mcp", "http://[::1]:8080/mcp", "https://[2001:db8::1]/mcp",
		"https://mcp.example.com:443/mcp", "https://mcp.example.com:8443/mcp", "https://mcp.example.com:1/mcp", "https://mcp.example.com:65535/mcp", "https://[2001:db8::1]:8443/mcp"} {
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
	} {
		if _, err := ParsePublicURL(raw); err == nil || !strings.Contains(err.Error(), inErr) {
			t.Errorf("%q: err = %v, want %q", raw, err, inErr)
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
