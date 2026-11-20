package config

import (
	"strconv"
	"strings"
	"testing"
)

// Every list setting refuses a value that names no entry, such as ",": it would read as unset, and a
// gate list would silently open the gate (parseEntries). OBO scopes, split at white space, take " "
// as theirs.
func TestEveryListSettingRefusesAListOfNone(t *testing.T) {
	loadOIDCWith := func(t *testing.T, kv ...string) error { _, err := loadOIDC(t, with(kv...)); return err }
	loadWith := func(t *testing.T, kv ...string) error { _, err := load(t, nil, kv...); return err }
	for _, tc := range []struct {
		env    string
		blanks []string // "," and " , " when nil
		extra  []string
		load   func(*testing.T, ...string) error // load when nil
	}{
		{env: "BYWARD_ALLOWED_HOSTS"},
		{env: "BYWARD_ALLOWED_ORIGINS"},
		{env: "BYWARD_TRUSTED_PROXIES"},
		{env: "BYWARD_CIMD_TRUSTED_HOSTS"},
		{env: "BYWARD_CIMD_ALLOWED_HOSTS"},
		{env: "BYWARD_CLIENT_DENYLIST"},
		{env: "BYWARD_GATE_TENANTS"},
		{env: "BYWARD_GATE_ROLES", blanks: []string{",", " ,, "}},
		{env: "BYWARD_GATE_GROUPS", blanks: []string{",", " "}},
		{env: "BYWARD_GATE_EMAIL_DOMAINS"},
		{env: "BYWARD_GATE_HOSTED_DOMAINS"},
		{env: "BYWARD_ASSERTION_CLAIMS"},
		{env: "BYWARD_UPSTREAM_STRIP_HEADERS"},
		{env: "BYWARD_OAUTH_RATE_LIMITS"},
		{env: "BYWARD_APP_ROLES", extra: []string{"BYWARD_APP_TOKENS=entra"}},
		{env: "BYWARD_APP_CLIENT_IDS", extra: []string{"BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=r"}},
		{env: "BYWARD_OBO_SCOPES", blanks: []string{" ", "\t"}},
		{env: "BYWARD_OIDC_SCOPES", load: loadOIDCWith},
	} {
		blanks, load := tc.blanks, tc.load
		if blanks == nil {
			blanks = []string{",", " , "}
		}
		if load == nil {
			load = loadWith
		}
		for _, blank := range blanks {
			t.Run(tc.env+"="+strconv.Quote(blank), func(t *testing.T) {
				err := load(t, append(tc.extra, tc.env+"="+blank)...)
				if want := tc.env + ": want at least one entry; got a list of none"; !isConfigError(err) || !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want the refusal %q", err, want)
				}
			})
		}
	}
}
