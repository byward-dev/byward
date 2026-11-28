package config

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every list setting refuses a value that names no entry, such as ",": it would read as unset, and a
// gate list would silently open the gate (parseEntries). OBO scopes, split at white space, take " "
// as theirs. The table has a row for every list setting in the registry (Setting.IsList), so a new
// one fails here until it has a row (#658).
func TestEveryListSettingRefusesAListOfNone(t *testing.T) {
	loadOIDCWith := func(t *testing.T, kv ...string) error { _, err := loadOIDC(t, with(kv...)); return err }
	loadWith := func(t *testing.T, kv ...string) error { _, err := load(t, nil, kv...); return err }
	rows := []struct {
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
	}
	// Not a list setting, yet refuses a list of none: its scopes are split at white space, not
	// commas, so it is shown as given (asGivenShape) and is not Setting.IsList.
	notLists := map[string]bool{"BYWARD_OBO_SCOPES": true}
	hasRow := map[string]bool{}
	for _, tc := range rows {
		hasRow[tc.env] = true
	}
	for _, s := range registry {
		switch {
		case s.IsList() && !hasRow[s.Env()]:
			t.Errorf("%s is a list setting with no row here: add one", s.Env())
		case !s.IsList() && hasRow[s.Env()] && !notLists[s.Env()]:
			t.Errorf("%s has a row here but is not a list setting", s.Env())
		}
	}
	for _, tc := range rows {
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

// A scope token (RFC 6749 §3.3) is every printable ASCII character but a space, a double quote and a
// backslash: each is taken, by BYWARD_SCOPE and by each entry of BYWARD_OIDC_SCOPES, and every other
// character is refused, ends of the range and controls included.
func TestAScopeTokenIsThePrintableASCIIButSpaceQuoteAndBackslash(t *testing.T) {
	reason := scopeCharsRefused // the literal reason, pinned once
	for r := rune(0); r <= 0x80; r++ {
		taken := r >= 0x21 && r <= 0x7e && r != '"' && r != '\\'
		scope := "a" + string(r) + "b" // inside, as a list trims an entry's white space
		t.Run(strconv.QuoteRune(r), func(t *testing.T) {
			c, err := load(t, nil, "BYWARD_SCOPE="+scope)
			want := "BYWARD_SCOPE: want one scope token, such as mcp; got a value (3 characters, not shown): " + reason
			switch {
			case taken && err != nil:
				t.Errorf("BYWARD_SCOPE=%q: %v, want it taken", scope, err)
			case taken && c.Scope != scope:
				t.Errorf("BYWARD_SCOPE=%q: got %q, want %q", scope, c.Scope, scope)
			case !taken && (!isConfigError(err) || !strings.Contains(err.Error(), want)):
				t.Errorf("BYWARD_SCOPE=%q: %v, want %q", scope, err, want)
			}
			if r == ',' { // a list's separator
				return
			}
			c, err = loadOIDC(t, with("BYWARD_OIDC_SCOPES=openid,"+scope))
			want = "BYWARD_OIDC_SCOPES: want a scope such as openid or email; got entry 2 of 2 (3 characters, not shown): " + reason
			switch {
			case taken && err != nil:
				t.Errorf("BYWARD_OIDC_SCOPES=openid,%q: %v, want it taken", scope, err)
			case taken && !slices.Contains(c.OIDCScopes, scope):
				t.Errorf("BYWARD_OIDC_SCOPES=openid,%q: got %v, want it to contain %q", scope, c.OIDCScopes, scope)
			case !taken && (!isConfigError(err) || !strings.Contains(err.Error(), want)):
				t.Errorf("BYWARD_OIDC_SCOPES=openid,%q: %v, want %q", scope, err, want)
			}
		})
	}
}
