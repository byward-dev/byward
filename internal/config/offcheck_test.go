package config

import (
	"slices"
	"strings"
	"testing"
)

// offCheckGUID stands in for a tenant or client ID: the all-zero form the fixtures use.
const offCheckGUID = "00000000-0000-0000-0000-000000000009"

// Every off check names each setting as the operator gave it: the flag, the file flag, or the
// environment variable (#607). Before, the app-only, On-Behalf-Of, store, no-auth and mixed-IdP
// checks always printed the environment variable, so --store-dir beside PostgreSQL was refused with
// "BYWARD_STORE_DIR", a name the operator never used. Each check is pinned once with a flag and
// once with its variable.
func TestAnOffCheckNamesTheSettingAsTheOperatorGaveIt(t *testing.T) {
	const dsnFile = "/run/secrets/postgres-dsn"
	files := func(p string) ([]byte, error) {
		if p == dsnFile {
			return []byte("postgres://store@db/byward"), nil
		}
		return baseFiles(p)
	}
	// An OIDC IdP with nothing else that would refuse: base sets the Entra family, which an OIDC
	// IdP refuses for its own reason.
	oidc := []string{
		"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp",
		"BYWARD_UPSTREAM_URL=http://upstream:9000/mcp",
		"BYWARD_IDP=oidc",
		"BYWARD_OIDC_ISSUER=https://idp.example.com",
	}
	// --insecure-no-auth, fenced in: a loopback URL, and one auth setting beside it.
	noAuth := []string{
		"BYWARD_INSECURE_NO_AUTH=true",
		"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp",
		"BYWARD_UPSTREAM_URL=http://u/mcp",
	}
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string // beside base, or stdioBase when stdio is set; a case with baseNil replaces it
		base  []string
		stdio bool
		want  string
		// not is the old spelling this refusal must not use any more, given as a flag. It is the whole
		// pair, not the bare variable: another check may name the same variable for its own reason.
		not string
	}{
		{name: "the app-only roles as a flag", args: []string{"--app-roles=reader"},
			want: "--app-roles set while BYWARD_APP_TOKENS=off", not: "BYWARD_APP_ROLES"},
		{name: "the app-only roles as a variable", env: []string{"BYWARD_APP_ROLES=reader"},
			want: "BYWARD_APP_ROLES set while BYWARD_APP_TOKENS=off"},
		{name: "the app-only client IDs as a flag", args: []string{"--app-client-ids=" + offCheckGUID},
			want: "--app-client-ids set while BYWARD_APP_TOKENS=off", not: "BYWARD_APP_CLIENT_IDS"},
		{name: "the app-only client IDs as a variable", env: []string{"BYWARD_APP_CLIENT_IDS=" + offCheckGUID},
			want: "BYWARD_APP_CLIENT_IDS set while BYWARD_APP_TOKENS=off"},
		{name: "the On-Behalf-Of header as a flag with stdio", stdio: true, args: []string{"--obo-header=X-Graph-Token"},
			want: "--obo-header: a stdio upstream gets its downstream token", not: "BYWARD_OBO_HEADER"},
		{name: "the On-Behalf-Of header as a variable with stdio", stdio: true, env: []string{"BYWARD_OBO_HEADER=X-Graph-Token"},
			want: "BYWARD_OBO_HEADER: a stdio upstream gets its downstream token"},
		{name: "a state directory as a flag beside PostgreSQL", args: []string{"--store-dir=/var/lib/byward"},
			env:  []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + dsnFile},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE and --store-dir: give one store", not: "BYWARD_STORE_DIR: give one store"},
		{name: "a state directory as a variable beside PostgreSQL", env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + dsnFile, "BYWARD_STORE_DIR=/var/lib/byward"},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_DIR: give one store"},
		{name: "a state directory as a variable beside a PostgreSQL file flag", args: []string{"--store-postgres-dsn-file=" + dsnFile},
			env:  []string{"BYWARD_STORE_DIR=/var/lib/byward"},
			want: "--store-postgres-dsn-file and BYWARD_STORE_DIR: give one store", not: "BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_DIR"},
		{name: "a counter file as a flag beside PostgreSQL", args: []string{"--store-counter-file=/var/lib/byward/counter.db"},
			env:  []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + dsnFile},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE and --store-counter-file: the counter file belongs to the SQLite store", not: "BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_COUNTER_FILE"},
		{name: "a counter file as a variable beside PostgreSQL", env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + dsnFile, "BYWARD_STORE_COUNTER_FILE=/var/lib/byward/counter.db"},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_COUNTER_FILE: the counter file belongs to the SQLite store"},
		{name: "the Entra tenant as a flag beside --insecure-no-auth", base: noAuth, args: []string{"--entra-tenant=" + offCheckGUID},
			want: "BYWARD_INSECURE_NO_AUTH cannot be combined with --entra-tenant", not: "with BYWARD_ENTRA_TENANT"},
		{name: "the Entra tenant as a variable beside --insecure-no-auth", base: noAuth, env: []string{"BYWARD_ENTRA_TENANT=" + offCheckGUID},
			want: "BYWARD_INSECURE_NO_AUTH cannot be combined with BYWARD_ENTRA_TENANT"},
		{name: "an Entra setting as a flag with an OIDC IdP", base: oidc, args: []string{"--entra-tenant=" + offCheckGUID},
			want: "--entra-tenant cannot be used with BYWARD_IDP=oidc", not: "BYWARD_ENTRA_TENANT cannot be used"},
		{name: "an Entra setting as a variable with an OIDC IdP", base: oidc, env: []string{"BYWARD_ENTRA_TENANT=" + offCheckGUID},
			want: "BYWARD_ENTRA_TENANT cannot be used with BYWARD_IDP=oidc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(slices.Clone(base), tc.env...)
			switch {
			case tc.base != nil:
				env = append(slices.Clone(tc.base), tc.env...)
			case tc.stdio:
				env = stdioBase(append([]string{stdioCommand}, tc.env...)...)
			}
			_, _, err := Load(tc.args, env, files)
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a config error containing %q", err, tc.want)
			}
			if tc.not != "" && strings.Contains(err.Error(), tc.not) { // it names the flag and the variable too
				t.Fatalf("err = %v, want no %q: the setting was given as a flag", err, tc.not)
			}
		})
	}
}
