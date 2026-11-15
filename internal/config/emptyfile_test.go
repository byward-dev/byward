package config

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// emptyFile and blankFile are secret files with nothing in them but line ends, or only whitespace.
const (
	emptyFile = "/run/secrets/empty"
	blankFile = "/run/secrets/blank"
)

// filesPlusEmptyAndBlank serves the test's own secret files and nothing from the disk: base's, the
// OIDC base's, the DSN file and the empty and blank ones.
func filesPlusEmptyAndBlank(p string) ([]byte, error) {
	switch p {
	case emptyFile:
		return []byte("\r\n"), nil
	case blankFile:
		return []byte(" \t\n"), nil
	case dsnFile:
		return []byte(pgDSN), nil
	case "/run/secrets/oidc":
		return []byte("s3cret-oidc\n"), nil
	case "/run/secrets/entra":
		return baseFiles(p)
	}
	return nil, os.ErrNotExist
}

// A file named for a secret is given even when it holds nothing (or only whitespace): it is refused,
// naming the setting as the operator gave it, and never stands in for "not set", where it would select
// the SQLite store or leave another credential as the one in use.
func TestANamedSecretFileThatIsEmptyIsRefusedNotTakenAsUnset(t *testing.T) {
	oidc := func(change func([]string) []string) []string { return change(slices.Clone(oidcBase)) }
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want string // the whole error
	}{
		{name: "an empty DSN file", env: append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+emptyFile),
			want: "BYWARD_STORE_POSTGRES_DSN_FILE: the file is empty"},
		{name: "a blank DSN file", env: append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+blankFile),
			want: "BYWARD_STORE_POSTGRES_DSN_FILE: the file holds only whitespace"},
		{name: "an empty DSN file given as a flag", args: []string{"--store-postgres-dsn-file=" + emptyFile}, env: slices.Clone(base),
			want: "--store-postgres-dsn-file: the file is empty"},
		{name: "an empty DSN file beside a state directory keeps the one-store rule", env: append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+emptyFile, "BYWARD_STORE_DIR=/var/lib/byward/state"),
			want: "BYWARD_STORE_POSTGRES_DSN_FILE: the file is empty; BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_DIR: give one store, PostgreSQL or a SQLite state directory, not both"},
		{name: "an empty Entra secret file", env: withoutSecret("BYWARD_ENTRA_CLIENT_SECRET_FILE=" + emptyFile),
			want: "BYWARD_ENTRA_CLIENT_SECRET_FILE: the file is empty"},
		{name: "an empty Entra certificate file alone", env: withoutSecret("BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=" + emptyFile),
			want: "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the file is empty"},
		{name: "an empty Entra certificate file beside a secret", env: append(slices.Clone(base), "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+emptyFile),
			want: "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the file is empty; BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE and BYWARD_ENTRA_CLIENT_SECRET_FILE are set together: Entra gets one credential, so keep only one of them"},
		{name: "an empty Entra certificate file keeps the certificate's expiry rule", env: withoutSecret("BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+emptyFile, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=2027-11-06"),
			want: "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the file is empty; BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT has no effect with BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: byward reads the certificate's own end date; remove it"},
		{name: "an empty OIDC secret file", env: oidc(with("BYWARD_OIDC_CLIENT_SECRET_FILE=" + emptyFile)),
			want: "BYWARD_OIDC_CLIENT_SECRET_FILE: the file is empty"},
		{name: "an empty OIDC key file beside a secret", env: oidc(with("BYWARD_OIDC_CLIENT_KEY_FILE=" + emptyFile)),
			want: "BYWARD_OIDC_CLIENT_KEY_FILE: the file is empty; BYWARD_OIDC_CLIENT_SECRET_FILE and BYWARD_OIDC_CLIENT_KEY_FILE are both set; give one of them"},
		{name: "an empty OIDC key file is still the key for its key ID and algorithm", env: oidc(func(env []string) []string {
			return with("BYWARD_OIDC_CLIENT_KEY_FILE="+emptyFile, "BYWARD_OIDC_CLIENT_KEY_ID=k1", "BYWARD_OIDC_CLIENT_KEY_ALG=RS256")(without("BYWARD_OIDC_CLIENT_SECRET_FILE")(env))
		}), want: "BYWARD_OIDC_CLIENT_KEY_FILE: the file is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(tc.args, tc.env, filesPlusEmptyAndBlank)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v\nwant %s", err, tc.want)
			}
		})
	}
}

// emptyFileContext is, for each secret setting, a configuration in which config reads it, so that an
// empty file named for it is checked. A new secret setting must be added here.
var emptyFileContext = map[string]func() []string{
	"upstream-credential":      func() []string { return slices.Clone(base) },
	"entra-client-secret":      func() []string { return withoutSecret() },
	"entra-client-certificate": func() []string { return withoutSecret() },
	"oidc-client-secret":       func() []string { return without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase)) },
	"oidc-client-key":          func() []string { return without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase)) },
	"store-postgres-dsn":       func() []string { return slices.Clone(base) },
}

// emptyFileAllowed are the secret settings whose empty file is accepted, and why.
var emptyFileAllowed = map[string]string{
	"upstream-env": "an empty environment file passes no variables to a stdio upstream; whether to refuse it is open (PR #442)",
}

// Every secret setting refuses a named file that is empty, unless emptyFileAllowed says why not, so a
// new one cannot quietly read it as "not set".
func TestEverySecretSettingRefusesANamedFileThatIsEmpty(t *testing.T) {
	for _, names := range []map[string]bool{keysOf(emptyFileContext), keysOf(emptyFileAllowed)} {
		for name := range names {
			if s, ok := settingNamed(name); !ok || !s.Secret {
				t.Errorf("%s is listed for the empty-file rule but is not a secret setting", name)
			}
		}
	}
	for _, s := range registry {
		if !s.Secret {
			continue
		}
		if why, ok := emptyFileAllowed[s.Name]; ok {
			t.Logf("%s: an empty file is accepted: %s", s.Env(), why)
			continue
		}
		context, ok := emptyFileContext[s.Name]
		if !ok {
			t.Errorf("%s is a secret setting: add a configuration that reads it to emptyFileContext, or the reason its empty file is accepted to emptyFileAllowed", s.Env())
			continue
		}
		_, _, err := Load(nil, append(context(), s.Env()+"_FILE="+emptyFile), filesPlusEmptyAndBlank)
		if want := s.Env() + "_FILE: the file is empty"; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", s.Env(), err, want)
		}
	}
}

// A _FILE variable set to nothing names no file: the setting is not given, as when it is absent.
func TestAnEmptyFileVariableNamesNoFile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   []string
		check func(*Config) bool
	}{
		{"the DSN, so the SQLite store", append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="), func(c *Config) bool { return c.StorePostgresDSN == "" }},
		{"the Entra certificate, so the secret", append(slices.Clone(base), "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="), func(c *Config) bool { return c.EntraClientSecret == "s3cret-entra" }},
		{"the OIDC key, so the secret", append(slices.Clone(oidcBase), "BYWARD_OIDC_CLIENT_KEY_FILE="),
			func(c *Config) bool { return c.OIDCClientSecret == "s3cret-oidc" && c.OIDCClientKey == "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, err := Load(nil, tc.env, filesPlusEmptyAndBlank)
			if err != nil {
				t.Fatalf("an empty _FILE variable must load as not given: %v", err)
			}
			if !tc.check(c) {
				t.Fatalf("the setting was taken as given")
			}
		})
	}
}

// With --dev a secret may be given inline: it is given as a file is, so the rules about which store and
// which credential still apply.
func TestAnInlineSecretUnderDevIsGivenAsAFileIs(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"an inline DSN beside a state directory", append(slices.Clone(base), "BYWARD_DEV=true", "BYWARD_STORE_POSTGRES_DSN=postgres://u@h/db", "BYWARD_STORE_DIR=/var/lib/byward/state"),
			"give one store, PostgreSQL or a SQLite state directory, not both"},
		{"an inline certificate with a secret expiry", withoutSecret("BYWARD_DEV=true", "BYWARD_ENTRA_CLIENT_CERTIFICATE=-----BEGIN", "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=2027-11-06"),
			"byward reads the certificate's own end date"},
		{"an inline Entra secret beside a federated token", withoutSecret("BYWARD_DEV=true", "BYWARD_ENTRA_CLIENT_SECRET=s3cret", "BYWARD_ENTRA_FEDERATED_TOKEN_FILE=/var/run/secrets/azure/tokens/azure-identity-token"),
			"are set together: Entra gets one credential"},
		{"an inline OIDC key beside a secret file", append(slices.Clone(oidcBase), "BYWARD_DEV=true", "BYWARD_OIDC_CLIENT_KEY=-----BEGIN"),
			"are both set; give one of them"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(nil, tc.env, filesPlusEmptyAndBlank); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func keysOf[V any](m map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func settingNamed(name string) (Setting, bool) {
	for _, s := range registry {
		if s.Name == name {
			return s, true
		}
	}
	return Setting{}, false
}
