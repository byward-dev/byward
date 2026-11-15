package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// emptyFile and blankFile are secret files with nothing in them but line ends or whitespace.
const (
	emptyFile = "/run/secrets/empty"
	blankFile = "/run/secrets/blank"
)

// filesWithEmpties serves base's, the OIDC base's and the DSN files, plus an empty and a blank one.
func filesWithEmpties(p string) ([]byte, error) {
	switch p {
	case emptyFile:
		return []byte("\r\n"), nil
	case blankFile:
		return []byte(" \t\n"), nil
	case dsnFile:
		return []byte(pgDSN), nil
	case "/run/secrets/entra":
		return baseFiles(p)
	}
	return oidcFiles(p)
}

// A file named for a secret is given even when it holds nothing (or only whitespace): it is refused,
// naming the setting as the operator gave it, and never stands in for "not set", where it would select
// the SQLite store or leave another credential as the one in use.
func TestANamedSecretFileThatIsEmptyIsRefusedNotTakenAsUnset(t *testing.T) {
	entraWithout := func(extra ...string) []string { return withoutSecret(extra...) }
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
			want: "BYWARD_STORE_POSTGRES_DSN_FILE: the file is empty"},
		{name: "an empty DSN file given as a flag", args: []string{"--store-postgres-dsn-file=" + emptyFile}, env: slices.Clone(base),
			want: "--store-postgres-dsn-file: the file is empty"},
		{name: "an empty DSN file beside a state directory keeps the one-store rule", env: append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+emptyFile, "BYWARD_STORE_DIR=/var/lib/byward/state"),
			want: "BYWARD_STORE_POSTGRES_DSN_FILE: the file is empty; BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_DIR: give one store, PostgreSQL or a SQLite state directory, not both"},
		{name: "an empty Entra secret file", env: entraWithout("BYWARD_ENTRA_CLIENT_SECRET_FILE=" + emptyFile),
			want: "BYWARD_ENTRA_CLIENT_SECRET_FILE: the file is empty"},
		{name: "an empty Entra certificate file alone", env: entraWithout("BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=" + emptyFile),
			want: "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the file is empty"},
		{name: "an empty Entra certificate file beside a secret", env: append(slices.Clone(base), "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+emptyFile),
			want: "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the file is empty; BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE and BYWARD_ENTRA_CLIENT_SECRET_FILE are set together: Entra gets one credential, so keep only one of them"},
		{name: "an empty Entra certificate file keeps the certificate's expiry rule", env: entraWithout("BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+emptyFile, "BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT=2027-11-06"),
			want: "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: the file is empty; BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT has no effect with BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: byward reads the certificate's own end date; remove it"},
		{name: "an empty OIDC secret file", env: oidc(with("BYWARD_OIDC_CLIENT_SECRET_FILE=" + emptyFile)),
			want: "BYWARD_OIDC_CLIENT_SECRET_FILE: the file is empty"},
		{name: "an empty OIDC key file beside a secret", env: oidc(with("BYWARD_OIDC_CLIENT_KEY_FILE=" + emptyFile)),
			want: "BYWARD_OIDC_CLIENT_KEY_FILE: the file is empty; BYWARD_OIDC_CLIENT_SECRET_FILE and BYWARD_OIDC_CLIENT_KEY_FILE are both set; give one of them"},
		{name: "an empty OIDC key file with its key ID and algorithm", env: oidc(func(env []string) []string {
			return with("BYWARD_OIDC_CLIENT_KEY_FILE="+emptyFile, "BYWARD_OIDC_CLIENT_KEY_ID=k1", "BYWARD_OIDC_CLIENT_KEY_ALG=RS256")(without("BYWARD_OIDC_CLIENT_SECRET_FILE")(env))
		}), want: "BYWARD_OIDC_CLIENT_KEY_FILE: the file is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(tc.args, tc.env, filesWithEmpties)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v\nwant %s", err, tc.want)
			}
		})
	}
}

// What is not a named file stays as it was: an empty _FILE variable names no file, and a DSN file
// with a connection string selects PostgreSQL.
func TestASecretFileSettingGivenEmptyNamesNoFile(t *testing.T) {
	c, _, err := Load(nil, append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE=", "BYWARD_OIDC_CLIENT_KEY_FILE="), filesWithEmpties)
	if err != nil || c.StorePostgresDSN != "" {
		t.Fatalf("err %v, DSN %q: an empty _FILE variable must leave the SQLite store", err, c.StorePostgresDSN)
	}
	c, _, err = Load(nil, append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile), filesWithEmpties)
	if err != nil || c.StorePostgresDSN != pgDSN {
		t.Fatalf("err %v, DSN set %v: a DSN file selects PostgreSQL", err, c.StorePostgresDSN != "")
	}
}

// BYWARD_ALLOWED_ORIGINS holds origins as browsers send them (RFC 6454 §6.2): the scheme's default
// port is dropped, as the public URL's origin drops it, so the entry matches; and the host[:port] gets
// BYWARD_ALLOWED_HOSTS's rule, so an entry no browser could send is refused.
func TestAllowedOriginsAreStoredAsBrowsersSendThem(t *testing.T) {
	c, err := load(t, nil, "BYWARD_ALLOWED_ORIGINS=https://App.example.com:443, http://app.example.com:80, http://app.example.com:443, https://[2001:DB8::1]:443, https://app.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://app.example.com", "http://app.example.com", "http://app.example.com:443", "https://[2001:db8::1]", "https://app.example.com:8443"}
	if !slices.Equal(c.AllowedOrigins, want) {
		t.Fatalf("origins %q, want %q", c.AllowedOrigins, want)
	}
	for origin, why := range map[string]string{
		"https://app.example.com:0443":  "a leading zero",
		"https://app.example.com:99999": "a port past 65535",
		"https://app.example.com:0":     "port 0",
		"https://app.example.com:":      "an empty port",
		"https://a..b":                  "an empty label",
		"https://.app.example.com":      "a leading dot",
		"https://app.example.com.":      "a trailing dot",
		"https://[fe80::1%25eth0]":      "an IPv6 zone",
	} {
		_, err := load(t, nil, "BYWARD_ALLOWED_ORIGINS="+origin)
		if err == nil || !strings.HasPrefix(err.Error(), "BYWARD_ALLOWED_ORIGINS: ") || !strings.Contains(err.Error(), "host[:port]") {
			t.Errorf("%s (%s): err = %v, want a BYWARD_ALLOWED_ORIGINS host[:port] refusal", origin, why, err)
		}
	}
}

// An IPv4-mapped prefix in BYWARD_TRUSTED_PROXIES is the IPv4 prefix it maps, since peers are compared
// unmapped; one shorter than /96 maps no IPv4 address (and would mask to an IPv6 range), so it is
// refused.
func TestTrustedProxiesTakeAnIPv4MappedPrefixAsIPv4(t *testing.T) {
	cfg, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES=::ffff:10.0.0.5/128, ::ffff:10.0.0.0/104, ::ffff:0:0/96"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(cfg.TrustedProxies), "[10.0.0.5/32 10.0.0.0/8 0.0.0.0/0]"; got != want {
		t.Fatalf("trusted proxies = %s, want %s", got, want)
	}
	for _, p := range []string{"::ffff:10.0.0.0/8", "::ffff:10.0.0.0/95"} {
		want := fmt.Sprintf("BYWARD_TRUSTED_PROXIES: %q is an IPv4-mapped prefix shorter than /96, which covers no IPv4 address; give it as IPv4, e.g. 10.0.0.0/8", p)
		if _, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES="+p), nil); err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %s", p, err, want)
		}
	}
}
