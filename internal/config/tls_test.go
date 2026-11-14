package config

import (
	"strings"
	"testing"
)

// #183: the TLS files are both set or neither, by absolute paths, and only with an https public
// URL: clients use the public URL, so an http one, the --dev loopback one included, would reach a
// listener that speaks only TLS. The issuer keeps deriving from the public URL.
func TestTLSFilesAreBothOrNeitherAbsoluteAndNeedAnHTTPSPublicURL(t *testing.T) {
	const cert, key = "BYWARD_TLS_CERT_FILE=/run/tls/tls.crt", "BYWARD_TLS_KEY_FILE=/run/tls/tls.key"
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want string // "" when valid
	}{
		{"neither", nil, nil, ""},
		{"both", nil, []string{cert, key}, ""},
		{"only the certificate", nil, []string{cert}, "BYWARD_TLS_CERT_FILE and BYWARD_TLS_KEY_FILE: set both or neither"},
		{"only the key", nil, []string{key}, "BYWARD_TLS_CERT_FILE and BYWARD_TLS_KEY_FILE: set both or neither"},
		{"a relative certificate path", nil, []string{"BYWARD_TLS_CERT_FILE=tls.crt", key}, `BYWARD_TLS_CERT_FILE: want an absolute path, got "tls.crt"`},
		{"a relative key path", nil, []string{cert, "BYWARD_TLS_KEY_FILE=tls.key"}, `BYWARD_TLS_KEY_FILE: want an absolute path, got "tls.key"`},
		{"an http public URL in --dev", []string{"--dev"}, []string{cert, key, "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp"},
			"BYWARD_TLS_CERT_FILE: TLS on the listener needs an https BYWARD_PUBLIC_URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, tc.args, tc.env...)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if c.Issuer() != "https://mcp.example.com" {
					t.Errorf("issuer = %q, want the public URL's", c.Issuer())
				}
				return
			}
			if err == nil || !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want a configuration error with %q", err, tc.want)
			}
		})
	}
}

// #183: TLS is the listener's, so it is accepted without authentication too, on the loopback
// https URL that mode allows; an http one is refused there as well.
func TestTLSWithoutAuthenticationNeedsAnHTTPSLoopbackURL(t *testing.T) {
	tls := []string{"BYWARD_TLS_CERT_FILE=/run/tls/tls.crt", "BYWARD_TLS_KEY_FILE=/run/tls/tls.key"}
	if _, err := loadAnon(t, nil, append(tls, "BYWARD_PUBLIC_URL=https://localhost:8443/mcp")...); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAnon(t, nil, tls...); err == nil || !isConfigError(err) || !strings.Contains(err.Error(), "needs an https BYWARD_PUBLIC_URL") {
		t.Fatalf("an http loopback public URL with TLS: %v", err)
	}
}
