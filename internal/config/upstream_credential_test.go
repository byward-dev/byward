package config

import (
	"strings"
	"testing"
)

const credFile = "/run/secrets/upstream"

// loadCred loads base plus env, with credFile holding cred.
func loadCred(t *testing.T, args []string, cred string, env ...string) (*Config, error) {
	t.Helper()
	files := func(p string) ([]byte, error) {
		if p == credFile {
			return []byte(cred), nil
		}
		return baseFiles(p)
	}
	c, _, err := Load(args, append(append([]string{}, base...), env...), files)
	return c, err
}

func TestNoUpstreamCredentialByDefault(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.UpstreamCredential != "" || c.UpstreamCredentialHeader != "" {
		t.Fatalf("credential %q in %q", c.UpstreamCredential, c.UpstreamCredentialHeader)
	}
}

// neverShown fails the test if any setting, as --print-config and the startup log show it, contains
// the credential.
func neverShown(t *testing.T, c *Config) {
	t.Helper()
	for _, v := range c.Values.Effective() {
		if strings.Contains(v.Display(), "k-123") {
			t.Fatalf("%s shows the credential", v.Setting.Env())
		}
	}
}

// The file fills the header the operator chose (Authorization by default, beside an assertion
// moved elsewhere), without its trailing newline; a tab inside the value is allowed, as in any
// header value; and the effective configuration never shows it.
func TestTheUpstreamCredentialFileFillsTheChosenHeaderAndIsRedacted(t *testing.T) {
	for _, tc := range []struct {
		name, cred, want, wantHeader string
		env                          []string
	}{
		{"in Authorization, the assertion moved", "Bearer k-123\n", "Bearer k-123", "Authorization", []string{"BYWARD_ASSERTION_HEADER=X-Byward-Identity"}},
		{"in a header of its own", "k-123\n", "k-123", "X-Api-Key", []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=x-api-key"}},
		{"with a tab inside", "k-123\tv2", "k-123\tv2", "X-Api-Key", []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := loadCred(t, nil, tc.cred, append([]string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}, tc.env...)...)
			if err != nil {
				t.Fatal(err)
			}
			if c.UpstreamCredential != tc.want || c.UpstreamCredentialHeader != tc.wantHeader {
				t.Fatalf("header %q", c.UpstreamCredentialHeader)
			}
			neverShown(t, c)
		})
	}
}

// Without authentication there is no assertion, so the credential may keep Authorization.
func TestWithoutAuthenticationTheCredentialMayUseAuthorization(t *testing.T) {
	c, _, err := Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_INSECURE_NO_AUTH=true",
		"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}, func(string) ([]byte, error) { return []byte("Bearer k-123\n"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if c.UpstreamCredential != "Bearer k-123" || c.UpstreamCredentialHeader != "Authorization" {
		t.Fatalf("header %q", c.UpstreamCredentialHeader)
	}
	neverShown(t, c)
}

// What cannot work refuses to start, and no error shows the credential.
func TestUpstreamCredentialSettingsRefuseWhatCannotWork(t *testing.T) {
	file := "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile
	for _, tc := range []struct {
		name  string
		cred  string
		env   []string
		inErr string
	}{
		{"the default header, where the assertion is too", "k-123", []string{file},
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER and BYWARD_ASSERTION_HEADER are both Authorization, but the credential and the identity assertion never share a header (ADR-0016 §7): set BYWARD_ASSERTION_HEADER"},
		{"the assertion's header in another spelling", "k-123", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X_Byward_Identity", "BYWARD_ASSERTION_HEADER=X-Byward-Identity"},
			"are both X_byward_identity"},
		{"a header without a credential", "", []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER is set, but there is no credential: set BYWARD_UPSTREAM_CREDENTIAL_FILE too"},
		{"a reserved header", "k-123", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=Cookie"},
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER: Cookie is a header the proxy, the transport or MCP relies on"},
		{"not a header name", "k-123", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X Api Key"},
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER: want a header name"},
		{"an empty file", "\n", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"BYWARD_UPSTREAM_CREDENTIAL_FILE: the file is empty"},
		{"two lines", "k-123\nk-456", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"one header value on one line, without control characters"},
		{"a DEL character", "k-123\x7f", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"one header value on one line, without control characters"},
		{"surrounding white space", " k-123", []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"the credential starts or ends with white space"},
		{"too long", "k-123" + strings.Repeat("k", maxUpstreamCredential-4), []string{file, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"the credential is longer than 4096 bytes"},
		{"a credential set inline, not from a file", "", []string{"BYWARD_UPSTREAM_CREDENTIAL=k-123", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"},
			"secrets must come from a file (BYWARD_UPSTREAM_CREDENTIAL_FILE)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadCred(t, nil, tc.cred, tc.env...)
			if err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
			if strings.Contains(err.Error(), "k-123") {
				t.Fatalf("the error shows the credential: %v", err)
			}
		})
	}
}

// A stdio upstream gets its credentials in its environment; this setting would do nothing there.
func TestTheUpstreamCredentialIsRefusedForAStdioUpstream(t *testing.T) {
	env := []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001",
		"BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002", "BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra",
		"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}
	files := func(p string) ([]byte, error) {
		if p == credFile {
			return []byte("k-123"), nil
		}
		return baseFiles(p)
	}
	_, _, err := Load([]string{"--", "/usr/local/bin/server"}, env, files)
	if err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE") {
		t.Fatalf("err = %v", err)
	}
}
