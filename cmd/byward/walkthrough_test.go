package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The ten broken configurations of the blind walkthrough of #485 (ADR-0031, Consequences): what
// check --offline prints for each, pinned whole: one line, which holds what led the operator to the
// fix (#513). Each case is its walkthrough's settings over the helpers' keys and secret files.
func TestTheWalkthroughsBrokenConfigurationsSayWhatToFix(t *testing.T) {
	program, err := os.Executable() // a program that exists on every host the tests run on
	if err != nil {
		t.Fatal(err)
	}
	command, _ := json.Marshal([]string{program, "--stdio"}) // strings always marshal
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("k-123"), 0o600); err != nil {
		t.Fatal(err)
	}
	public := "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp"
	upstream := "BYWARD_UPSTREAM_URL=http://127.0.0.1:9000/mcp"
	for _, tc := range []struct {
		name string
		env  func(t *testing.T) []string
		want string
	}{
		{"01 a client secret given as the client ID", func(t *testing.T) []string {
			return append(without(authEnv(t), "BYWARD_ENTRA_CLIENT_ID="), public, upstream,
				"BYWARD_ENTRA_CLIENT_ID=Zt8Q~fAkEvAlUe.NoT-ReAl_0123456789abcdEF")
		},
			`byward: configuration error: BYWARD_ENTRA_CLIENT_ID: want the application (client) ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, App registrations, your app, Overview, Application (client) ID); got a value (40 characters, not shown): it is not a GUID`},
		{"02 a header line given as the credential's header", func(t *testing.T) []string {
			return append(authEnv(t), "BYWARD_PUBLIC_URL=https://tools.example.org/mcp", "BYWARD_UPSTREAM_URL=https://search-api.internal.example.org/mcp",
				"BYWARD_UPSTREAM_CREDENTIAL_FILE="+credential, "BYWARD_ASSERTION_HEADER=X-Byward-Identity",
				"BYWARD_UPSTREAM_CREDENTIAL_HEADER=Authorization: Bearer x")
		},
			`byward: configuration error: BYWARD_UPSTREAM_CREDENTIAL_HEADER: want a header name such as Authorization or X-Api-Key; got a value (23 characters, not shown): it holds a ":", as a header line does: give only the header's name, the part before the ":"`},
		{"03 a URL with a mistyped scheme among the allowed hosts", func(t *testing.T) []string {
			return append(authEnv(t), public, upstream, "BYWARD_LISTEN=0.0.0.0:8443",
				"BYWARD_ALLOWED_HOSTS=mcp.example.com,https;//mcp-internal.example.net,10.0.4.17:8443")
		},
			`byward: configuration error: BYWARD_ALLOWED_HOSTS: want a host[:port] such as mcp.example.com or 127.0.0.1:8080; got entry 2 of 3 (32 characters, not shown): it holds a "/" or a space; give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone`},
		{"04 a log format mistyped", func(t *testing.T) []string {
			return append(oidcAuthEnv(t), public, upstream, "BYWARD_IDP=okta",
				"BYWARD_OIDC_ISSUER=https://example.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9", "BYWARD_OIDC_CLIENT_ID=0oa1b2c3d4e5f6g7h8i9",
				"BYWARD_GATE_GROUPS=mcp-users", "BYWARD_LOG_FORMAT=jsonn")
		},
			`byward: configuration error: BYWARD_LOG_FORMAT: want json or text; got a value (5 characters, not shown): it is not one of them`},
		{"05 a duration without its unit", func(t *testing.T) []string {
			return append(authEnv(t), public, upstream, "BYWARD_UPSTREAM_HEADER_TIMEOUT=10m",
				"BYWARD_REFRESH_GRACE=30")
		},
			`byward: configuration error: BYWARD_REFRESH_GRACE: want a duration from 0s to 60s, such as 30s; got a value (2 characters, not shown): it has a number without a unit; give one of ns, us, ms, s, m or h`},
		{"06 a connection string given as its file", func(t *testing.T) []string {
			return append(without(authEnv(t), "BYWARD_STORE_DIR="), public, "BYWARD_UPSTREAM_URL=http://mcp-server:9000/mcp",
				"BYWARD_STORE_POSTGRES_DSN_FILE=postgres://byward:Fake-Pw-123@db.internal.example:5432/byward?sslmode=verify-full")
		},
			`byward: configuration error: BYWARD_STORE_POSTGRES_DSN_FILE: want the path of a file holding the secret, such as /run/secrets/store-postgres-dsn; got a value (81 characters, not shown): it cannot be read: no such file or directory; it is a relative path, read from the working directory`},
		{"07 a CIDR with a prefix longer than an address", func(t *testing.T) []string {
			return append(authEnv(t), public, upstream, "BYWARD_LISTEN=0.0.0.0:8080",
				"BYWARD_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.1.0/33,100.64.0.0/10")
		},
			`byward: configuration error: BYWARD_TRUSTED_PROXIES: want a CIDR or an IP address such as 10.0.0.0/8 or 192.0.2.1; got entry 3 of 4 (14 characters, not shown): its prefix length is longer than /32, the length of an IPv4 address`},
		{"08 a public URL with a query", func(t *testing.T) []string {
			return append(oidcAuthEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp?env=prod", upstream,
				"BYWARD_IDP=google", "BYWARD_OIDC_CLIENT_ID=123456789012-abcdefghijklmnop.apps.googleusercontent.com",
				"BYWARD_GATE_HOSTED_DOMAINS=example.com")
		},
			`byward: configuration error: BYWARD_PUBLIC_URL: want a URL without a query or fragment, such as https://mcp.example.com/mcp; got a query or fragment, not shown: remove it`},
		{"09 a tenant's domain given as its ID", func(t *testing.T) []string {
			return append(without(stdioAuthEnv(t), "BYWARD_ENTRA_TENANT="), public, "BYWARD_ENTRA_TENANT=mcpteam.onmicrosoft.com",
				"BYWARD_GATE_ROLES=MCP.User", "BYWARD_UPSTREAM_COMMAND="+string(command))
		},
			`byward: configuration error: BYWARD_ENTRA_TENANT: want the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, Overview, Tenant ID); got a value (23 characters, not shown): it is not a GUID`},
		{"10 an http issuer off loopback", func(t *testing.T) []string {
			return append(oidcAuthEnv(t), public, upstream, "BYWARD_IDP=keycloak",
				"BYWARD_OIDC_ISSUER=http://keycloak.example.net/realms/mcp", "BYWARD_OIDC_CLIENT_ID=byward-proxy", "BYWARD_GATE_ROLES=mcp-user")
		},
			`byward: configuration error: BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it, such as https://idp.example.com/realms/mcp; got http on a host that is not loopback: give https; an issuer is http only on a loopback host, with --dev`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runDone([]string{"check", "--offline"}, tc.env(t)...)
			got := strings.TrimSpace(stdout + stderr)
			if code != exitConfig || got != tc.want {
				t.Errorf("exit %d, output:\n%s\nwant exit %d and only the line %q", code, got, exitConfig, tc.want)
			}
		})
	}
}
