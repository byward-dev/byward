package config

import (
	"slices"
	"testing"
)

// A URL cannot carry an IPv6 zone (#644): the five URL settings read through urlReason (the public URL,
// the upstream URL, the resource documentation, the OIDC issuer and the allowed origins) refuse one
// with one reason, named as the operator gave it, by env and by flag, and show the value by its length.
func TestEachURLSettingRefusesAnIPv6ZoneWithOneReason(t *testing.T) {
	const zone = "it has an IPv6 zone, which a URL cannot carry; give the address without its %zone"
	for _, tc := range []struct {
		name, setting, value string
		base                 []string
		env, flag            string // the whole refusal, by env and by flag
	}{
		{"the public URL", "public-url", "https://[fe80::1%25eth0]/mcp", without("BYWARD_PUBLIC_URL")(slices.Clone(base)),
			"BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (28 characters, not shown): " + zone,
			"--public-url: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (28 characters, not shown): " + zone},
		{"the upstream URL", "upstream-url", "http://[fe80::1%25eth0]:9000/mcp", without("BYWARD_UPSTREAM_URL")(slices.Clone(base)),
			"BYWARD_UPSTREAM_URL: want an absolute http(s) URL such as http://127.0.0.1:9000/mcp; got a value (32 characters, not shown): " + zone + " (or BYWARD_UPSTREAM_COMMAND, or a command after --)",
			"--upstream-url: want an absolute http(s) URL such as http://127.0.0.1:9000/mcp; got a value (32 characters, not shown): " + zone + " (or BYWARD_UPSTREAM_COMMAND, or a command after --)"},
		{"the resource documentation", "resource-documentation", "https://[fe80::1%25eth0]/docs", slices.Clone(base),
			"BYWARD_RESOURCE_DOCUMENTATION: want an absolute http(s) URL such as https://docs.example.com/mcp; got a value (29 characters, not shown): " + zone,
			"--resource-documentation: want an absolute http(s) URL such as https://docs.example.com/mcp; got a value (29 characters, not shown): " + zone},
		{"the OIDC issuer", "oidc-issuer", "https://[fe80::1%25eth0]/realms/acme", without("BYWARD_OIDC_ISSUER")(slices.Clone(oidcBase)),
			"BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it, such as https://idp.example.com/realms/mcp; got a value (36 characters, not shown): " + zone,
			"--oidc-issuer: want the issuer URL, exactly as the IdP's discovery document states it, such as https://idp.example.com/realms/mcp; got a value (36 characters, not shown): " + zone},
		{"an allowed origin", "allowed-origins", "https://[fe80::1%25eth0]", slices.Clone(base),
			"BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (24 characters, not shown): " + zone,
			"--allowed-origins: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 (24 characters, not shown): " + zone},
	} {
		t.Run(tc.name+", by env", func(t *testing.T) {
			_, _, err := Load(nil, append(slices.Clone(tc.base), Setting{Name: tc.setting}.Env()+"="+tc.value), filesPlusEmptyAndBlank)
			if !isConfigError(err) || err.Error() != tc.env {
				t.Errorf("err = %v\nwant  %s", err, tc.env)
			}
		})
		t.Run(tc.name+", by flag", func(t *testing.T) {
			_, _, err := Load([]string{"--" + tc.setting + "=" + tc.value}, tc.base, filesPlusEmptyAndBlank)
			if !isConfigError(err) || err.Error() != tc.flag {
				t.Errorf("err = %v\nwant  %s", err, tc.flag)
			}
		})
	}
}
