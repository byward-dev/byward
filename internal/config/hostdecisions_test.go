package config

import (
	"errors"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// Each host and URL setting's decision on every host family is pinned in testdata/hostdecisions.golden,
// and the inputs a setting takes in testdata/hostdecisions.allowed, so a setting that takes a new
// form fails by name (#656). The messages are hostrule.golden's.
func TestEveryHostSettingDecidesEveryHostFamilyAsPinned(t *testing.T) {
	one := func(name string, parse func(Value) error) func(string) (bool, string) {
		return func(in string) (bool, string) {
			if err := parse(Value{Setting: lookup(name), Given: NewOpaque(in)}); err != nil {
				return false, hostfamilies.Reason(err.Error())
			}
			return true, ""
		}
	}
	list := func(parse func(Value) ([]string, []error)) func(Value) error {
		return func(v Value) error { _, errs := parse(v); return errors.Join(errs...) }
	}
	single := func(parse func(Value) (string, error)) func(Value) error {
		return func(v Value) error { _, err := parse(v); return err }
	}
	https, both := hostfamilies.URLProbes("/mcp", "https"), hostfamilies.URLProbes("/mcp", "https", "http")
	hosts := hostfamilies.HostProbes()
	listen := func(want string) func(Value) error {
		return func(v Value) error { _, err := parseListen(v, want); return err }
	}
	hostfamilies.Run(t, "internal/config", []hostfamilies.Column{
		{Name: "public-url", Probes: both, Judge: one("public-url", func(v Value) error { _, err := parsePublicURL(v); return err })},
		{Name: "upstream-url", Probes: both, Judge: one("upstream-url", func(v Value) error { _, err := parseUpstreamURL(v); return err })},
		{Name: "resource-documentation", Probes: https, Judge: one("resource-documentation", single(parseResourceDocumentation))},
		{Name: "oidc-issuer", Probes: https, Judge: one("oidc-issuer", single(parseIssuer))},
		{Name: "allowed-origins", Probes: hostfamilies.URLProbes("", "https", "http"), Judge: one("allowed-origins", list(parseOrigins))},
		{Name: "allowed-hosts", Probes: hosts, Judge: one("allowed-hosts", list(parseAllowedHosts))},
		{Name: "cimd-trusted-hosts", Probes: hosts, Judge: one("cimd-trusted-hosts", list(parseCIMDHosts))},
		{Name: "cimd-allowed-hosts", Probes: hosts, Judge: one("cimd-allowed-hosts", list(parseCIMDHosts))},
		{Name: "client-denylist host", Probes: hosts, Judge: one("client-denylist", list(parseClientDenylist))},
		// Config refuses only a client ID that can carry a credential, or a zone; registration's
		// "denylist entry" column judges the rest of the URL.
		{Name: "client-denylist client ID", Probes: hostfamilies.Only(hostfamilies.URLProbes("/client.json", "https"), "url shape", "zone"), Judge: one("client-denylist", list(parseClientDenylist))},
		{Name: "listen", Probes: hosts, Judge: one("listen", listen("host:port such as 127.0.0.1:8080"))},
		{Name: "internal-listen", Probes: hosts, Judge: one("internal-listen", listen("host:port such as 127.0.0.1:9090, or empty"))},
	})
}
