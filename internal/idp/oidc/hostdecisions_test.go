package oidc

import (
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// An endpoint an IdP's discovery document names is decided for every host family as pinned in
// testdata/hostdecisions.golden, and passes only the inputs in testdata/hostdecisions.allowed, so a
// discovery check that takes a new form fails by name (#656): with an https issuer, and in
// development mode with a loopback http one; and the issuer as the adapter takes it.
func TestEveryOIDCHostCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
	judge := func(issuer string, dev bool) func(string) (bool, string) {
		return func(in string) (bool, string) {
			if err := checkURL(in, issuer, dev); err != nil {
				return false, strings.TrimPrefix(err.Error(), logging.URL(in)+" ")
			}
			return true, ""
		}
	}
	endpoints := hostfamilies.URLProbes("/token", "https", "http")
	hostfamilies.Run(t, "internal/idp/oidc", []hostfamilies.Column{
		{Name: "IdP endpoint", Probes: endpoints, Judge: judge("https://idp.example.com/realms/a", false)},
		{Name: "IdP endpoint, --dev", Probes: endpoints, Judge: judge("http://127.0.0.1:8080/realms/a", true)},
		// The issuer itself, as New takes it outside development mode: config's parseIssuer (column
		// "oidc-issuer") refuses the other forms first, so this records the adapter's own rule outside
		// --dev: https only, so an http issuer, loopback included, is refused.
		{Name: "IdP issuer", Probes: hostfamilies.URLProbes("/realms/a", "https", "http"), Judge: func(in string) (bool, string) {
			if _, err := New(Config{Issuer: in, ClientID: "c", RedirectURL: "https://mcp.example.com/callback/oidc"}); err != nil {
				return false, strings.TrimPrefix(err.Error(), "oidc: issuer: "+logging.URL(in)+" ")
			}
			return true, ""
		}},
	})
}
