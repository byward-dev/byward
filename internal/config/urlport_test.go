package config

import (
	"fmt"
	"testing"
	"unicode/utf8"
)

// urlSettings are the settings read as an http(s) URL (parseHTTPURL), each with a URL whose port is %s
// (written with its colon), one with a port and no host, and its refusal up to its length (got) and
// after its reason (after). The client denylist is not one: its CIMD client IDs are registration's.
var urlSettings = []struct {
	env, url, noHost, got, after string
	load                         func(*testing.T) func(kv ...string) error
}{
	{"BYWARD_PUBLIC_URL", "https://mcp.example.com%s/mcp", "https://:8443/mcp", wantPublicAsURL, "", withConfig},
	{"BYWARD_UPSTREAM_URL", "http://127.0.0.1%s/mcp", "http://:9000/mcp", "BYWARD_UPSTREAM_URL: want an absolute http(s) URL such as http://127.0.0.1:9000/mcp; got a value ",
		" (or BYWARD_UPSTREAM_COMMAND, or a command after --)", withConfig},
	{"BYWARD_RESOURCE_DOCUMENTATION", "https://docs.example.com%s/x", "https://:443/x", "BYWARD_RESOURCE_DOCUMENTATION: want an absolute http(s) URL such as https://docs.example.com/mcp; got a value ", "", withConfig},
	{"BYWARD_OIDC_ISSUER", "https://idp.example.com%s/realms/x", "https://:443/realms/x", "BYWARD_OIDC_ISSUER: want the issuer URL, exactly as the IdP's discovery document states it, such as https://idp.example.com/realms/mcp; got a value ", "", withOIDC},
	{"BYWARD_ALLOWED_ORIGINS", "https://app.example.com%s", "https://:8443", wantOrigins, "", withConfig},
}

// Every http(s) URL setting refuses a port with no host before it, such as http://:9000/mcp (#614): a
// setting names the host it means, where a dialer would read the empty host as this one, and an
// issuer so written never matches what an IdP publishes. The value is never shown. (The order of
// this reason among the others: TestAURLRefusedForItsFormSaysWhichPartIsWrong.)
func TestEveryURLSettingRefusesAPortWithNoHost(t *testing.T) {
	for _, s := range urlSettings {
		t.Run(s.env, func(t *testing.T) {
			want := fmt.Sprintf("%s(%d characters, not shown): it has no host before its port%s", s.got, utf8.RuneCountInString(s.noHost), s.after)
			if err := s.load(t)(s.env + "=" + s.noHost); !isConfigError(err) || err.Error() != want {
				t.Fatalf("err = %v\nwant %s", err, want)
			}
		})
	}
}

// Every URL setting takes a port from 1 to 65535 as written, without a sign or leading zero (#602):
// url.Parse checks only that a port is digits, so :0, :08080 and :99999 parsed, and failed only at the
// first request, at OIDC discovery, or never. A refused port is never shown. (The allowed hosts:
// TestAURLOrHostRefusedForItsFormSaysWhereAndWhyNeverWhat; the listen addresses, which take 0:
// TestAListenAddressIsHostColonANumericPortAndARefusedOneIsNeverShown; the client denylist, whose
// CIMD client IDs take port 443 only, refused at startup: internal/server's
// TestABadDenylistEntryRefusesToStartNamingTheSetting.)
func TestEveryURLSettingTakesAPortFrom1To65535Only(t *testing.T) {
	for _, s := range urlSettings {
		// A middle port that is no scheme's default: the public URL refuses its scheme's default port
		// (#522, pinned in TestPublicURLAcceptsHTTPSOrLoopbackAndNamesTheRuleABadOneBreaks).
		for _, p := range []struct{ name, port string }{{"no port", ""}, {"port 1", ":1"}, {"port 8443", ":8443"}, {"port 65535", ":65535"}} {
			t.Run(s.env+" takes "+p.name, func(t *testing.T) {
				if err := s.load(t)(s.env + "=" + fmt.Sprintf(s.url, p.port)); err != nil {
					t.Fatalf("%v; want it taken", err)
				}
			})
		}
		for _, p := range []struct{ name, port string }{
			{"port 0", ":0"}, {"port 65536", ":65536"}, {"port 99999", ":99999"}, {"a leading zero", ":08080"}, {"an empty port", ":"},
		} {
			t.Run(s.env+" refuses "+p.name, func(t *testing.T) {
				raw := fmt.Sprintf(s.url, p.port)
				want := fmt.Sprintf("%s(%d characters, not shown): it %s%s", s.got, utf8.RuneCountInString(raw), rulePort, s.after)
				if err := s.load(t)(s.env + "=" + raw); !isConfigError(err) || err.Error() != want {
					t.Fatalf("err = %v\nwant %s", err, want)
				}
			})
		}
	}
}
