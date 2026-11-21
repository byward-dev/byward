package config

import (
	"fmt"
	"testing"
	"unicode/utf8"
)

// Every URL setting takes a port from 1 to 65535 as written, without a sign or leading zero (#602):
// url.Parse checks only that a port is digits, so :0, :08080 and :99999 parsed, and failed only at the
// first request, at OIDC discovery, or never. A refused port is never shown. (The public URL, the
// allowed origins and hosts, and the listen addresses: TestAURLOrHostRefusedForItsFormSaysWhereAndWhyNeverWhat.)
func TestEveryURLSettingTakesAPortFrom1To65535Only(t *testing.T) {
	for _, s := range []struct {
		env, url, want, after string
		load                  func(*testing.T) func(kv ...string) error
	}{
		{"BYWARD_UPSTREAM_URL", "http://127.0.0.1%s/mcp", "an absolute http(s) URL such as http://127.0.0.1:9000/mcp", " (or BYWARD_UPSTREAM_COMMAND, or a command after --)", withConfig},
		{"BYWARD_RESOURCE_DOCUMENTATION", "https://docs.example.com%s/x", "an absolute http(s) URL such as https://docs.example.com/mcp", "", withConfig},
		{"BYWARD_OIDC_ISSUER", "https://idp.example.com%s/realms/x", "the issuer URL, exactly as the IdP's discovery document states it, such as https://idp.example.com/realms/mcp", "", withOIDC},
	} {
		for _, port := range []string{"", ":1", ":443", ":65535"} {
			t.Run(s.env+" takes "+port, func(t *testing.T) {
				if err := s.load(t)(s.env + "=" + fmt.Sprintf(s.url, port)); err != nil {
					t.Fatalf("%v; want it taken", err)
				}
			})
		}
		for _, port := range []string{":0", ":65536", ":99999", ":08080", ":"} {
			t.Run(s.env+" refuses "+port, func(t *testing.T) {
				raw := fmt.Sprintf(s.url, port)
				want := fmt.Sprintf("%s: want %s; got a value (%d characters, not shown): it has a port that is not a number from 1 to 65535 without a sign or leading zero%s",
					s.env, s.want, utf8.RuneCountInString(raw), s.after)
				if err := s.load(t)(s.env + "=" + raw); !isConfigError(err) || err.Error() != want {
					t.Fatalf("err = %v\nwant %s", err, want)
				}
			})
		}
	}
}
