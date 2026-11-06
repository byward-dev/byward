package registration

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func FuzzMatchRedirect(f *testing.F) {
	for _, fx := range clientFixtures {
		for _, s := range fx.sent {
			f.Add(fx.registered[0], s)
		}
	}
	f.Add("https://a.example/cb", "https://a.example/cb#x")
	f.Add("http://[::1]/cb", "http://[::1]:1/cb")
	f.Fuzz(func(t *testing.T, registered, sent string) {
		err := MatchRedirect([]string{registered}, sent)
		var re *RedirectError
		if err != nil && !errors.As(err, &re) {
			t.Fatalf("non-RedirectError %T", err)
		}
		if err != nil {
			return
		}
		// Anything accepted is a valid redirect URI, equal to the registration or a loopback
		// variant that differs only in port.
		if ValidateRedirect(sent) != nil {
			t.Fatalf("accepted invalid %q", sent)
		}
		if sent == registered {
			return
		}
		su, _ := url.Parse(sent)
		ru, err := url.Parse(registered)
		if err != nil || su.Scheme != "http" || ru.Scheme != "http" || su.Hostname() != ru.Hostname() ||
			su.EscapedPath() != ru.EscapedPath() || su.RawQuery != ru.RawQuery || !loopbackHosts[su.Hostname()] {
			t.Fatalf("registered %q accepted %q", registered, sent)
		}
	})
}

func FuzzLoadStatic(f *testing.F) {
	f.Add(`{"clients":[{"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]}]}`)
	f.Add(`{"clients":[{"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"s"}]}`)
	f.Add(`{"clients":[{"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}}]}`)
	f.Add(`{"clients":null}`)
	f.Fuzz(func(t *testing.T, data string) {
		fs := files{"/c.json": data, "/s": goodSecret}
		reg, err := LoadStatic("/c.json", fs.read, NewMemoryJTICache(time.Now, 10))
		if err != nil {
			if strings.Contains(err.Error(), goodSecret) {
				t.Fatal("error leaks the secret")
			}
			return
		}
		sr := reg.(*StaticRegistry)
		for id, c := range sr.clients {
			if !validClientID(id) || len(c.redirects) == 0 || len(c.redirects) > MaxRedirectURIs {
				t.Fatalf("invalid client accepted: %q", id)
			}
			for _, r := range c.redirects {
				if ValidateRedirect(r) != nil {
					t.Fatalf("invalid redirect accepted: %q", r)
				}
			}
		}
	})
}
