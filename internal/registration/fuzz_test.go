package registration

import (
	"regexp"

	"errors"
	"strings"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
)

// loopRe is an independent, string-level reading of a loopback redirect URI: host literal, then
// whatever follows the optional port.
var loopRe = regexp.MustCompile(`^http://(127\.0\.0\.1|\[::1\]|localhost)(?::[0-9]*)?([/?].*)?$`)

func FuzzMatchRedirect(f *testing.F) {
	for _, fx := range clientFixtures {
		for _, s := range fx.sent {
			f.Add(fx.registered[0], s)
		}
	}
	f.Add("https://a.example/cb", "https://a.example/cb#x")
	f.Add("http://[::1]/cb", "http://[::1]:1/cb")
	f.Add(`http://127.0.0.1/a"b`, "http://127.0.0.1:1/a%22b")
	f.Fuzz(func(t *testing.T, registered, sent string) {
		// Any-port rule (ADR-0009 §2): a valid loopback registration accepts another port.
		if rm := loopRe.FindStringSubmatch(registered); rm != nil && ValidateRedirect(registered) == nil {
			if other := "http://" + rm[1] + ":4321" + rm[2]; len(other) <= MaxRedirectURILen {
				if err := MatchRedirect([]string{registered}, other); err != nil {
					t.Fatalf("loopback %q refused another port: %v", registered, err)
				}
			}
		}
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
		sm, rm := loopRe.FindStringSubmatch(sent), loopRe.FindStringSubmatch(registered)
		if sm == nil || rm == nil || sm[1] != rm[1] || sm[2] != rm[2] {
			t.Fatalf("registered %q accepted %q", registered, sent)
		}
	})
}

func FuzzLoadStatic(f *testing.F) {
	f.Add(`{"clients":[{"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]}]}`)
	f.Add(`{"clients":[{"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"s"}]}`)
	f.Add(`{"clients":[{"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":` + publicJWKS(f, fakeidp.NewCertificate(f)) + `}]}`)
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
			switch c.method {
			case None:
			case ClientSecretBasic, ClientSecretPost:
				if len(c.secret) < MinSecretBytes {
					t.Fatalf("short secret accepted for %q", id)
				}
			case PrivateKeyJWT:
				if c.keys == nil {
					t.Fatalf("no keys for %q", id)
				}
			default:
				t.Fatalf("method %q accepted", c.method)
			}
			for _, r := range c.redirects {
				if ValidateRedirect(r) != nil {
					t.Fatalf("invalid redirect accepted: %q", r)
				}
			}
		}
	})
}
