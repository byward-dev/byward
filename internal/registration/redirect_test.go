package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// Documented client redirect URIs (ADR-0009 Context, 2026-11-05). They are fixtures and
// documentation, never presets in code (ADR-0009 §9).
var clientFixtures = map[string]struct {
	registered []string
	sent       []string
}{
	"Claude Code": {
		registered: []string{"http://localhost/callback", "http://127.0.0.1/callback"},
		sent:       []string{"http://localhost:51234/callback", "http://127.0.0.1:61000/callback", "http://localhost/callback"},
	},
	"Claude (hosted)": {
		registered: []string{"https://claude.ai/api/mcp/auth_callback"},
		sent:       []string{"https://claude.ai/api/mcp/auth_callback"},
	},
	"VS Code": {
		registered: []string{"http://127.0.0.1:33418/", "https://vscode.dev/redirect"},
		sent:       []string{"http://127.0.0.1:33418/", "http://127.0.0.1:40000/", "https://vscode.dev/redirect"},
	},
	"Cursor": {
		registered: []string{"http://localhost:8787/callback", "https://www.cursor.com/agents/mcp/oauth/callback"},
		sent:       []string{"http://localhost:8787/callback", "http://localhost:9999/callback", "https://www.cursor.com/agents/mcp/oauth/callback"},
	},
	"ChatGPT": {
		registered: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		sent:       []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
	},
}

func TestDocumentedClientRedirectsAreValidAndMatch(t *testing.T) {
	for name, fx := range clientFixtures {
		t.Run(name, func(t *testing.T) {
			for _, r := range fx.registered {
				if err := ValidateRedirect(r); err != nil {
					t.Errorf("registered %s: %v", r, err)
				}
			}
			for _, s := range fx.sent {
				if err := MatchRedirect(fx.registered, s); err != nil {
					t.Errorf("sent %s: %v", s, err)
				}
			}
		})
	}
}

// A registered redirect URI follows the URL settings' host rule (ADR-0032 §3, #707): its host holds
// only ASCII letters, digits, - . and _ (an internationalized name in its xn-- form), and its port,
// if any, is 1 to 65535 with no sign or leading zero. The loopback set is unchanged (ADR-0032 §5):
// the exact literals, over http, on any such port. An empty label and an edge hyphen are the host
// lists' own rule (#630), so they pass here. Each refusal names its reason, never the URI's host.
func TestARedirectURIFollowsTheURLSettingsHostRule(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want string // the refusal's reason, or "" when the URI passes
	}{
		{"http://localhost/cb", ""},
		{"http://127.0.0.1/cb", ""},
		{"http://[::1]/cb", ""},
		{"http://localhost:1/cb", ""},
		{"http://127.0.0.1:8080/cb", ""},
		{"http://[::1]:65535/cb", ""},
		{"http://localhost:0/cb", ReasonPort},
		{"http://127.0.0.1:65536/cb", ReasonPort},
		{"http://[::1]:080/cb", ReasonPort},
		{"http://127.0.0.1:/cb", ReasonPort},  // a ":" with no port, which the URL settings refuse too
		{"http://LOCALHOST/cb", ReasonScheme}, // the loopback set is exact (§5)
		{"http://127.1/cb", ReasonScheme},
		{"https://app.example/cb", ""},
		{"https://app.example:8443/cb", ""},
		{"https://my_app.example/cb", ""},
		{"https://xn--bcher-kva.example/cb", ""},
		{"https://app.example./cb", ""}, // a trailing dot: the host lists' rule, not this one
		{"https://-app.example/cb", ""}, // an edge hyphen: likewise
		{"https://app.example:0/cb", ReasonPort},
		{"https://app.example:65536/cb", ReasonPort},
		{"https://app.example:+443/cb", ReasonMalformed}, // url.Parse refuses a sign itself, as before
		{"https://bücher.example/cb", ReasonHost},
		{"https://xn--bcher-\u212Ava.example/cb", ReasonHost},
		{"https://ev\u0130l.example/cb", ReasonHost},
		{"https://fa\u00DF.example/cb", ReasonHost},
		{"https://0\xb6\xb6.example/cb", ReasonHost},
		{"https://app~x.example/cb", ReasonHost},
		{"https://[fe80::1%25eth0]/cb", ReasonHost},
		{"https://a\u200bb.example/cb", ReasonMalformed},  // an invisible character anywhere in the URI
		{"https://app.example/c\u00a0b", ReasonMalformed}, // white space in the path, not only the host
		{"https://app.example/c\u0085b", ReasonMalformed}, // a C1 control in the path
		{"https://app.example/c\u200db", ReasonMalformed}, // an invisible character in the path
	} {
		var re *RedirectError
		err := ValidateRedirect(tc.uri)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%q: %v, want it to pass", tc.uri, err)
		case tc.want != "" && (!errors.As(err, &re) || re.Reason != tc.want):
			t.Errorf("%q: %v, want it refused with reason %q", tc.uri, err, tc.want)
		}
	}
}

func TestMatchRedirect(t *testing.T) {
	for _, tc := range []struct {
		name       string
		registered []string
		sent       string
		reason     string // "" = match
	}{
		{"https exact", []string{"https://app.example/cb"}, "https://app.example/cb", ""},
		{"https trailing slash", []string{"https://app.example/cb"}, "https://app.example/cb/", ReasonNotRegistered},
		{"https case", []string{"https://app.example/cb"}, "https://APP.example/cb", ReasonNotRegistered},
		{"https port differs", []string{"https://app.example/cb"}, "https://app.example:8443/cb", ReasonNotRegistered},
		{"https extra query", []string{"https://app.example/cb"}, "https://app.example/cb?x=1", ReasonNotRegistered},
		{"https query exact", []string{"https://app.example/cb?x=1"}, "https://app.example/cb?x=1", ""},
		{"https default port spelled", []string{"https://app.example/cb"}, "https://app.example:443/cb", ReasonNotRegistered},
		{"loopback any port", []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:8080/cb", ""},
		{"loopback registered port, other port", []string{"http://127.0.0.1:1234/cb"}, "http://127.0.0.1:5678/cb", ""},
		{"loopback ipv6", []string{"http://[::1]/cb"}, "http://[::1]:9000/cb", ""},
		{"loopback host literal differs", []string{"http://127.0.0.1/cb"}, "http://localhost:8080/cb", ReasonNotRegistered},
		{"loopback path differs", []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:8080/other", ReasonNotRegistered},
		{"loopback query differs", []string{"http://127.0.0.1/cb?a=1"}, "http://127.0.0.1:8080/cb?a=2", ReasonNotRegistered},
		{"loopback empty query marker", []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:8080/cb?", ReasonNotRegistered},
		{"loopback https registration, http sent", []string{"https://127.0.0.1/cb"}, "http://127.0.0.1/cb", ReasonNotRegistered},
		{"http non-loopback", []string{"http://app.example/cb"}, "http://app.example/cb", ReasonScheme},
		{"http 127.0.0.2", []string{"http://127.0.0.2/cb"}, "http://127.0.0.2/cb", ReasonScheme},
		{"localhost subdomain", []string{"http://evil.localhost/cb"}, "http://evil.localhost/cb", ReasonScheme},
		{"custom scheme", []string{"myapp://cb"}, "myapp://cb", ReasonScheme},
		{"fragment", []string{"https://app.example/cb"}, "https://app.example/cb#x", ReasonFragment},
		{"userinfo", []string{"https://app.example/cb"}, "https://user@app.example/cb", ReasonUserinfo},
		{"wildcard", []string{"https://*.example/cb"}, "https://*.example/cb", ReasonWildcard},
		{"relative", []string{"/cb"}, "/cb", ReasonMalformed},
		{"opaque", []string{"https:app.example"}, "https:app.example", ReasonMalformed},
		{"a port with no host", []string{"https://:443/cb"}, "https://:443/cb", ReasonMalformed}, // #625
		{"a colon with no host", []string{"https://:/cb"}, "https://:/cb", ReasonMalformed},
		{"user information and a port with no host", []string{"https://u@:443/cb"}, "https://u@:443/cb", ReasonMalformed},
		{"http with a port and no host", []string{"http://:80/cb"}, "http://:80/cb", ReasonMalformed},
		{"too long", []string{"https://app.example/"}, "https://app.example/" + strings.Repeat("a", MaxRedirectURILen), ReasonTooLong},
		{"empty", []string{"https://app.example/cb"}, "", ReasonMalformed},
		{"space in path", []string{"https://app.example/c b"}, "https://app.example/c b", ReasonMalformed},
		{"tab", []string{"https://app.example/cb"}, "https://app.example/cb\t", ReasonMalformed},
		{"loopback escaped path differs", []string{`http://127.0.0.1/a"b`}, "http://127.0.0.1:1/a%22b", ReasonNotRegistered},
		{"loopback escaped path differs reverse", []string{"http://127.0.0.1/a%22b"}, `http://127.0.0.1:1/a"b`, ReasonNotRegistered},
		{"loopback no path, query", []string{"http://127.0.0.1?x=1"}, "http://127.0.0.1:9?x=1", ""},
		{"uppercase scheme loopback", []string{"Http://127.0.0.1"}, "htTp://127.0.0.1", ReasonScheme},
		{"uppercase scheme https", []string{"https://app.example/cb"}, "HTTPS://app.example/cb", ReasonScheme},
		{"localhost uppercase", []string{"http://localhost/cb"}, "http://LOCALHOST:9/cb", ReasonScheme},
		{"ipv6 zone", []string{"http://[::1]/cb"}, "http://[::1%25eth0]:8/cb", ReasonScheme},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := MatchRedirect(tc.registered, tc.sent)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			var re *RedirectError
			if !errors.As(err, &re) || re.Reason != tc.reason {
				t.Fatalf("err = %v, want reason %s", err, tc.reason)
			}
		})
	}
}

func TestRedirectErrorDiagnostics(t *testing.T) {
	err := MatchRedirect([]string{"https://a.example/cb", "http://127.0.0.1/cb"}, "https://b.example/cb?code=SECRET")
	msg := err.Error()
	if !strings.Contains(msg, "registered https://a.example/cb, http://127.0.0.1/cb, sent https://b.example/cb?code=SECRET") {
		t.Errorf("message = %q", msg)
	}
	var re *RedirectError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, not a *RedirectError", err)
	}
	// User information a client puts in a redirect URI is no more logged than its query.
	if !errors.As(MatchRedirect([]string{"https://a.example/cb"}, "https://user:SECRET@b.example/cb"), &re) {
		t.Fatal("user information is not a *RedirectError")
	}
	if got, want := re.logText(), "redirect URI https://b.example/cb rejected: must not contain user information"; got != want {
		t.Errorf("logText = %q, want %q", got, want)
	}
	// The text for a logged error shows every URI as logs may, registered ones included.
	if !errors.As(MatchRedirect([]string{"https://u:SECRET@a.example/cb?k=SECRET"}, "https://b.example/cb?code=SECRET"), &re) {
		t.Fatal("an unregistered URI is not a *RedirectError")
	}
	if got, want := re.logText(), "redirect URI not registered: registered https://a.example/cb, sent https://b.example/cb"; got != want {
		t.Errorf("logText = %q, want %q", got, want)
	}
}

// A *RedirectError logged as it is, not through logText, still shows each URI as logs may: scheme,
// host and path, never user information or a query (ADR-0009 §8), through the proxy's own logger.
func TestADirectlyLoggedRedirectErrorShowsItsURIsAsLogsMay(t *testing.T) {
	for _, tc := range []struct{ name, sent, want string }{
		{"user information", "https://user:SECRET@b.example/cb?k=SECRET", "redirect URI https://b.example/cb rejected: must not contain user information"},
		{"not registered", "https://b.example/cb?code=SECRET", "redirect URI not registered: registered https://a.example/cb, sent https://b.example/cb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logging.New(&buf, "json").Warn("refused", "error", MatchRedirect([]string{"https://a.example/cb?k=SECRET"}, tc.sent))
			var rec map[string]any
			if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
				t.Fatalf("log line %q: %v", buf.String(), err)
			}
			if got := rec["error"]; got != tc.want {
				t.Errorf("logged error = %v, want %q (line %s)", got, tc.want, buf.String())
			}
		})
	}
}

func TestARedirectKeyDropsOnlyALoopbackPort(t *testing.T) {
	for uri, want := range map[string]string{
		"http://127.0.0.1:53124/callback":    "http://127.0.0.1/callback",
		"http://localhost:8787/callback?x=1": "http://localhost/callback?x=1",
		"http://[::1]:33418/":                "http://[::1]/",
		"http://127.0.0.1/callback":          "http://127.0.0.1/callback",
		"https://app.example:8443/cb":        "https://app.example:8443/cb", // only loopback http varies
		"https://localhost:8443/cb":          "https://localhost:8443/cb",
		"http://app.example:8080/cb":         "http://app.example:8080/cb",
	} {
		if got := RedirectKey(uri); got != want {
			t.Errorf("RedirectKey(%q) = %q, want %q", uri, got, want)
		}
	}
}
