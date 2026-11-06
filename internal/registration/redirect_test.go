package registration

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
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
		{"too long", []string{"https://app.example/"}, "https://app.example/" + strings.Repeat("a", MaxRedirectURILen), ReasonTooLong},
		{"empty", []string{"https://app.example/cb"}, "", ReasonMalformed},
		{"space in path", []string{"https://app.example/c b"}, "https://app.example/c b", ReasonMalformed},
		{"tab", []string{"https://app.example/cb"}, "https://app.example/cb\t", ReasonMalformed},
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
	errors.As(err, &re)
	logged := fmt.Sprint(re.LogValue())
	if strings.Contains(logged, "SECRET") || !strings.Contains(logged, "https://b.example/cb") || !strings.Contains(logged, ReasonNotRegistered) {
		t.Errorf("log value = %s", logged)
	}
	var _ slog.LogValuer = re
}
