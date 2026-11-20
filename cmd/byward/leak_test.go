package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/testutil/pgtest"
)

// canary stands for the secret in secretForms, the 14 forms of a secret in the #485 leak matrix (the
// "14 secret shapes" of ADR-0031 §1). No other value in the test holds it.
const canary = "LK7CANARY"

var secretForms = []struct{ name, value string }{
	{"userinfo", "https://u:LK7CANARY@h.example/x"},
	{"query", "https://h.example/x?k=LK7CANARY"},
	{"params", "https://h.example/x;k=LK7CANARY"},
	{"fragment", "https://h.example/x#LK7CANARY"},
	{"header line", "X-Api-Key: LK7CANARY"},
	{"bare", "LK7CANARY~tok"},
	{"DSN key=value", "host=db password=LK7CANARY"},
	{"semicolon for colon", "https;//h.example/;tok=LK7CANARY"},
	{"no colon", "https//h.example/;tok=LK7CANARY"},
	{"space after colon", "https: //h.example/;tok=LK7CANARY"},
	{"backslash", `https:\h.example/;tok=LK7CANARY`},
	{"no scheme", "//h.example/;tok=LK7CANARY"},
	{"no slashes", "https:h.example/;tok=LK7CANARY"},
	{"one slash", "https:/h.example/;tok=LK7CANARY"},
}

// hostForm is a secret in a URL's host, which is a valid host name. A URL setting's shape shows an
// accepted URL's host (ADR-0031 §2 leaves such a value to #495), so the form is checked only where
// config refuses it: the public URL refuses its upper case.
var hostForm = struct{ name, value string }{"in the host", "https://LK7CANARY.Example/mcp"}

// hidingSettings lists the settings whose shape hides part or all of a value. Each must have cells
// config accepts, and none of those may show a canary.
// client-denylist shows a non-URL entry as given, but config refuses every form here without a :// as a
// host name.
var hidingSettings = []string{"upstream-credential", "upstream-env", "entra-client-secret", "entra-client-certificate",
	"oidc-client-secret", "oidc-client-key", "store-postgres-dsn", "public-url", "upstream-url", "resource-documentation",
	"oidc-issuer", "client-denylist", "upstream-command"}

// A value config accepts for a setting whose shape hides part or all of it, in any of the 14 secret
// forms, appears on no output of startup, check --offline, --print-config or doctor, in either log
// format. Those settings are listed here (hidingSettings), not asked of their shape, which is the code
// under test. Any other setting is shown as given, so a value it accepts may appear wherever its
// cell's output repeats it (TestTheSettingsOfEachShapeAreExactlyThese, internal/config, pins which
// settings those are); the test only checks that its shape does show it, so a setting whose shape
// hides a value cannot be left off the list. A secret setting's value is written to the file it is
// read from. A value config refuses at load is run the same way: every command refuses it, in the
// one format "BYWARD_X: want …; got …" (ADR-0031 §1), and no output shows a canary. Startup runs
// with its context done and a listen address it cannot bind (TEST-NET-1), so it serves nothing;
// doctor's HTTP clients refuse every request (TestMain).
func TestNoCommandShowsAHiddenOrARefusedValue(t *testing.T) {
	commands := []struct {
		name string
		args []string
	}{{"startup", nil}, {"check --offline", []string{"check", "--offline"}}, {"--print-config", []string{"--print-config"}}, {"doctor", []string{"doctor"}}}
	// pgx reads the PG* variables, the service file and the password file from the process, not from
	// the settings, so PGSSLMODE=verify-full on the host would take the DSN form past its refusal and
	// make startup resolve its host; pgtest.ClearEnv clears them. Once they are cleared, and
	// with an upstream given by IP, no cell resolves a name or dials beyond loopback: the resolver
	// below fails the test on a DNS lookup, and TestMain's doctor clients refuse every request.
	t.Setenv("PGSSLMODE", "verify-full") // as a host may set it; ClearEnv must remove it
	pgtest.ClearEnv(t)
	// Any name a cell resolves through DNS fails the test: startup looks names up through
	// net.DefaultResolver (lookupNetIP), as does anything that dials a name, and a name here would make
	// real network queries on every host. Doctor's own lookups go to TestMain's resolver, which refuses
	// them.
	resolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("a cell resolved a name through DNS: give every context and form an IP or a loopback host")
		return nil, errors.New("the leak test resolves no names")
	}}
	t.Cleanup(func() { net.DefaultResolver = resolver })
	program, err := os.Executable() // a program that exists on every host the tests run on
	if err != nil {
		t.Fatal(err)
	}
	contexts := leakContexts(t, program)
	settings := allSettings(t, contexts["entra"])
	tried, refusedTried := map[string]int{}, map[string]int{}
	for _, s := range settings {
		for _, form := range append(slices.Clone(secretForms), hostForm) {
			// The setting's own value comes last, so it wins over the context's and the log format's.
			env := append(slices.Clone(contexts[leakContext(s)]), "BYWARD_LOG_FORMAT=@format@")
			if s.Secret() {
				file := filepath.Join(t.TempDir(), "value")
				if err := os.WriteFile(file, []byte(form.value), 0o600); err != nil {
					t.Fatal(err)
				}
				env = append(env, s.Env()+"_FILE="+file)
			} else {
				env = append(env, s.Env()+"="+given(s, form.value, program))
			}
			hiding := slices.Contains(hidingSettings, s.Name)
			if !hiding { // checked whether config accepts the form or not, so a refusal cannot hide a missing entry
				if shown := (config.Value{Setting: s, Given: config.NewOpaque(given(s, form.value, program))}).Display(); !strings.Contains(shown, canary) {
					t.Errorf("%s shows %q as %q, hiding it: fix its shape, or add the setting to hidingSettings", s.Env(), form.value, shown)
				}
			}
			_, _, loadErr := config.Load(nil, withFormat(env, "json"), os.ReadFile)
			refusing := loadErr != nil
			switch {
			case refusing:
				refusedTried[s.Name]++
				named := strings.Contains(loadErr.Error(), s.Env()+": want ") || strings.Contains(loadErr.Error(), s.Env()+"_FILE: want ")
				if !named || !strings.Contains(loadErr.Error(), "; got ") {
					t.Errorf("%s refuses %s outside the one format (%v): refuse it through refusedForm or refusedMeaning", s.Env(), form.name, loadErr)
				}
			case form == hostForm:
				continue // an accepted URL shows its host (hostForm)
			case !hiding:
				continue
			default:
				tried[s.Name]++
			}
			for _, format := range []string{"json", "text"} {
				for _, c := range commands {
					code, stdout, stderr := runDone(c.args, withFormat(env, format)...)
					got := stdout + stderr
					if shows(got) {
						t.Errorf("%s=%s (%s), %s, log %s: exit %d, a secret is shown:\n%s", s.Env(), form.value, form.name, c.name, format, code, got)
					}
					// The DSN form is refused at wiring for its sslmode, so it never dials; a PGSSLMODE left in
					// the environment would let check --offline pass it.
					if s.Name == "store-postgres-dsn" && form.name == "DSN key=value" && c.name == "check --offline" && code != exitConfig {
						t.Errorf("check --offline on %s=%s exits %d, want %d: the host's PG* environment reached the DSN", s.Env(), form.value, code, exitConfig)
					}
					// A refused cell is refused by every command, naming the setting, so its output is the refusal.
					if refusing && (code != exitConfig || !strings.Contains(got, s.Env())) {
						t.Errorf("%s=%s (%s), %s, log %s: exit %d, want %d naming the setting:\n%s", s.Env(), form.value, form.name, c.name, format, code, exitConfig, got)
					}
					// --print-config reaches the setting's display line in every accepted cell, so a context
					// that broke a command could not pass on its empty output.
					if !refusing && c.name == "--print-config" && (code != exitOK || !strings.Contains("\n"+got, "\n"+s.Env()+"=")) {
						t.Errorf("%s=%s (%s), --print-config, log %s: exit %d, want the setting's line:\n%s", s.Env(), form.value, form.name, format, code, got)
					}
				}
			}
		}
	}
	// Config refuses some form of most settings: fewer would mean the forms stopped reaching them.
	if len(refusedTried) < 40 {
		t.Errorf("config refused forms of %d settings, want at least 40: %v", len(refusedTried), refusedTried)
	}
	for _, name := range hidingSettings {
		switch {
		case !slices.ContainsFunc(settings, func(s config.Setting) bool { return s.Name == name }):
			t.Errorf("hidingSettings names %s, which is not a setting", name)
		case tried[name] == 0:
			t.Errorf("config accepted no form for %s, so the test checked nothing of it: give it a context in contextOf (and leakContexts)", name)
		}
	}

}

// shows reports whether output shows the canary, in any case (a refusal could lower-case it), or the
// contexts' own client secret (authEnv's), which only a reader of another setting could reach.
func shows(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, strings.ToLower(canary)) || strings.Contains(lower, entraSecret)
}

// given is how a value is given to s: as itself, or for the stdio upstream's command as an argument
// of program, the only form that setting accepts.
func given(s config.Setting, value, program string) string {
	if s.Name != "upstream-command" {
		return value
	}
	argv, _ := json.Marshal([]string{program, value}) // strings always marshal
	return string(argv)
}

// withFormat is env with its log format placeholder set to format.
func withFormat(env []string, format string) []string {
	out := slices.Clone(env)
	for i, kv := range out {
		if kv == "BYWARD_LOG_FORMAT=@format@" {
			out[i] = "BYWARD_LOG_FORMAT=" + format
		}
	}
	return out
}

// contextOf names the context of each setting that its group does not decide (leakContext).
var contextOf = map[string]string{
	"gate-hosted-domains":      "google",
	"gate-email-domains":       "oidc",
	"oidc-client-key":          "oidc, no secret", // a key or a secret, not both
	"entra-client-certificate": "entra, no secret",
	"store-postgres-dsn":       "entra, no state directory",     // one store, not two
	"upstream-credential":      "entra, other assertion header", // the two share Authorization by default
	// Each of these is refused for its context alone: a header without a credential, half a TLS pair,
	// a second Entra credential, a key's settings without the key.
	"upstream-credential-header": "entra, a credential",
	"tls-cert-file":              "entra, a TLS key",
	"tls-key-file":               "entra, a TLS certificate",
	"entra-federated-token-file": "entra, no secret",
	"oidc-client-key-alg":        "oidc, a key",
	"oidc-client-key-id":         "oidc, a key",
}

// leakContext is the context a setting is tried in: one where it applies, so config refuses a value
// only for its form, not for the wrong IdP, upstream mode or a setting it excludes.
func leakContext(s config.Setting) string {
	if c, ok := contextOf[s.Name]; ok {
		return c
	}
	switch s.Group {
	case config.GroupStdioUpstream:
		return "stdio"
	case config.GroupAppOnly:
		return "app"
	case config.GroupOIDC:
		return "oidc"
	}
	return "entra"
}

// leakContexts is each context's settings: Entra with an HTTP upstream; Entra with a stdio upstream
// instead (no upstream URL, no assertion keys), whose command is program; Entra with app-only
// tokens; an oidc IdP; Google; and the variants that leave room for the setting tried in them.
// Startup in each cannot bind its listener, and config accepts each as it is, apart from the three
// that need the setting tried in them.
func leakContexts(t *testing.T, program string) map[string][]string {
	t.Helper()
	listen := []string{"BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_LISTEN=192.0.2.1:8080", "BYWARD_INTERNAL_LISTEN="}
	httpServe := append(slices.Clone(listen), "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp") // an IP, so startup resolves no name
	entra := append(authEnv(t), httpServe...)
	command, _ := json.Marshal([]string{program}) // strings always marshal
	oidcBase := append(oidcAuthEnv(t), httpServe...)
	oidc := append(slices.Clone(oidcBase), "BYWARD_IDP=oidc", "BYWARD_OIDC_ISSUER=https://idp.example", "BYWARD_OIDC_CLIENT_ID=abc",
		"BYWARD_GATE_ALLOW_EMPTY=true")
	dir := t.TempDir()
	credential, key := filepath.Join(dir, "credential"), filepath.Join(dir, "key.pem")
	for _, f := range []string{credential, key} {
		if err := os.WriteFile(f, []byte("k-123"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tls := filepath.Join(dir, "tls")
	contexts := map[string][]string{
		"entra":                         entra,
		"entra, a credential":           append(slices.Clone(entra), "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credential, "BYWARD_ASSERTION_HEADER=X-Byward-Identity"),
		"entra, a TLS key":              append(slices.Clone(entra), "BYWARD_TLS_KEY_FILE="+tls),
		"entra, a TLS certificate":      append(slices.Clone(entra), "BYWARD_TLS_CERT_FILE="+tls),
		"oidc, a key":                   append(without(oidc, "BYWARD_OIDC_CLIENT_SECRET_FILE="), "BYWARD_OIDC_CLIENT_KEY_FILE="+key),
		"entra, no secret":              without(entra, "BYWARD_ENTRA_CLIENT_SECRET_FILE="),
		"entra, no state directory":     without(entra, "BYWARD_STORE_DIR="),
		"entra, other assertion header": append(slices.Clone(entra), "BYWARD_ASSERTION_HEADER=X-Byward-Identity"),
		"oidc":                          oidc,
		"oidc, no secret":               without(oidc, "BYWARD_OIDC_CLIENT_SECRET_FILE="),
		"google":                        append(slices.Clone(oidcBase), "BYWARD_IDP=google", "BYWARD_OIDC_CLIENT_ID=abc", "BYWARD_GATE_ALLOW_EMPTY=true"),
		"stdio":                         append(append(stdioAuthEnv(t), listen...), "BYWARD_UPSTREAM_COMMAND="+string(command)),
		"app":                           append(slices.Clone(entra), "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=r"),
	}
	for name, env := range contexts {
		if name == "entra, no secret" || name == "oidc, no secret" || name == "entra, no state directory" || name == "entra, a TLS key" || name == "entra, a TLS certificate" {
			continue // each needs the setting tried in it, as entra-client-certificate, oidc-client-key, store-postgres-dsn or the other TLS file
		}
		if _, _, err := config.Load(nil, env, os.ReadFile); err != nil {
			t.Fatalf("the %s context is refused: %v", name, err)
		}
	}
	return contexts
}

// allSettings is every setting config reads, in registry order.
func allSettings(t *testing.T, env []string) []config.Setting {
	t.Helper()
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	var out []config.Setting
	for _, v := range cfg.Values.Effective() {
		out = append(out, v.Setting)
	}
	return out
}
