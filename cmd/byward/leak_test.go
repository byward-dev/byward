package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/server"
	"github.com/byward-dev/byward/internal/testutil/pgtest"
)

// canary stands for the secret in secretForms: the 14 forms of a secret in the #485 leak matrix (the
// "14 secret shapes" of ADR-0031 §1), and the kinds of the catalogue of secrets (#657). No other
// value in the test holds it.
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
	// The catalogue's kinds (internal/logging/secretkind.go, #657), each holding the canary; the URL
	// with a password and the key=value password are the userinfo and DSN forms above.
	{"GitHub token", "ghp_" + "LK7CANARY" + "Q7Q7Q7"},
	{"Slack token", "xoxb-" + "LK7CANARY" + "-12345"},
	{"JWT", "eyJ" + "hbGciOiJSUzI1NiJ9." + "LK7CANARY" + ".c2lnbmF0dXJl"},
	{"GitHub token after a line break", "x\n" + "ghp_" + "LK7CANARY" + "Q7Q7Q7"},
	{"GitHub token percent-escaped", "https://h.example/ghp%5F" + "LK7CANARY" + "Q7Q7Q7"},
	{"opaque Bearer credential", "Bearer " + "LK7CANARY" + "Q7Q7Q7Q7"}, // redact-only: a Known gap (#657)
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
// read from. A value config refuses at load is run the same way: config refuses it in the one format
// "BYWARD_X: want …; got …" (ADR-0031 §1), every command refuses it naming the setting, and no
// output shows a canary. Startup runs
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
	for _, name := range contextOf { // a context named but not built would run its setting with no settings at all
		if _, ok := contexts[name]; !ok {
			t.Fatalf("contextOf names the context %q, which leakContexts does not build", name)
		}
	}
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
				if shows(loadErr.Error()) {
					t.Errorf("%s=%s (%s): config's refusal shows a secret: %v", s.Env(), form.value, form.name, loadErr)
				}
				// Every line is a refusal of this setting, in the one format.
				for _, line := range strings.Split(loadErr.Error(), "\n") {
					named := strings.HasPrefix(line, s.Env()+": want ") || strings.HasPrefix(line, s.Env()+"_FILE: want ")
					if !named || !strings.Contains(line, "; got ") {
						t.Errorf("%s refuses %s with the line %q, outside the one format: refuse it through refusedForm or refusedMeaning", s.Env(), form.name, line)
					}
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
	// Every setting but these, for which config refuses none of the forms above, refuses some form, so
	// its refusal is run through every command: one that stops refusing, or starts, is named here. A
	// setting that is not secret refuses at least the form with a password in a URL, as a secret's
	// kind (#495), so only secrets and the command, whose arguments are never shown, are left.
	acceptsEveryForm := []string{"entra-client-certificate", "entra-client-secret", "oidc-client-key",
		"oidc-client-secret", "store-postgres-dsn", "upstream-command"}
	for _, s := range settings {
		switch refuses := refusedTried[s.Name] > 0; {
		case refuses && slices.Contains(acceptsEveryForm, s.Name):
			t.Errorf("config refused forms of %s, which acceptsEveryForm lists: remove it, so its refusals stay checked", s.Name)
		case !refuses && !slices.Contains(acceptsEveryForm, s.Name):
			t.Errorf("config refused no form of %s, so no refusal of it was checked: give it a context in contextOf, or list it in acceptsEveryForm", s.Name)
		}
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
// tokens; an oidc IdP; Google; and the variants that leave room for, or supply the partner of, the
// setting tried in them.
// Startup in each cannot bind its listener, and config accepts each as it is, apart from those that
// need the setting tried in them (needsItsSetting).
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
	// These need the setting tried in them, so config refuses each alone; every other loads as it is.
	needsItsSetting := map[string]bool{"entra, no secret": true, "oidc, no secret": true,
		"entra, a TLS key": true, "entra, a TLS certificate": true}
	for name, env := range contexts {
		if _, _, err := config.Load(nil, env, os.ReadFile); (err != nil) != needsItsSetting[name] {
			t.Fatalf("the %s context: Load = %v, want it refused alone %v", name, err, needsItsSetting[name])
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

// byward init shows a value it was given only in the script it prints, which is the script's purpose
// (#576). Every form of a secret, and a secret in a URL's host, is given in each place: as the IdP's
// name, alone and with each refusal init makes before it reads the name; as each of init's flags; as
// BYWARD_PUBLIC_URL and BYWARD_UPSTREAM_URL, alone and with an undefined flag; as an undefined flag,
// with and without a value; in a bad flag syntax; and as an extra argument. Each cell must reach its
// own refusal, which names a refused value only by its length, as config does (#512), or for a URL be
// accepted, and show the value in no refusal, on stderr or stdout. Nothing reaches os.Stderr or the log
// package either: the flag package writes to os.Stderr unless told otherwise, defaults from the
// environment included.
func TestInitShowsAValueItWasGivenOnlyInTheScriptItPrints(t *testing.T) {
	const usage = "byward: usage: byward init entra --tenant <tenant-id> [--public-url <url>] [--upstream-url <url>] [--secret-years 1|2] [--credential secret|certificate]\n"
	processStderr := redirectStderr(t)
	base := []string{"--tenant", tenant, "--public-url", "https://m.example/mcp"}
	entra := func(extra ...string) []string { return append(append([]string{"init", "entra"}, base...), extra...) }
	// Each of init's flags, by the refusal its value reaches; a URL init accepts is printed.
	flagRefusals := map[string]struct {
		want     string
		accepted bool
	}{
		"tenant":       {"the tenant must be the tenant ID", false},
		"public-url":   {"BYWARD_PUBLIC_URL", true},
		"upstream-url": {"BYWARD_UPSTREAM_URL", true},
		"secret-years": {"--secret-years: want a whole number of years; got a value it does not take (not shown)", false},
		"credential":   {"the credential must be secret or certificate; got another value (", false},
	}
	fs, _ := newInitFlags(nil)
	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := flagRefusals[f.Name]; !ok {
			t.Errorf("init's flag --%s has no cell here", f.Name)
		}
	})
	type cell struct {
		place, want string
		exact       bool // want is all of stderr
		accepted    bool // a URL init may accept, and print
		args, env   []string
	}
	for _, form := range append(slices.Clone(secretForms), hostForm) {
		v := form.value
		cells := []cell{
			{place: "the IdP's name", want: "the IdP must be entra; got another name (", args: append([]string{"init", v}, base...)},
			{place: "the IdP's name, with an undefined flag", want: "got an undefined flag (4 characters, not shown)", args: []string{"init", v, "--tenant", tenant, "--nope"}},
			{place: "the IdP's name, asking for help", want: usage, exact: true, args: []string{"init", v, "-h"}},
			{place: "the IdP's name, with a flag without its value", want: "flag needs an argument: -tenant", args: []string{"init", v, "--tenant"}},
			{place: "the IdP's name, without a tenant", want: usage, exact: true, args: []string{"init", v, "--public-url", "https://m.example/mcp"}},
			{place: "the IdP's name, with an extra argument", want: usage, exact: true, args: append(append([]string{"init", v}, base...), "now")},
			{place: "the IdP's name, with a bad lifetime", want: "--secret-years: want", args: append(append([]string{"init", v}, base...), "--secret-years=x")},
			{place: "the IdP's name, without a public URL", want: "BYWARD_PUBLIC_URL is required", args: []string{"init", v, "--tenant", tenant}},
			{place: "the IdP's name, with a bad upstream URL", want: "BYWARD_UPSTREAM_URL: want", args: append(append([]string{"init", v}, base...), "--upstream-url=ftp://up.example/mcp")},
			{place: "BYWARD_PUBLIC_URL", want: "BYWARD_PUBLIC_URL", accepted: true, args: []string{"init", "entra", "--tenant", tenant}, env: []string{"BYWARD_PUBLIC_URL=" + v}},
			{place: "BYWARD_UPSTREAM_URL", want: "BYWARD_UPSTREAM_URL", accepted: true, args: entra(), env: []string{"BYWARD_UPSTREAM_URL=" + v}},
			{place: "BYWARD_PUBLIC_URL, with an undefined flag", want: "got an undefined flag (4 characters, not shown)", args: []string{"init", "entra", "--tenant", tenant, "--nope"}, env: []string{"BYWARD_PUBLIC_URL=" + v}},
			{place: "BYWARD_UPSTREAM_URL, with an undefined flag", want: "got an undefined flag (4 characters, not shown)", args: entra("--nope"), env: []string{"BYWARD_UPSTREAM_URL=" + v}},
			// The flag package ends a flag's name at its first =, so the form is given once with each = replaced.
			{place: "an undefined flag", want: "got an undefined flag (", args: entra("--" + strings.ReplaceAll(v, "=", "_"))},
			{place: "an undefined flag with a value", want: "got an undefined flag (", args: entra("--" + v)},
			{place: "a bad flag syntax", want: "got an argument with a bad flag syntax (", args: entra("---" + v)},
			{place: "an extra argument", want: usage, exact: true, args: entra(v)},
		}
		for name, r := range flagRefusals {
			cells = append(cells, cell{place: "--" + name, want: r.want, accepted: r.accepted, args: entra("--" + name + "=" + v)})
		}
		for _, c := range cells {
			t.Run(c.place+"/"+form.name, func(t *testing.T) {
				code, stdout, stderr := runWith(c.args, c.env...)
				if shows(stderr) || code != exitOK && shows(stdout) {
					t.Errorf("exit %d; stdout %q, stderr %q show the value given", code, stdout, stderr)
				}
				if got := processStderr(t); got != "" {
					t.Errorf("init wrote %q to os.Stderr or the log package, want nothing", got)
				}
				if code == exitOK && c.accepted {
					return
				}
				if code != exitConfig || !c.exact && !strings.Contains(stderr, c.want) || c.exact && stderr != c.want {
					t.Errorf("exit %d, stderr %q; want exit %d and the refusal %q", code, stderr, exitConfig, c.want)
				}
			})
		}
	}
}

// byward init refuses a URL whose text, as the script would print it, holds a secret's kind, as config
// refuses one in a setting that is not secret: naming the flag or variable and the kind, never the
// value (#641). The script prints --upstream-url whole, so a token in its query is refused too.
func TestInitRefusesAURLItWouldPrintWithASecretInIt(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("Q7", 18)
	jwt := "eyJ" + "hbGciOiJFUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJ4In0" + "." + "sig"
	for _, tc := range []struct {
		name, variable, kind string
		args, env            []string
	}{
		{"--public-url, a token in its path", "BYWARD_PUBLIC_URL", "a GitHub token", []string{"--public-url", "https://m.example/" + ghp + "/mcp"}, nil},
		{"--upstream-url, a token in its query", "BYWARD_UPSTREAM_URL", "a GitHub token", []string{"--public-url", "https://m.example/mcp", "--upstream-url", "https://up.example/mcp?key=" + ghp}, nil},
		{"--upstream-url, a JWT in its path", "BYWARD_UPSTREAM_URL", "a JWT", []string{"--public-url", "https://m.example/mcp", "--upstream-url", "https://up.example/" + jwt}, nil},
		{"BYWARD_UPSTREAM_URL, a token in its query", "BYWARD_UPSTREAM_URL", "a GitHub token", []string{"--public-url", "https://m.example/mcp"}, []string{"BYWARD_UPSTREAM_URL=https://up.example/mcp?key=" + ghp}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith(append([]string{"init", "entra", "--tenant", tenant}, tc.args...), tc.env...)
			if code != exitConfig || stdout != "" || !strings.HasPrefix(stderr, "byward: init: "+tc.variable+": ") || !strings.Contains(stderr, "it looks like "+tc.kind) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit %d refusing %s as %s", code, stdout, stderr, exitConfig, tc.variable, tc.kind)
			}
			if strings.Contains(stderr, "Q7Q7") || strings.Contains(stderr, "zdWIi") {
				t.Errorf("stderr %q shows the value given", stderr)
			}
		})
	}
	if code, stdout, _ := runWith([]string{"init", "entra", "--tenant", tenant, "--public-url", "https://m.example/mcp", "--upstream-url", "https://up.example/mcp?team=ghp-docs"}); code != exitOK || !strings.Contains(stdout, "team=ghp-docs") {
		t.Errorf("exit %d; want a URL with no secret's kind printed in the script", code)
	}
}

// revoke-user shows no key it was given: under Entra, a token pasted where the user key belongs is
// refused (it is no tid:oid), and named by its length, as init names a value it refuses (#594, ADR-0031 §1). Every form of a secret,
// and a token's three segments, is given as the key; each must reach the refusal and show nothing.
func TestRevokeUserShowsNoKeyItWasGiven(t *testing.T) {
	keys := append(slices.Clone(secretForms), struct{ name, value string }{"JWT", "eyJhbGciOiJSUzI1NiJ9." + canary + ".c2lnbmF0dXJl"})
	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			code, stdout, stderr := runWith([]string{"revoke-user", key.value}, append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)...)
			want := "byward: revoke-user " + logging.NotShown(key.value) + ": " + server.ErrNotAUserKey.Error() + "\n"
			if code != exitConfig || stdout != "" || stderr != want {
				t.Fatalf("code %d (want %d), stdout %q, stderr %q; want only %q", code, exitConfig, stdout, stderr, want)
			}
			if shows(stdout + stderr) {
				t.Errorf("the key given is shown: stdout %q, stderr %q", stdout, stderr)
			}
		})
	}
}

// redirectStderr sends os.Stderr and the log package (slog's default logger writes through it) to a file
// until the test ends, and returns a function that reads what was written there since it last read, failing
// the test (or subtest) it is given if it cannot. It swaps variables, not file descriptor 2. No test in
// this package runs in parallel, so none writes there meanwhile.
func redirectStderr(t *testing.T) func(*testing.T) string {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	saved, savedLog := os.Stderr, log.Writer()
	os.Stderr = f
	log.SetOutput(f)
	t.Cleanup(func() { os.Stderr = saved; log.SetOutput(savedLog); _ = f.Close() })
	read := 0
	return func(t *testing.T) string {
		t.Helper()
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		got := string(b[read:])
		read = len(b)
		return got
	}
}

// tokenForms are tokens and credentials pasted where a user key belongs (#594). Entra refuses each,
// as no tid:oid. Under an oidc IdP keyed on sub, a form within the 255 ASCII characters OIDC Core 1.0
// §2 allows a sub is a key (subOK), and one longer is refused.
var tokenForms = []struct {
	name, value string
	subOK       bool
}{
	{"a compact JWS", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.LK7CANARY", true},
	{"a JWS longer than a sub", "eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("eyJzdWIiOiJhIn0", 16) + ".LK7CANARY", false},
	{"a Bearer credential", "Bearer LK7CANARY", true},
}

// The operator commands show no argument they were given, whether they refuse it or take it (#594). Every command but
// revoke-user and init takes only fixed words, so a value after them gets the command's usage line;
// init has TestInitShowsAValueItWasGivenOnlyInTheScriptItPrints. revoke-user under an oidc IdP keyed on
// sub takes a key as OIDC Core allows a sub: every secret form is within that rule, so it is taken
// (these runs have no store, so none is revoked or shown), and a token form longer than a sub is
// refused and named by its length. Entra refuses every token form (TestRevokeUserShowsNoKeyItWasGiven
// covers its other forms). Every command in the commands map has a cell here or names its test. Nothing reaches
// os.Stderr or the log package.
func TestOperatorCommandsShowNoArgumentTheyAreGiven(t *testing.T) {
	const (
		checkUsage           = "byward: usage: byward check --offline [-- stdio-upstream-command [args...]] (for the network checks, run byward doctor)\n"
		doctorUsage          = "byward: usage: byward doctor [--json] [-- stdio-upstream-command [args...]]\n"
		jwksUsage            = "byward: usage: byward jwks (prints the JWKS; redirect it to a file)\n"
		downstreamTokenUsage = "byward: usage: byward downstream-token [--json] (run by a stdio upstream process or one of its descendants)\n"
		storeMissingLine     = "byward: revoke-user: BYWARD_STORE_DIR" + storeMissing
	)
	coveredElsewhere := map[string]string{"init": "TestInitShowsAValueItWasGivenOnlyInTheScriptItPrints"}
	processStderr := redirectStderr(t)
	entraEnv, _, _ := operatorEnv(t, noStore)
	oidcEnv := append(without(entraEnv, "BYWARD_ENTRA_"), "BYWARD_OIDC_CLIENT_SECRET_FILE="+setting(entraEnv, "BYWARD_ENTRA_CLIENT_SECRET_FILE"),
		"BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_CLIENT_ID=byward", "BYWARD_GATE_ALLOW_EMPTY=true")
	refused := func(v string) string {
		// The length is counted here, not by logging.NotShown, so a NotShown that showed part of v fails.
		return fmt.Sprintf("byward: revoke-user (%d characters, not shown): %s\n", utf8.RuneCountInString(v), server.ErrNotAUserKey)
	}
	type cell struct {
		place     string
		want      string // stderr, exactly
		args, env []string
	}
	placed := map[string]bool{}
	run := func(t *testing.T, form string, cells []cell) {
		for _, c := range cells {
			placed[c.args[0]] = true
			t.Run(c.place+"/"+form, func(t *testing.T) {
				code, stdout, stderr := runWith(c.args, c.env...)
				if shows(stderr) || shows(stdout) {
					t.Errorf("exit %d; stdout %q, stderr %q show the value given", code, stdout, stderr)
				}
				if got := processStderr(t); got != "" {
					t.Errorf("wrote %q to os.Stderr or the log package, want nothing", got)
				}
				if code != exitConfig || stdout != "" || stderr != c.want {
					t.Errorf("exit %d, stdout %q, stderr %q; want exit %d and stderr %q", code, stdout, stderr, exitConfig, c.want)
				}
			})
		}
	}
	usageCells := func(v string) []cell {
		return []cell{
			{"revoke-user, a second key", revokeUserUsage, []string{"revoke-user", "u1", v}, entraEnv},
			{"revoke-all", revokeAllUsage, []string{"revoke-all", v}, entraEnv},
			{"revoke-all --yes, then a value", revokeAllUsage, []string{"revoke-all", "--yes", v}, entraEnv},
			{"store", newEpochUsage, []string{"store", v}, entraEnv},
			{"store new-epoch, then a value", newEpochUsage, []string{"store", "new-epoch", v}, entraEnv},
			{"store new-epoch --yes, then a value", newEpochUsage, []string{"store", "new-epoch", "--yes", v}, entraEnv},
			{"check", checkUsage, []string{"check", v}, entraEnv},
			{"check --offline, then a value", checkUsage, []string{"check", "--offline", v}, entraEnv},
			{"doctor", doctorUsage, []string{"doctor", v}, entraEnv},
			{"doctor --json, then a value", doctorUsage, []string{"doctor", "--json", v}, entraEnv},
			{"jwks", jwksUsage, []string{"jwks", v}, entraEnv},
			{"downstream-token", downstreamTokenUsage, []string{"downstream-token", v}, entraEnv},
			{"downstream-token --json, then a value", downstreamTokenUsage, []string{"downstream-token", "--json", v}, entraEnv},
		}
	}
	for _, form := range append(slices.Clone(secretForms), hostForm) {
		v := form.value
		oidcWant := storeMissingLine
		if strings.ContainsFunc(v, func(r rune) bool { return r < ' ' || r > '~' }) {
			oidcWant = refused(v) // a sub is printable ASCII
		}
		run(t, form.name, append(usageCells(v),
			cell{"revoke-user, oidc", oidcWant, []string{"revoke-user", v}, oidcEnv}))
	}
	for _, form := range tokenForms {
		v := form.value
		oidcWant := refused(v)
		if form.subOK {
			oidcWant = storeMissingLine
		}
		run(t, form.name, append(usageCells(v),
			cell{"revoke-user, entra", refused(v), []string{"revoke-user", v}, entraEnv},
			cell{"revoke-user, oidc", oidcWant, []string{"revoke-user", v}, oidcEnv}))
	}
	for name := range commands {
		if !placed[name] && coveredElsewhere[name] == "" {
			t.Errorf("operator command %q has no cell here: add one, or name the test that covers it", name)
		}
	}
}
