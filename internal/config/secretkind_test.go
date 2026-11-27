package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// fakeToken is a token of prefix's form, made here so no file holds one whole: a secret scanner
// never meets it, and it is never a real credential.
func fakeToken(prefix string) string { return prefix + strings.Repeat("Q7", 18) }

// fakeJWT is a compact JWS built by concatenation, so no whole token sits in the file.
func fakeJWT() string {
	return "eyJ" + "hbGciOiJFUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJ4In0" + "." + "sig"
}

// secretKinds are a value of each kind secretKind names, with the class a refusal says.
var secretKinds = []struct{ value, class string }{
	{fakeToken("ghp_"), "a GitHub token"},
	{fakeToken("github_pat_"), "a GitHub token"},
	{fakeToken("gho_"), "a GitHub token"},
	{fakeToken("ghu_"), "a GitHub token"},
	{fakeToken("ghs_"), "a GitHub token"},
	{fakeToken("ghr_"), "a GitHub token"},
	{fakeToken("xoxb-"), "a Slack token"},
	{fakeToken("xoxp-"), "a Slack token"},
	{fakeToken("xapp-"), "a Slack token"},
	{fakeToken("xoxe.xapp-"), "a Slack token"},
	{fakeToken("xwfp-"), "a Slack token"},
	{"--token=" + fakeToken("ghp_"), "a GitHub token"},                       // after a character that is not a word's
	{"Bearer " + fakeToken("xoxb-"), "a Slack token"},                        // after a space
	{"\t" + fakeToken("ghp_"), "a GitHub token"},                             // shown quoted, after the escape \t
	{"\x9b" + fakeToken("xoxb-"), "a Slack token"},                           // shown quoted, after the escape \x9b
	{"x\n" + fakeToken("ghp_"), "a GitHub token"},                            // shown quoted, after the escape \n
	{"x\u00a0" + fakeToken("ghp_"), "a GitHub token"},                        // shown quoted, after a no-break space's escape
	{"host=db\n" + "password=Q7Q7Q7", "a connection string with a password"}, // after an escaped line break
	{"ghp_" + strings.Repeat("Q", 10), "a GitHub token"},                     // the fewest token characters a prefix takes
	{"postgres://app:" + "Q7Q7Q7" + "@db.example/app", "a connection string with a password"},
	{"Server=db.example;User Id=app;" + "Password=Q7Q7Q7", "a connection string with a password"},
	{"Host=db.example;" + "PWD=Q7Q7Q7", "a connection string with a password"},
	{"host=db.example user=app " + "password=Q7Q7Q7", "a connection string with a password"}, // libpq's keyword form
	{"postgres://db.example/app?user=app&" + "password=Q7Q7Q7", "a connection string with a password"},
	{"Password=" + "Q7Q7Q7", "a connection string with a password"},
	{"Server=db," + "password=Q7Q7Q7", "a connection string with a password"},
	{"postgres://db.example/app?" + "password=Q7Q7Q7", "a connection string with a password"},
	{"host=db.example," + "password=Q7Q7Q7", "a connection string with a password"},
	{"host=db.example " + "password = Q7Q7Q7", "a connection string with a password"},
	{"xoxb-" + "1234-5678-abcdQ7", "a Slack token"}, // a dashed tail, as Slack's are
	{"x\r" + fakeToken("ghp_"), "a GitHub token"},   // after each escape strconv.Quote writes for a character that is not printable
	{"x\a" + fakeToken("ghp_"), "a GitHub token"},
	{"x\b" + fakeToken("ghp_"), "a GitHub token"},
	{"x\f" + fakeToken("ghp_"), "a GitHub token"},
	{"x\v" + fakeToken("ghp_"), "a GitHub token"},
	{"x\U000e0001" + fakeToken("ghp_"), "a GitHub token"},
	{"x\U000f0000" + fakeToken("ghp_"), "a GitHub token"},
	{"100% " + fakeToken("ghp_"), "a GitHub token"},         // a % that is no escape
	{"ghp_" + strings.Repeat("q7", 18), "a GitHub token"},   // a tail in lower case
	{"ghp_Q_" + strings.Repeat("Q7", 18), "a GitHub token"}, // an underscore in the tail
	{fakeJWT(), "a JWT"},
	{"Bearer " + fakeJWT(), "a JWT"},   // as an Authorization header's value
	{"x\n" + fakeJWT(), "a JWT"},       // shown quoted, after the escape \n
	{"Bearer%20" + fakeJWT(), "a JWT"}, // percent-escaped, as a URL's path shows it
}

// kindRefusal is the refusal of a setting, named as given, whose value looks like class: shown by its
// length in characters only.
func kindRefusal(name, value, class string) string {
	return name + ": want a value that is not a secret (give a secret only in a secret setting's file); got a value (" +
		strconv.Itoa(utf8.RuneCountInString(value)) + " characters, not shown): it looks like " + class
}

// A value that looks like a secret, in a setting that is not secret, is refused naming the setting
// and the kind, never the value, before any parser reads it or anything shows it: accepted,
// --print-config and the startup log would show it (#495). One setting shown as given, and a gate
// list, take every kind; every setting takes one (TestEverySettingThatIsNotSecretRefusesASecretItWouldShow).
func TestASecretPastedIntoASettingThatIsNotSecretIsRefusedByItsKind(t *testing.T) {
	for _, name := range []string{"operator-name", "gate-roles"} {
		s := lookup(name)
		c := readContextOf(s)
		for _, k := range secretKinds {
			_, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+k.value), c.files)
			if want := kindRefusal(s.Env(), k.value, k.class); !isConfigError(err) || err.Error() != want {
				t.Errorf("%s=<%s>: %v\nwant %s", s.Env(), k.class, err, want)
			}
		}
		// The flag is named as given.
		k := secretKinds[0]
		if _, _, err := Load(append(slices.Clone(c.args), "--"+name+"="+k.value), c.env, c.files); !isConfigError(err) || err.Error() != kindRefusal("--"+name, k.value, k.class) {
			t.Errorf("--%s=<%s>: %v, want it named as the flag", name, k.class, err)
		}
	}
}

// Every setting that shows a secret is refused, not only the first, so an operator fixes them all at once.
func TestEverySettingThatShowsASecretIsRefusedTogether(t *testing.T) {
	tok := fakeToken("ghp_")
	_, err := load(t, nil, "BYWARD_OPERATOR_NAME="+tok, "BYWARD_RESOURCE_NAME="+tok)
	want := kindRefusal("BYWARD_RESOURCE_NAME", tok, "a GitHub token") + "; " + kindRefusal("BYWARD_OPERATOR_NAME", tok, "a GitHub token")
	if !isConfigError(err) || err.Error() != want {
		t.Fatalf("%v\nwant %s", err, want)
	}
}

// secretKind names each kind, and nothing else: a prefix named in prose, with too few token
// characters after it, inside a word, split from its tail by a space or tab, or followed by _
// rather than a letter or digit, is no token; a URL with a user but no password, or an empty one,
// a / before what looks like a password, a key=value that is not a password, and a key that only
// starts or ends with "password" are no connection string.
func TestSecretKindNamesOnlyTheKindsItLists(t *testing.T) {
	for _, k := range secretKinds {
		if got := secretKind(k.value); got != k.class {
			t.Errorf("secretKind(<%s>) = %q, want %q", k.class, got, k.class)
		}
	}
	for _, s := range []string{"ghp_", "xoxb-", "ghp_ tokens", "ghp_short", "xoxb-style", "ghp_" + strings.Repeat("Q", 9),
		"ghp__" + strings.Repeat("Q", 10), "app-" + fakeToken("ghp_"), "my.xoxb-" + strings.Repeat("Q", 10),
		"team_ghs_" + strings.Repeat("Q", 10), "a" + fakeToken("ghp_"), "1" + fakeToken("ghp_"), "MCP.User", "byward-users",
		"/byward-users", "https://app.example/client.json", "postgres://db.example/app", "postgres://app@db.example/app",
		"user@example.com", "Server=db;Database=app", "a=b", "OldPassword=x", "passwords=many", "00000000-0000-0000-0000-000000000000",
		"A" + fakeToken("ghp_"), "ghp_\t" + strings.Repeat("Q7", 18), "https://h.example/a:b@c", "https://h.example:8080/pkg@1.0",
		"postgres://app:@db.example/app", "a+password=b",
		"docs at https://docs.example: ask ops@example.com",        // a space ends a URL's password
		"docs at https://docs.example see ops:on-call@example.com", // and its user name
		"https://ops@a.example:8443,ops@example.com",               // an @ ends a URL's user name
		"smtp://ops:@mail.example,ops@example.com"} {               // and its password
		if got := secretKind(s); got != "" {
			t.Errorf("secretKind(%q) = %q, want none", s, got)
		}
	}
}

// unshownSettings are the settings that are not secret yet need no check for a secret: their
// shape never shows what they hold. Each is pinned with its reason.
var unshownSettings = map[string]string{}

// shownTokens are a GitHub token in a value of s's shape, placed where the shape shows it (whole, as
// a command's program, or in a URL's path, the first its shape shows), plainly and after a
// character the shape shows escaped; none when it shows none of these places.
func shownTokens(s Setting) []string {
	tok := fakeToken("ghp_")
	for _, p := range []struct{ plain, escaped string }{
		{tok, "x\n" + tok},
		{`["` + tok + `"]`, `["x\n` + tok + `"]`},
		{"https://h.example/" + tok, "https://h.example/x%0A" + tok},
	} {
		if strings.Contains(s.shape.display(p.plain), tok) {
			return []string{p.plain, p.escaped}
		}
	}
	return nil
}

// Every setting that is not secret refuses a secret it would show, in a context where it is read,
// unless unshownSettings names it with a reason: the check runs on every setting by default, so a
// new one is covered with no code to add, and this fails naming any that is not (#495).
func TestEverySettingThatIsNotSecretRefusesASecretItWouldShow(t *testing.T) {
	checked := 0
	for _, s := range registry {
		if s.Secret() {
			continue
		}
		c := readContextOf(s)
		values := shownTokens(s)
		_, unshown := unshownSettings[s.Name]
		if values == nil && !unshown {
			t.Errorf("%s's shape shows a token in none of shownTokens' places: add the place it shows one, or, if it never does, name the setting in unshownSettings with that reason", s.Env())
		}
		for _, value := range values {
			_, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+value), c.files)
			refused := isConfigError(err) && err.Error() == kindRefusal(s.Env(), value, "a GitHub token")
			switch {
			case unshown && refused:
				t.Errorf("%s refuses a secret it would show, though unshownSettings lists it: remove it there", s.Env())
			case !unshown && !refused:
				t.Errorf("%s=%q (with a GitHub token): %v; want it refused by its kind (parseSecretKinds), or name the setting in unshownSettings with the reason it never shows it", s.Env(), strings.ReplaceAll(value, fakeToken("ghp_"), "<token>"), err)
			}
		}
		checked++
	}
	if checked < 66 {
		t.Fatalf("%d settings checked, want every one that is not secret (66 today)", checked)
	}
}

// A realistic value of each setting that holds free text, a name or a host still loads: the kinds
// are narrow enough not to refuse what an operator means.
func TestARealisticValueOfAFreeTextSettingIsNoSecret(t *testing.T) {
	for name, value := range map[string]string{
		"upstream-credential-header": "X-Api-Key",
		"upstream-strip-headers":     "X-Debug-Token, X-Atlassian-Base-Url",
		"allowed-hosts":              "mcp.example.com, 127.0.0.1:8080",
		"scope":                      "mcp",
		"resource-name":              "Acme MCP (password reset tools)",
		"operator-name":              "Acme Corp. IT, xoxb-style bots welcome",
		"scope-description":          "Read dashboards; no passwords are stored",
		"oidc-client-id":             "byward-proxy",
		"oidc-client-key-id":         "ghp-key-2026",
		"oidc-scopes":                "groups, roles",
		"oidc-subject-claim":         "sub",
		"oidc-roles-claim":           "https://example.com/roles",
		"oidc-groups-claim":          "groups",
		"oidc-name":                  "Acme SSO",
		"assertion-header":           "X-Byward-Identity",
		"obo-header":                 "X-Byward-Downstream-Token",
		"client-denylist":            "bad.example, https://bad.example/client.json",
		"cimd-trusted-hosts":         "app.example",
		"cimd-allowed-hosts":         "app.example",
	} {
		s := lookup(name)
		c := readContextOf(s)
		if _, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+value), c.files); err != nil {
			t.Errorf("%s=%q: %v, want it to load", s.Env(), value, err)
		}
	}
}

// A Bearer or Basic word in free text is no secret: logging.LooksSecret matches it, to hide a value
// in a log line, but config refuses only what holds a credential's shape, a JWT here (#495). These
// rows fail if config refuses by LooksSecret instead of logging.HoldsJWT.
func TestABearerOrBasicWordInFreeTextLoads(t *testing.T) {
	for _, name := range []string{"resource-name", "operator-name", "scope-description", "oidc-name"} {
		s := lookup(name)
		c := readContextOf(s)
		for _, value := range []string{"Basic read access to your dashboards", "Ann Basic Lee", "Bearer API", "Basic tier", "Read the bearer bonds ledger"} {
			if _, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+value), c.files); err != nil {
				t.Errorf("%s=%q: %v, want it to load", s.Env(), value, err)
			}
		}
	}
}

// A list with a secret in two entries is refused once, as any setting is.
func TestAListWithTwoSecretsIsRefusedOnce(t *testing.T) {
	tok := fakeToken("ghp_")
	s := lookup("gate-roles")
	c := readContextOf(s)
	v := tok + "," + tok
	_, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+v), c.files)
	if want := kindRefusal(s.Env(), v, "a GitHub token"); !isConfigError(err) || err.Error() != want {
		t.Errorf("%v\nwant %s", err, want)
	}
}

// A list setting whose entries can hold an @ loads with a later entry holding one: no entry holds a
// comma, so each is read on its own, and a comma, which is a URL user part's character to
// urlPassword in any other setting (TestWhatAShapeShowsIsWhatIsChecked), never joins two entries
// into one user part. A list whose entries refuse an @ refuses it by its own rule. A connection
// string whose password a comma split is refused all the same, as the list shows it whole
// (splitPassword): an entry scheme://X:Y, Y no port, then an @ before any / in a later entry.
func TestAListWithAnAtInALaterEntryLoads(t *testing.T) {
	appOn := append(slices.Clone(base), "BYWARD_APP_TOKENS=entra")
	for _, tc := range []struct {
		env   []string
		files readFileFunc
		kv    string
		want  string // "" when it loads, or the setting's own refusal
	}{
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=admin,https://byward.example/roles/mcp-user,ops@example.com", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=urn:byward:role:admin,ops@example.com", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=https://a.example:8443,ops@example.com", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=https://byward.example,urn:byward:admin,ops@example.com", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=api://byward:read,api://byward:write", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=ops@example.com,api://byward:read", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=api://byward:read,https://idp.example/groups/@sre", ""},
		{oidcBase, oidcFiles, "BYWARD_GATE_ROLES=postgres://app:Hun," + "ter2Q7@db/x",
			kindRefusal("BYWARD_GATE_ROLES", "postgres://app:Hun,"+"ter2Q7@db/x", "a connection string with a password")},
		{oidcBase, oidcFiles, "BYWARD_OIDC_SCOPES=openid,postgres://app:Hun," + "ter2Q7@db/x",
			kindRefusal("BYWARD_OIDC_SCOPES", "openid,postgres://app:Hun,"+"ter2Q7@db/x", "a connection string with a password")},
		{oidcBase, oidcFiles, "BYWARD_GATE_GROUPS=engineering,https://idp.example/groups/sre,ops@example.com", ""},
		{base, baseFiles, "BYWARD_GATE_ROLES=Tasks.Read,api://byward/Tasks.Write,ops@example.com", ""},
		{appOn, baseFiles, "BYWARD_APP_ROLES=Tasks.Read,api://byward/Tasks.Write,ops@example.com", ""},
		{oidcBase, oidcFiles, "BYWARD_OIDC_SCOPES=openid,api://byward/mcp.read,ops@example.com", ""},
		{base, baseFiles, "BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Send@me", ""},
		{base, baseFiles, "BYWARD_GATE_EMAIL_DOMAINS=example.com,ops@example.com",
			"BYWARD_GATE_EMAIL_DOMAINS: want domain names such as example.com, without @ or wildcards; got entry 2 of 2 (15 characters, not shown): it is not a domain name"},
	} {
		_, _, err := Load(nil, append(slices.Clone(tc.env), tc.kv), tc.files)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v, want it to load", tc.kv, err)
		case tc.want != "" && (!isConfigError(err) || err.Error() != tc.want):
			t.Errorf("%s: %v\nwant %s", tc.kv, err, tc.want)
		}
	}
}

// What a shape shows is what is checked: a token or a URL's password shown, escaped or not, is
// refused; what a URL setting never shows (its user part, query or fragment) is left to its own
// rule; and a percent-escape is undone once, as a reader decodes it, so %255F reads as %5F.
func TestWhatAShapeShowsIsWhatIsChecked(t *testing.T) {
	tok := fakeToken("ghp_")
	const kind = "kind"         // refused as a GitHub token
	const password = "password" // refused as a connection string with a password
	const nbsp = "\u00a0"       // not printable to strconv.Quote, so the value is shown quoted
	for _, tc := range []struct {
		name, setting, value string
		want                 string // kind, "" when it loads, or the setting's own refusal
	}{
		{"a token in a command's quoted program", "upstream-command", `["x\n` + tok + `", "--flag"]`, kind},
		{"a token percent-escaped in a URL's path", "upstream-url", "https://up.example/ghp%5F" + strings.Repeat("Q7", 18), kind},
		{"a token percent-escaped in lower case", "upstream-url", "https://up.example/ghp%5f" + strings.Repeat("Q7", 18), kind},
		{"a token percent-escaped after an escape", "operator-name", "x\t%67hp_" + strings.Repeat("Q7", 18), kind},
		{"a token percent-escaped after a % that is no escape", "operator-name", "100% %67hp_" + strings.Repeat("Q7", 18), kind},
		{"a % with one hex digit before a token", "operator-name", "%5" + tok, ""},
		{"a %-escaped / in a URL's password", "operator-name", "postgres://app:" + "p%2FQ7" + "@db.example/app", password},
		{"a token escaped twice in a URL's path", "upstream-url", "https://up.example/ghp%255F" + strings.Repeat("Q7", 18), ""},
		{"a token escaped beside a % that is no escape", "upstream-strip-headers", "%67hp_" + strings.Repeat("Q7", 18) + ",X-100%", kind},
		{"a token in a URL's query", "upstream-url", "https://up.example/mcp?k=" + tok, ""},
		{"a token in a URL's fragment", "upstream-url", "https://up.example/mcp#" + tok, ""},
		{"a backslash in a quoted URL's password", "operator-name", `postgres://app:p\Q7q7Q7@db/x` + nbsp, password},
		{"a quote in a quoted URL's password", "operator-name", `postgres://app:p"Q7q7Q7@db/x` + nbsp, password},
		{"an escape in a URL's password", "operator-name", "postgres://app:p" + nbsp + "Q7q7Q7@db/x", password},
		{"an escape in a URL's user name", "operator-name", "postgres://a\tpp:Q7q7Q7@db/x", password},
		{"an escape in a percent-escaped URL's user name", "operator-name", "postgres%3A%2F%2Fu\x01%3A" + "Q7q7Q7%40db", password},
		{"a percent-escaped tab in a percent-escaped URL's user name", "operator-name", "postgres%3A%2F%2Fa%09pp%3A" + "Q7q7Q7%40db", password},
		{"a percent-escaped space in a percent-escaped URL's user name", "operator-name", "postgres%3A%2F%2Fa%20pp%3A" + "Q7q7Q7%40db", password},
		{"a percent-escaped tab in a percent-escaped URL's password", "operator-name", "postgres%3A%2F%2Fapp%3AQ7%09" + "q7Q7%40db", password},
		{"a password key percent-escaped after an escape", "operator-name", "host=db\tpassword%3D" + "Q7Q7Q7", password},
		{"a password key after a percent-escaped control character", "operator-name", "host%3Ddb%01password%3D" + "Q7Q7Q7", password},
		{"a password key starting a value shown quoted", "operator-name", "password=" + "Q7Q7Q7\t", password},
		{"a password key after a percent-escaped DEL", "operator-name", "host%3Ddb%7Fpassword%3D" + "Q7Q7Q7", password},
		{"a password key starting a list shown quoted", "gate-roles", "pwd=" + "Q7Q7Q7,a\u00a0", password},
		{"an escape in a URL's user name and a %-escaped / in its password", "operator-name", "postgres://a\tpp:p%2F" + "Q7q7Q7@db/x", password},
		{"a comma in a URL's password", "operator-name", "postgres://app:Hun," + "ter2Q7@db.example/app", password},
		{"a comma in a URL's user name", "resource-name", "postgres://a,pp:" + "Q7Q7Q7@db.example/app", password},
		{"a URL with a port and no path, then an @", "operator-name", "https://a.example:8443," + "ops@example.com", password},
		{"an escape between a prefix and its tail", "resource-name", "ghp_\t" + strings.Repeat("Q7", 18), ""},
		{"a password in a URL's user part", "upstream-url", "https://app:" + "Q7Q7Q7" + "@up.example/mcp",
			"BYWARD_UPSTREAM_URL: want an absolute http(s) URL such as http://127.0.0.1:9000/mcp; got a value (33 characters, not shown): it holds a user name or password (or BYWARD_UPSTREAM_COMMAND, or a command after --)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lookup(tc.setting)
			c := readContextOf(s)
			_, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+tc.value), c.files)
			want := tc.want
			switch want {
			case kind:
				want = kindRefusal(s.Env(), tc.value, "a GitHub token")
			case password:
				want = kindRefusal(s.Env(), tc.value, "a connection string with a password")
			}
			switch {
			case want == "" && err != nil:
				t.Errorf("%v, want it to load", err)
			case want != "" && (!isConfigError(err) || err.Error() != want):
				t.Errorf("%v\nwant %s", err, want)
			}
		})
	}
}

// examplePattern is a setting given in a document, its value plain or quoted: BYWARD_X=value,
// BYWARD_X: value (compose), - {name: BYWARD_X, value: v} (Kubernetes), --x=value, --x value, or a
// table row | `BYWARD_X` | `value` |.
var examplePattern = regexp.MustCompile("(BYWARD_[A-Z0-9_]+|--[a-z0-9-]+)(?:=|:[ \\t]+|,[ \\t]*value:[ \\t]+| +|`\\s*\\|\\s*`)(?:\"([^\"\\n]*)\"|'([^'\\n]*)'|([^\\s\"'`|)}]+))")

// examplePattern reads a setting's name and value from each form a document gives one in, so the
// docs walk's floor never has to stand in for a form it lost.
func TestExamplePatternReadsEachDocumentedForm(t *testing.T) {
	for _, tc := range []struct{ line, name, value string }{
		{"BYWARD_OPERATOR_NAME=Ops", "BYWARD_OPERATOR_NAME", "Ops"},
		{`BYWARD_OPERATOR_NAME="Ops team"`, "BYWARD_OPERATOR_NAME", "Ops team"},
		{"BYWARD_OPERATOR_NAME='Ops team'", "BYWARD_OPERATOR_NAME", "Ops team"},
		{"      BYWARD_OPERATOR_NAME: Ops", "BYWARD_OPERATOR_NAME", "Ops"},
		{"  - {name: BYWARD_OPERATOR_NAME, value: Ops}", "BYWARD_OPERATOR_NAME", "Ops"},
		{"byward --operator-name=Ops", "--operator-name", "Ops"},
		{"byward --operator-name Ops", "--operator-name", "Ops"},
		{"byward --operator-name  Ops", "--operator-name", "Ops"},
		{"      BYWARD_OPERATOR_NAME:\tOps", "BYWARD_OPERATOR_NAME", "Ops"},
		{"| `BYWARD_OPERATOR_NAME` | `Ops` |", "BYWARD_OPERATOR_NAME", "Ops"},
	} {
		m := examplePattern.FindStringSubmatch(tc.line)
		if m == nil || m[1] != tc.name || m[2]+m[3]+m[4] != tc.value {
			t.Errorf("examplePattern in %q = %q, want %s and %q", tc.line, m, tc.name, tc.value)
		}
	}
}

// No example the docs, scripts or Dockerfile give for a setting that is not secret looks like a
// secret, so an operator who copies one is never refused by its kind.
func TestNoDocumentedExampleLooksLikeASecret(t *testing.T) {
	root := filepath.Join("..", "..")
	byName := map[string]Setting{}
	for _, s := range registry {
		if !s.Secret() {
			byName[s.Env()], byName["--"+s.Name] = s, s
		}
	}
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") || slices.Contains(skippedDirs, d.Name())):
			return filepath.SkipDir
		case d.IsDir() || !strings.HasSuffix(p, ".md") && !strings.HasSuffix(p, ".sh") && d.Name() != "Dockerfile":
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the repository's own documents
		if err != nil {
			return err
		}
		for _, m := range examplePattern.FindAllStringSubmatch(string(b), -1) {
			s, ok := byName[m[1]]
			value := m[2] + m[3] + m[4]
			if !ok || value == "" || strings.ContainsAny(value[:1], "$<") || strings.HasPrefix(value, "BYWARD_") || strings.HasPrefix(value, "--") {
				continue // a secret's, an unknown name, a placeholder, or another setting's name
			}
			n++
			if k := shownKind(s.shape.display(value)); k != "" {
				t.Errorf("%s: %s=%q looks like %s", p, m[1], value, k)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 150 {
		t.Fatalf("%d documented examples found, want them all (160 today)", n)
	}
}
