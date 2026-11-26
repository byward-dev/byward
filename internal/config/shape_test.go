package config

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// shapeSettings is a shape, its name in messages and the settings that have it.
type shapeSettings struct {
	name     string
	shape    *shape
	settings []string
}

// shapesOfSettings names each shape and lists, literally, the settings that have it. Giving a
// setting another shape, or a new setting any shape, is a reviewed change to this table: shown as
// given above all, since the leak test lets such a setting show what it accepted
// (TestNoCommandShowsAHiddenOrARefusedValue, cmd/byward). A setting given a new
// shape, such as #486's host rule, leaves the as-given list here.
var shapesOfSettings = []shapeSettings{
	{"secret", secretShape, []string{
		"upstream-credential", "upstream-env", "entra-client-secret", "entra-client-certificate",
		"oidc-client-secret", "oidc-client-key", "store-postgres-dsn"}},
	{"URL", urlShape, []string{"public-url", "upstream-url", "resource-documentation", "oidc-issuer"}},
	{"URL list", urlListShape, []string{"client-denylist"}},
	{"list", listShape, []string{
		"upstream-strip-headers", "allowed-origins", "allowed-hosts", "trusted-proxies", "oauth-rate-limits",
		"oidc-scopes", "assertion-claims", "gate-tenants", "gate-roles", "gate-groups", "gate-email-domains",
		"gate-hosted-domains", "cimd-trusted-hosts", "cimd-allowed-hosts", "app-roles", "app-client-ids"}},
	{"command", commandShape, []string{"upstream-command"}},
	{"path", pathShape, []string{
		"tls-cert-file", "tls-key-file", "entra-federated-token-file", "data-dir", "keys-dir", "assertion-keys-dir",
		"static-clients-file", "store-dir", "store-counter-file"}},
	{"as given", asGivenShape, []string{
		"upstream-header-timeout", "upstream-credential-header", "stdio-max-processes", "stdio-max-processes-per-user",
		"stdio-stream-idle-timeout", "listen", "scope", "resource-name", "log-format", "internal-listen",
		"idp", "entra-tenant", "entra-client-id", "entra-client-secret-expires-at", "oidc-client-id",
		"oidc-client-key-alg", "oidc-client-key-id", "oidc-subject-claim", "oidc-roles-claim",
		"oidc-groups-claim", "oidc-name", "assertion-header", "identity-headers", "obo-scopes",
		"obo-header", "assertion-unverified-email", "dcr", "cimd", "app-tokens", "gate-allow-empty",
		"operator-name", "scope-description", "refresh-grace", "insecure-no-auth", "dev"}},
}

// Each shape is given to exactly the settings shapesOfSettings lists, and every registry setting is
// in one of its lists.
func TestTheSettingsOfEachShapeAreExactlyThese(t *testing.T) {
	listed := 0
	for _, c := range shapesOfSettings {
		var got []string
		for _, s := range registry {
			if s.shape == c.shape {
				got = append(got, s.Name)
			}
		}
		if !slices.Equal(got, c.settings) {
			t.Errorf("the %s shape is given to %q, want %q (in registry order): a setting changes shape only by a reviewed change to this table, shown as given above all (ADR-0031 §2)", c.name, got, c.settings)
		}
		listed += len(c.settings)
	}
	for _, s := range registry {
		if !slices.ContainsFunc(shapesOfSettings, func(c shapeSettings) bool { return c.shape == s.shape }) {
			t.Errorf("%s has no shape, or one shapesOfSettings does not list", s.Name)
		}
	}
	if listed != len(registry) {
		t.Errorf("shapesOfSettings lists %d settings, the registry has %d", listed, len(registry))
	}
}

// checkShapes panics on a registry with a setting that has no shape, naming it; init runs it on the
// real registry, so the program stops before it shows any value (ADR-0031 §3). The real registry
// passes it, which TestTheSettingsOfEachShapeAreExactlyThese also checks.
func TestCheckShapesRefusesASettingWithoutAShape(t *testing.T) {
	checkShapes(registry) // a second catch for the real registry, should init stop calling it
	defer func() {
		if r := recover(); r != "config: setting no-shape has no shape" {
			t.Fatalf("recovered %v, want the panic naming the setting", r)
		}
	}()
	checkShapes([]Setting{{Name: "shaped", shape: asGivenShape}, {Name: "no-shape"}})
}

// Each shape in shapesOfSettings shows an accepted value by its own rule; a shape without an example
// here fails.
func TestEachShapeShowsAnAcceptedValueByItsRule(t *testing.T) {
	examples := map[string]struct{ raw, shown string }{
		"secret":   {"S3CRET", "<redacted>"},
		"URL":      {"https://u:p@h.example/x;s=1?k=S3CRET#f", "https://h.example/x;…?…#…"},
		"URL list": {"https://h.example/x?k=S3CRET,bad.example", "https://h.example/x?…, bad.example"},
		"command":  {`["/bin/server","--token","S3CRET"]`, "/bin/server (2 arguments not shown)"},
		"as given": {"https://u:p@h.example/x?k=v", "https://u:p@h.example/x?k=v"},
		"list":     {"a.example, b.example", "a.example, b.example"},
		"path":     {"/var/lib/byward/keys", "/var/lib/byward/keys"},
	}
	for _, c := range shapesOfSettings {
		e, ok := examples[c.name]
		if !ok {
			t.Errorf("the %s shape has no example here: add one showing an accepted value by its rule", c.name)
			continue
		}
		delete(examples, c.name)
		if got := (Value{Setting: Setting{shape: c.shape}, Given: NewOpaque(e.raw)}).Display(); got != e.shown {
			t.Errorf("the %s shape shows %q as %q, want %q", c.name, e.raw, got, e.shown)
		}
	}
	for name := range examples {
		t.Errorf("an example names the %s shape, which shapesOfSettings does not list", name)
	}
}

// A value a shape shows as given is quoted when it holds a character that is not printable or a byte
// that is not UTF-8, so it never starts a line of its own in --print-config, where it could forge
// another setting's line (#505): the as-given shape's whole value and a URL list's entry that is not
// a URL (the command's program: TestTheUpstreamCommandIsShownByItsProgramAndArgumentCount). A
// printable value, non-ASCII included, is shown unquoted.
func TestAValueShownAsGivenIsQuotedWhenItHoldsACharacterThatIsNotPrintableOrAByteThatIsNotUTF8(t *testing.T) {
	for _, c := range []struct {
		name  string
		shape *shape
		raw   string
		shown string
	}{
		{"as given, a newline", asGivenShape, "x\nBYWARD_ENTRA_CLIENT_SECRET=<redacted> (file)", `"x\nBYWARD_ENTRA_CLIENT_SECRET=<redacted> (file)"`},
		{"as given, a carriage return", asGivenShape, "x\rBYWARD_DEV=true", `"x\rBYWARD_DEV=true"`},
		{"as given, a terminal escape", asGivenShape, "x\x1b[2K", `"x\x1b[2K"`},
		{"as given, a tab", asGivenShape, "a\tb", `"a\tb"`},
		{"as given, DEL", asGivenShape, "a\x7fb", `"a\x7fb"`},
		{"as given, a C1 control", asGivenShape, "a\u0085b", `"a\u0085b"`},
		{"as given, a line separator", asGivenShape, "a\u2028b", `"a\u2028b"`},
		{"as given, a bidi override", asGivenShape, "a\u202eb", `"a\u202eb"`},
		{"as given, a no-break space", asGivenShape, "a\u00a0b", `"a\u00a0b"`},
		{"as given, a byte that is not UTF-8", asGivenShape, "a\x9bb", `"a\x9bb"`},
		{"as given, non-ASCII with a newline", asGivenShape, "Café\nx", `"Café\nx"`},
		{"as given, printable", asGivenShape, "Contoso IT", "Contoso IT"},
		{"as given, printable non-ASCII", asGivenShape, "Café Zürich", "Café Zürich"},
		{"URL list, an entry that is not a URL, with a newline", urlListShape, "https://h.example/x?k=1,bad\nBYWARD_DEV=true", `https://h.example/x?…, "bad\nBYWARD_DEV=true"`},
		{"URL list, a printable entry that is not a URL", urlListShape, "https://h.example/x,bad.example", "https://h.example/x, bad.example"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := (Value{Setting: Setting{shape: c.shape}, Given: NewOpaque(c.raw)}).Display(); got != c.shown {
				t.Errorf("Display of %q = %q, want %q", c.raw, got, c.shown)
			}
		})
	}
}

// A URL list shows an entry holding :// as the URL shape does, whatever its scheme's case and whatever
// it holds: escaped, without its query, or Hidden; never as given, which would show a query's secret
// or a raw character that is not printable (#458, #505).
func TestAURLListShowsAnEntryWithASchemeAsAURL(t *testing.T) {
	for raw, want := range map[string]string{
		"HTTPS://h.example/x?k=S3CRET":          "HTTPS://h.example/x?…",
		"https://h.example/a\u2028b,ok.example": "https://h.example/a%E2%80%A8b, ok.example",
		"https://h.example/x\nBYWARD_DEV=true":  "the value (not shown: it may hold a password)",
	} {
		if got := (Value{Setting: Setting{shape: urlListShape}, Given: NewOpaque(raw)}).Display(); got != want {
			t.Errorf("Display of %q = %q, want %q", raw, got, want)
		}
	}
}

// Every setting shows any value, whatever it holds, on one line of printable characters, so no value
// can start a line of its own in --print-config (#505). A setting whose shape forgets the rule, such
// as a new shape, fails here.
func TestEverySettingShowsAnyValueOnOneLineOfPrintableCharacters(t *testing.T) {
	hostile := []string{
		"x\nBYWARD_DEV=true", "x\r\nBYWARD_DEV=true", "x\x1b[2K", "a\u2028b", "a\x9bb", "a\tb", "a\x7fb",
		"a\u202eb", "a\u00a0b", "a\u0085b", "Café\nx",
		"https://h.example/a\nb", "https://h.example/a\u2028b?k=v", "https://h.example/x,bad\nc",
		"https://h.example/a%0Ab", "https://a\u0085b.example/",
		`["/bin/x\nBYWARD_DEV=true","a"]`, `["/bin/x\u2028y"]`, `{"k":"v\nBYWARD_DEV=true"}`,
	}
	for _, s := range registry {
		for _, raw := range hostile {
			got := Value{Setting: s, Given: NewOpaque(raw)}.Display()
			if !utf8.ValidString(got) || strings.ContainsFunc(got, func(r rune) bool { return !strconv.IsPrint(r) }) {
				t.Errorf("%s shows %q as %q: not one line of printable characters", s.Name, raw, got)
			}
		}
	}
}

// A Setting built without a shape, outside the registry, shows a value as Hidden, never whole.
func TestAValueOfASettingWithoutAShapeIsHidden(t *testing.T) {
	if got := (Value{Setting: Setting{Name: "not-in-the-registry"}, Given: NewOpaque("https://u:S3CRET@h.example/x")}).Display(); got != "the value (not shown: it may hold a password)" {
		t.Errorf("shown as %q, want it hidden", got)
	}
	if got := (Value{Setting: Setting{Name: "not-in-the-registry"}}).Display(); got != "" {
		t.Errorf("an unset value is shown as %q, want nothing", got)
	}
}

// newShape panics on a shape without its display or its refused function, so a half-built one stops
// the program at init.
func TestAShapeWithoutAFunctionCannotBeBuilt(t *testing.T) {
	show := func(raw string) string { return raw }
	for _, c := range []struct {
		name             string
		display, refused func(string) string
	}{
		{"no display", nil, show},
		{"no refused", show, nil},
		{"neither", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != "config: a shape needs both its display and its refused function" {
					t.Fatalf("recovered %v, want the shape's panic", r)
				}
			}()
			newShape(c.display, c.refused)
		})
	}
}

// Each shape's refused function gives a value's length only (ADR-0031 §1), in characters. Nothing
// calls it yet: #494 routes refusals through it.
func TestEachShapesRefusedFunctionGivesOnlyTheLength(t *testing.T) {
	for _, c := range shapesOfSettings {
		for value, want := range map[string]string{
			"https://u:S3CRET@h.example/x?k=S3CRET": "(37 characters, not shown)",
			"ä€":                                    "(2 characters, not shown)",
			"S":                                     "(1 character, not shown)",
			"":                                      "(0 characters, not shown)",
		} {
			if got := c.shape.refused(value); got != want {
				t.Errorf("the %s shape shows a refused %q as %q, want %q", c.name, value, got, want)
			}
		}
	}
}
