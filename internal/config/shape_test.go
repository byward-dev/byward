package config

import (
	"slices"
	"testing"
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
// (TestAnAcceptedValueOfAHidingSettingAppearsInNoCommandsOutput, cmd/byward). A setting given a new
// shape, such as #486's host rule, leaves the as-given list here.
var shapesOfSettings = []shapeSettings{
	{"secret", secretShape, []string{
		"upstream-credential", "upstream-env", "entra-client-secret", "entra-client-certificate",
		"oidc-client-secret", "oidc-client-key", "store-postgres-dsn"}},
	{"URL", urlShape, []string{"public-url", "upstream-url", "resource-documentation", "oidc-issuer"}},
	{"URL list", urlListShape, []string{"client-denylist"}},
	{"command", commandShape, []string{"upstream-command"}},
	{"as given", asGivenShape, []string{
		"upstream-header-timeout", "upstream-credential-header", "upstream-strip-headers",
		"stdio-max-processes", "stdio-max-processes-per-user", "stdio-stream-idle-timeout", "listen",
		"tls-cert-file", "tls-key-file", "allowed-origins", "allowed-hosts", "scope", "resource-name",
		"log-format", "trusted-proxies", "oauth-rate-limits", "internal-listen", "idp", "entra-tenant",
		"entra-client-id", "entra-federated-token-file", "entra-client-secret-expires-at", "oidc-client-id",
		"oidc-client-key-alg", "oidc-client-key-id", "oidc-scopes", "oidc-subject-claim", "oidc-roles-claim",
		"oidc-groups-claim", "oidc-name", "data-dir", "keys-dir", "assertion-keys-dir", "assertion-header",
		"identity-headers", "obo-scopes", "obo-header", "assertion-claims", "assertion-unverified-email",
		"static-clients-file", "gate-tenants", "gate-roles", "gate-groups", "gate-email-domains",
		"gate-hosted-domains", "dcr", "cimd", "cimd-trusted-hosts", "cimd-allowed-hosts", "app-tokens",
		"app-roles", "app-client-ids", "gate-allow-empty", "operator-name", "scope-description", "store-dir",
		"store-counter-file", "refresh-grace", "insecure-no-auth", "dev"}},
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
	}
	for _, c := range shapesOfSettings {
		e, ok := examples[c.name]
		if !ok {
			t.Errorf("the %s shape has no example here: add one showing an accepted value by its rule", c.name)
			continue
		}
		delete(examples, c.name)
		if got := (Value{Setting: Setting{shape: c.shape}, Raw: e.raw}).Display(); got != e.shown {
			t.Errorf("the %s shape shows %q as %q, want %q", c.name, e.raw, got, e.shown)
		}
	}
	for name := range examples {
		t.Errorf("an example names the %s shape, which shapesOfSettings does not list", name)
	}
}

// A Setting built without a shape, outside the registry, shows a value as Hidden, never whole.
func TestAValueOfASettingWithoutAShapeIsHidden(t *testing.T) {
	if got := (Value{Setting: Setting{Name: "not-in-the-registry"}, Raw: "https://u:S3CRET@h.example/x"}).Display(); got != "the value (not shown: it may hold a password)" {
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
