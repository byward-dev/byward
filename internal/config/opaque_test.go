package config

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// canaryText stands for a secret given as a setting's value; no other text in these tests holds it.
const canaryText = "OPQ7CANARY"

// holdsCanary reports whether text holds canaryText in any case: a refusal could lower-case it.
func holdsCanary(text string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(canaryText))
}

// Every way Go formats or encodes a value shows an Opaque only by its length (ADR-0031 §1): each fmt
// verb, slog's text and JSON handlers, encoding/json and encoding.TextMarshaler. The value alone is
// shown as exactly its length, so no encoding of the text (hex, base64) passes; inside a struct,
// exported or not, a slice or a map, each holds the length and never the text. Only raw returns it.
func TestAnOpaqueValueIsShownOnlyByItsLength(t *testing.T) {
	o := NewOpaque("https://u:" + canaryText + "@h.example/x")
	const shown = "(32 characters, not shown)"
	j, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var tm encoding.TextMarshaler = o
	b, err := tm.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	exact := map[string]struct{ got, want string }{
		"String":      {o.String(), shown},
		"GoString":    {o.GoString(), "config.Opaque" + shown},
		"Sprint":      {fmt.Sprint(o), shown},
		"Sprintln":    {fmt.Sprintln(o), shown + "\n"},
		"json":        {string(j), `"` + shown + `"`},
		"MarshalText": {string(b), shown},
	}
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d", "%10.3s"} {
		exact[verb] = struct{ got, want string }{fmt.Sprintf(verb, o), shown}
	}
	for how, e := range exact {
		if e.got != e.want {
			t.Errorf("%s shows %q, want %q", how, e.got, e.want)
		}
	}
	type holder struct {
		Exported   Opaque
		unexported Opaque
	}
	h := holder{o, o}
	held := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
		held[verb+" of a struct"], held[verb+" of a pointer to it"] = fmt.Sprintf(verb, h), fmt.Sprintf(verb, &h)
	}
	for name, handler := range map[string]func(*bytes.Buffer) slog.Handler{
		"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"slog JSON": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var b bytes.Buffer
		slog.New(handler(&b)).Info("m", "value", o, "holder", h, slog.Any("any", o))
		held[name] = b.String()
	}
	for name, v := range map[string]any{"json of a struct": h, "json of a slice": []Opaque{o}, "json of a map": map[string]Opaque{"k": o}} {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		held[name] = string(j)
	}
	for how, text := range held {
		if !strings.Contains(text, shown) || holdsCanary(text) {
			t.Errorf("%s shows %q, want the length %s and never the text", how, text, shown)
		}
	}
	if o.raw() != "https://u:"+canaryText+"@h.example/x" {
		t.Errorf("raw = %q, want the text as given", o.raw())
	}
}

// An Opaque tells empty, blank and other text apart; the zero Opaque and one set to nothing are both
// empty.
func TestAnOpaqueValueTellsEmptyAndBlankApart(t *testing.T) {
	for _, tc := range []struct {
		name         string
		o            Opaque
		empty, blank bool
		shown        string
	}{
		{"the zero value", Opaque{}, true, true, "(empty)"},
		{"set to nothing", NewOpaque(""), true, true, "(empty)"},
		{"white space", NewOpaque(" \t"), false, true, "(2 characters, not shown)"},
		{"one character", NewOpaque("x"), false, false, "(1 character, not shown)"},
		{"a character that is not ASCII, counted once", NewOpaque("ü"), false, false, "(1 character, not shown)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.empty && tc.o.raw() != "" {
				t.Errorf("raw = %q, want nothing", tc.o.raw())
			}
			if tc.o.empty() != tc.empty || tc.o.blank() != tc.blank || tc.o.String() != tc.shown {
				t.Errorf("Empty %v, Blank %v, shown %q; want %v, %v, %q", tc.o.empty(), tc.o.blank(), tc.o.String(), tc.empty, tc.blank, tc.shown)
			}
		})
	}
}

// A refusal has one format, "BYWARD_X: want …; got …": a value or an entry refused for its form by
// its place and length, one refused for its meaning as the parser read it.
func TestARefusalHasOneFormat(t *testing.T) {
	s := Setting{Name: "allowed-hosts", shape: asGivenShape}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a value refused for its form", refusedForm(s, whole, "a"+canaryText, "a host", "it has no dot"),
			"BYWARD_ALLOWED_HOSTS: want a host; got a value (11 characters, not shown): it has no dot"},
		{"an entry refused for its form", refusedForm(s, entry{1, 3}, canaryText, "a host", "it has no dot"),
			"BYWARD_ALLOWED_HOSTS: want a host; got entry 2 of 3 (10 characters, not shown): it has no dot"},
		{"a value refused for its meaning", refusedMeaning(s, whole, "10.0.0.1", "a loopback host", "it is not loopback"),
			"BYWARD_ALLOWED_HOSTS: want a loopback host; got 10.0.0.1: it is not loopback"},
		{"an entry refused for its meaning", refusedMeaning(s, entry{0, 2}, "10.0.0.1", "a loopback host", "it is not loopback"),
			"BYWARD_ALLOWED_HOSTS: want a loopback host; got entry 1 of 2, 10.0.0.1: it is not loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !isConfigError(tc.err) || tc.err.Error() != tc.want {
				t.Errorf("got %v, want the configuration error %q", tc.err, tc.want)
			}
		})
	}
}

// #494: a listen address needs a host (empty, an IP address, a zoned IPv6 one included, or a host name,
// with one trailing dot at most) and a numeric port from 0 to 65535, as net.Listen takes them; a
// service name such as http is refused. A refused one is named by its length and why, never shown, so
// startup's net.Listen error can never quote it.
func TestAListenAddressNeedsAHostAndANumericPortAndARefusedOneIsNeverShown(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8080", ":8080", "[::1]:8080", "localhost:0", "0.0.0.0:65535", "byward.internal:8443",
		"[fe80::1%lo0]:8080", "byward.internal.:8443", "127.0.0.1:000080"} {
		for _, name := range []string{"BYWARD_LISTEN", "BYWARD_INTERNAL_LISTEN"} {
			if _, err := load(t, nil, "BYWARD_LISTEN=127.0.0.1:1", name+"="+ok); err != nil {
				t.Errorf("%s=%s: %v", name, ok, err)
			}
		}
	}
	for _, tc := range []struct{ value, why string }{
		{"8080", "it is not host:port"},
		{"https://u:" + canaryText + "@h.example/x", "it is not host:port"},
		{"//h.example/x?k=" + canaryText + ":80", "it has a host that is neither an IP address nor a host name"},
		{"h.example..:80", "it has a host that is neither an IP address nor a host name"},
		{"127.0.0.1:" + canaryText, "it has a port that is not a number"},
		{"127.0.0.1:http", "it has a port that is not a number"},
		{"127.0.0.1:", "it has a port that is not a number"},
		{"127.0.0.1:65536", "it has a port that is not a number from 0 to 65535"},
		{"127.0.0.1:+80", "it has a port that is not a number"},
		{"127.0.0.1:-1", "it has a port that is not a number"},
		{"127.0.0.1:99999999999999999999", "it has a port that is not a number from 0 to 65535"},
	} {
		for _, s := range []struct{ env, want string }{
			{"BYWARD_LISTEN", "host:port such as 127.0.0.1:8080"},
			{"BYWARD_INTERNAL_LISTEN", "host:port such as 127.0.0.1:9090, or empty"},
		} {
			want := fmt.Sprintf("%s: want %s; got a value (%d characters, not shown): %s", s.env, s.want, length(tc.value), tc.why)
			_, err := load(t, nil, s.env+"="+tc.value)
			if !isConfigError(err) || err.Error() != want || holdsCanary(err.Error()) {
				t.Errorf("%s=%s: %v, want the error %q and never the value", s.env, tc.value, err, want)
			}
		}
	}
}

// length is the number of characters notShown counts.
func length(s string) int { return len([]rune(s)) }

// #478: a URL whose scheme is mistyped in any of its seven ways, with a token in its path parameters,
// is refused by each URL and host setting, the OIDC issuer and the listen addresses, without any of it
// shown: neither the token nor the host. (BYWARD_OIDC_SCOPES takes any text without white space, a
// backslash or a double quote: #512.)
func TestAURLWithAMistypedSchemeIsRefusedWithoutAnyOfItShown(t *testing.T) {
	forms := []string{"https;//h.example/;tok=", "https//h.example/;tok=", "https: //h.example/;tok=", `https:\h.example/;tok=`,
		"//h.example/;tok=", "https:h.example/;tok=", "https:/h.example/;tok="}
	load := withConfig(t)
	for _, env := range []string{"BYWARD_PUBLIC_URL", "BYWARD_UPSTREAM_URL", "BYWARD_RESOURCE_DOCUMENTATION", "BYWARD_ALLOWED_ORIGINS",
		"BYWARD_ALLOWED_HOSTS", "BYWARD_CLIENT_DENYLIST", "BYWARD_CIMD_TRUSTED_HOSTS", "BYWARD_CIMD_ALLOWED_HOSTS", "BYWARD_TRUSTED_PROXIES",
		"BYWARD_OBO_SCOPES", "BYWARD_LISTEN", "BYWARD_INTERNAL_LISTEN"} {
		for _, form := range forms {
			value := form + canaryText
			err := load(env + "=" + value)
			// BYWARD_OBO_SCOPES splits at white space, so the form with a space is two refused entries.
			if !isConfigError(err) || !strings.Contains(err.Error(), env+": want ") || !strings.Contains(err.Error(), " characters, not shown): ") ||
				holdsCanary(err.Error()) || strings.Contains(err.Error(), "h.example") {
				t.Errorf("%s=%s: %v, want it refused by its length, and neither its token nor its host shown", env, value, err)
			}
		}
	}
	for _, form := range forms {
		value := form + canaryText
		_, err := loadOIDC(t, with("BYWARD_OIDC_ISSUER="+value))
		if !isConfigError(err) || !strings.Contains(err.Error(), " characters, not shown): ") || holdsCanary(err.Error()) || strings.Contains(err.Error(), "h.example") {
			t.Errorf("BYWARD_OIDC_ISSUER=%s: %v, want it refused by its length, and neither its token nor its host shown", value, err)
		}
	}
}

// An empty listen address is refused as nothing given, not as "0 characters".
func TestAnEmptyListenAddressIsRefusedAsNothingGiven(t *testing.T) {
	_, err := load(t, nil, "BYWARD_LISTEN=")
	if want := "BYWARD_LISTEN: want host:port such as 127.0.0.1:8080; got nothing"; !isConfigError(err) || err.Error() != want {
		t.Errorf("BYWARD_LISTEN=: %v, want %q", err, want)
	}
}

// Doctor names the upstream URL and the issuer only through their shapes: the upstream as parsed (the
// aud), the issuer as given or a preset's own. Values that do not hold the setting, as a Config built
// by hand has none, show it as Hidden, never as nothing a caller could take for unset, nor as given.
func TestASettingIsShownOnlyThroughItsShapeAndAsHiddenWhereTheValuesDoNotHoldIt(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"nil Values":                         (*Values)(nil).display("upstream-url"),
		"a name not a setting":               c.Values.display("upstream_url"),
		"a Config by hand, its upstream URL": (&Config{UpstreamURL: &url.URL{Scheme: "https", Host: "up.example", RawQuery: "k=" + canaryText}}).ShownUpstreamURL(),
		"a Config by hand, its issuer":       (&Config{OIDCIssuer: "https://u:" + canaryText + "@idp.example"}).ShownIssuer(),
		"Values without the issuer":          (&Config{OIDCIssuer: "https://idp.example/x?k=" + canaryText, Values: &Values{}}).ShownIssuer(),
	} {
		if got != logging.Hidden {
			t.Errorf("%s shows %q, want %q", name, got, logging.Hidden)
		}
	}
	for _, tc := range []struct {
		name, want string
		env        []string
	}{
		{"the upstream URL as parsed, its query left out", "https://up.example/mcp?…", []string{"BYWARD_UPSTREAM_URL=HTTPS://up.example/mcp?api_key=" + canaryText}},
		{"a stdio upstream, which has no URL", logging.Hidden, []string{"BYWARD_UPSTREAM_URL=", `BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`}},
	} {
		c, err := load(t, nil, tc.env...)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.ShownUpstreamURL(); got != tc.want {
			t.Errorf("%s: shown as %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct{ name, issuer, want string }{
		{"an issuer set, its path parameters left out", "https://idp.example/realms/a;k=" + canaryText, "https://idp.example/realms/a;…"},
		{"a preset's own issuer, the setting unset", "", "https://accounts.google.com"},
	} {
		c, err := loadOIDC(t, func(env []string) []string {
			return with("BYWARD_IDP=google", "BYWARD_OIDC_ISSUER="+tc.issuer)(without("BYWARD_IDP", "BYWARD_OIDC_ISSUER")(env))
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := c.ShownIssuer(); got != tc.want {
			t.Errorf("%s: shown as %q, want %q", tc.name, got, tc.want)
		}
	}
}

// An issuer that loads is kept byte for byte, as the IdP's discovery document states it: never as
// url.Parse would write it again.
func TestAnIssuerIsKeptExactlyAsGiven(t *testing.T) {
	for _, issuer := range []string{"HTTPS://sso.example.com/realms/Acme", "https://sso.example.com/realms/a%20b", "https://sso.example.com:443/realms/acme/"} {
		c, err := loadOIDC(t, with("BYWARD_OIDC_ISSUER="+issuer))
		if err != nil {
			t.Fatalf("%s: %v", issuer, err)
		}
		if c.OIDCIssuer != issuer {
			t.Errorf("%s: kept as %q, want it exactly as given", issuer, c.OIDCIssuer)
		}
	}
}

// An entry of BYWARD_CLIENT_DENYLIST that client registration refuses at wiring is named by its place
// and its length in characters, never shown, in the format of every refusal config makes.
func TestADenylistEntryRefusedAtWiringIsNamedByItsPlaceAndLength(t *testing.T) {
	c, err := load(t, nil, "BYWARD_CLIENT_DENYLIST=https://app.example:8443/bü-"+canaryText+".json, good.example")
	if err != nil {
		t.Fatal(err)
	}
	want := "BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 2 (43 characters, not shown): it is not a client ID metadata document URL: only port 443 is fetched"
	if got := c.RefusedDenylistEntry(0, "it is not a client ID metadata document URL: only port 443 is fetched"); !isConfigError(got) || got.Error() != want {
		t.Errorf("got %v, want %q", got, want)
	}
	c, err = load(t, nil, "BYWARD_CLIENT_DENYLIST=good.example, https://app.example:8443/c.json")
	if err != nil {
		t.Fatal(err)
	}
	want = "BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 2 of 2 (31 characters, not shown): it is not a client ID metadata document URL: only port 443 is fetched"
	if got := c.RefusedDenylistEntry(1, "it is not a client ID metadata document URL: only port 443 is fetched"); !isConfigError(got) || got.Error() != want {
		t.Errorf("the second entry: got %v, want %q", got, want)
	}
}

// get reads only a setting still read as text (readAsText), and panics on any other: a setting with a
// parser of its own is never read past it.
func TestGetPanicsOnASettingReadThroughItsParser(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("get read listen, which has a parser of its own, without a panic")
		}
	}()
	c.Values.get("listen")
}
