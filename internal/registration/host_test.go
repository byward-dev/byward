package registration

import "testing"

// BrowserHost is the ASCII name a browser goes to, the form the denylist compares and the consent
// page shows beside a Unicode spelling.
func TestBrowserHostIsTheASCIINameABrowserGoesTo(t *testing.T) {
	for host, want := range map[string]string{
		"App.Example.":          "app.example",
		"BÜCHER.example":        "xn--bcher-kva.example",
		"ａｐｐ。example":           "app.example",
		"ｍｙ_app.example":        "my_app.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"127.0.0.1":             "127.0.0.1",
		"XN--":                  "xn--", // maps to nothing: kept, lower-cased
	} {
		if got := BrowserHost(host); got != want {
			t.Errorf("BrowserHost(%q) = %q, want %q", host, got, want)
		}
	}
}

// BrowserHostOK tells a host a browser goes to from one it refuses or that no DNS name can be, where
// BrowserHost is only the mapping it got that far (xn--claude-.ai maps to claude.ai, but a browser
// refuses it).
func TestBrowserHostOKSaysWhetherABrowserGoesToTheHost(t *testing.T) {
	for host, want := range map[string]struct {
		name string
		ok   bool
	}{
		"app.example":           {"app.example", true},
		"App.Example.":          {"app.example", true},
		"app.example\u3002":     {"app.example", true}, // the host's own trailing full stop
		"app.example\uff0e":     {"app.example", true},
		"app.example\uff61":     {"app.example", true},
		"\u05d0a.example":       {"xn--a-zhc.example", false}, // a label mixing directions
		"\u05d0.example":        {"xn--4db.example", true},
		"XN--":                  {"xn--", false}, // the name is BrowserHost's even when refused
		"BÜCHER.example":        {"xn--bcher-kva.example", true},
		"ｍｙ_app.example":        {"my_app.example", true},
		"xn--bcher-kva.example": {"xn--bcher-kva.example", true},
		"127.0.0.1":             {"127.0.0.1", true},
		"xn--claude-.ai":        {"claude.ai", false},          // invalid punycode: the mapping it got that far
		"a\u200db.example":      {"xn--ab-m1t.example", false}, // a joiner out of context
		"xn--":                  {"xn--", false},               // an empty label
		"xn--.example":          {".example", false},
		"a.xn--":                {"a", false}, // a last label that decodes to nothing
		"a.xn--.":               {"a.", false},
		"a..b.example":          {"a..b.example", false},
		"\u00ad":                {"\u00ad", false}, // invisible characters only
		// A name that is, or maps to, a forbidden domain code point: the browser refuses it.
		"evil.example\uff20claude.ai": {"evil.example@claude.ai", false},
		"evil\uff1f.claude.ai":        {"evil?.claude.ai", false},
		"a\u3000b.claude.ai":          {"a b.claude.ai", false},
		"a\u2100b.example":            {"aa/cb.example", false},
		"a<b.claude.ai":               {"a<b.claude.ai", false},
		"a%62.example":                {"a%62.example", false},
		"":                            {"", false},
	} {
		if name, ok := BrowserHostOK(host); name != want.name || ok != want.ok {
			t.Errorf("BrowserHostOK(%q) = %q, %v; want %q, %v", host, name, ok, want.name, want.ok)
		}
	}
}
