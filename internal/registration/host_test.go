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
		"app.example":             {"app.example", true},
		"App.Example.":            {"app.example", true},
		"app.example\u3002":       {"app.example", true}, // the host's own trailing full stop
		"app.example\uff0e":       {"app.example", true},
		"app.example\uff61":       {"app.example", true},
		"\u05d0a.example":         {"xn--a-zhc.example", false}, // a label mixing directions
		"\u05d0.example":          {"xn--4db.example", true},
		"XN--":                    {"xn--", false},       // the name is BrowserHost's even when refused
		"2001:DB8::1":             {"2001:db8::1", true}, // an IPv6 literal: no domain to map
		"::1":                     {"::1", true},
		"fe80::1%en0":             {"fe80::1%en0", false},             // a zone: the browser refuses it
		"xn--xn--abc-t2a.example": {"xn--xn--abc-t2a.example", false}, // decodes to a label starting xn--
		"a.xn--xn--abc-t2a":       {"a.xn--xn--abc-t2a", false},
		"a-xn--b.example":         {"a-xn--b.example", true}, // xn-- inside a label, not at its start
		"xn-a.example":            {"xn-a.example", true},    // starts xn-, not xn--
		"BÜCHER.example":          {"xn--bcher-kva.example", true},
		"ｍｙ_app.example":          {"my_app.example", true},
		"xn--bcher-kva.example":   {"xn--bcher-kva.example", true},
		"127.0.0.1":               {"127.0.0.1", true},
		"xn--claude-.ai":          {"claude.ai", false},          // invalid punycode: the mapping it got that far
		"a\u200db.example":        {"xn--ab-m1t.example", false}, // a joiner out of context
		"xn--":                    {"xn--", false},               // an empty label
		"xn--.example":            {".example", false},
		"a.xn--":                  {"a", false}, // a last label that decodes to nothing
		"a.xn--.":                 {"a.", false},
		"a..b.example":            {"a..b.example", false},
		"\u00ad":                  {"\u00ad", false}, // invisible characters only
		// A name that is, or maps to, a forbidden domain code point: the browser refuses it.
		"evil\uff20claude.example": {"evil@claude.example", false}, // an example domain: the privacy check reads a@b as an email
		"evil\uff1f.claude.ai":     {"evil?.claude.ai", false},
		"a\u3000b.claude.ai":       {"a b.claude.ai", false},
		"a\u2100b.example":         {"aa/cb.example", false},
		"a<b.claude.ai":            {"a<b.claude.ai", false},
		"a%62.example":             {"a%62.example", false},
		"a\uff03b.example":         {"a#b.example", false},
		"a\uff1ab.example":         {"a:b.example", false},
		"a\uff1eb.example":         {"a>b.example", false},
		"a\uff3bb.example":         {"a[b.example", false},
		"a\uff3cb.example":         {"a\\b.example", false},
		"a\uff3db.example":         {"a]b.example", false},
		"a\uff3eb.example":         {"a^b.example", false},
		"a\uff5cb.example":         {"a|b.example", false},
		"a\x7fb.example":           {"a\x7fb.example", false}, // DEL
		"":                         {"", false},
	} {
		if name, ok := BrowserHostOK(host); name != want.name || ok != want.ok {
			t.Errorf("BrowserHostOK(%q) = %q, %v; want %q, %v", host, name, ok, want.name, want.ok)
		}
	}
}

// BrowserUnicode decodes xn-- labels as a browser does, "_" included, and keeps a name that does not
// decode.
func TestBrowserUnicodeDecodesAsABrowserDoes(t *testing.T) {
	for ascii, want := range map[string]string{
		"xn--bcher-kva.example":  "b\u00fccher.example",
		"xn--b_cher-3ya.example": "b\u00fc_cher.example",
		"app.example":            "app.example",
		"xn--claude-.ai":         "xn--claude-.ai", // invalid punycode: kept, never claude.ai
	} {
		if got := BrowserUnicode(ascii); got != want {
			t.Errorf("BrowserUnicode(%q) = %q, want %q", ascii, got, want)
		}
	}
}
