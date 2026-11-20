package host

import "testing"

// BrowserName is the ASCII name a browser goes to, the form the denylist compares and the consent
// page shows beside a Unicode spelling.
func TestBrowserNameIsTheASCIINameABrowserGoesTo(t *testing.T) {
	for host, want := range map[string]string{
		"App.Example.":          "app.example",
		"BÜCHER.example":        "xn--bcher-kva.example",
		"ａｐｐ。example":           "app.example",
		"ｍｙ_app.example":        "my_app.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"127.0.0.1":             "127.0.0.1",
		"XN--":                  "xn--", // maps to nothing: kept, lower-cased
	} {
		if got := BrowserName(host); got != want {
			t.Errorf("BrowserName(%q) = %q, want %q", host, got, want)
		}
	}
}

// BrowserNameOK names a host a browser goes to as the browser does, and tells it from one the
// browser refuses or that no DNS name can be. For a refused host only the refusal is pinned: its name
// is the mapping x/net got that far (xn--claude-.ai maps to claude.ai), which no caller may use.
func TestBrowserNameOKSaysWhetherABrowserGoesToTheHost(t *testing.T) {
	for host, want := range map[string]string{
		"app.example":           "app.example",
		"App.Example.":          "app.example",
		"app.example\u3002":     "app.example", // the host's own trailing full stop
		"app.example\uff0e":     "app.example",
		"app.example\uff61":     "app.example",
		"\u05d0.example":        "xn--4db.example",
		"BÜCHER.example":        "xn--bcher-kva.example",
		"ｍｙ_app.example":        "my_app.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"a-xn--b.example":       "a-xn--b.example", // xn-- inside a label, not at its start
		"xn-a.example":          "xn-a.example",    // starts xn-, not xn--
		"127.0.0.1":             "127.0.0.1",
		"2001:DB8::1":           "2001:db8::1", // an IPv6 literal: no domain to map
		"::1":                   "::1",
	} {
		if name, ok := BrowserNameOK(host); name != want || !ok {
			t.Errorf("BrowserNameOK(%q) = %q, %v; want %q, true", host, name, ok, want)
		}
	}
	for _, host := range []string{
		"\u05d0a.example",         // a label mixing directions
		"a\u200db.example",        // a joiner out of context
		"xn--claude-.ai",          // invalid punycode
		"xn--xn--abc-t2a.example", // decodes to a label starting xn--
		"a.xn--xn--abc-t2a",
		"fe80::1%en0", // a zone
		// No DNS name can be it: empty, an empty label, invisible characters only.
		"",
		"XN--",
		"xn--",
		"xn--.example",
		"a.xn--", // a last label that decodes to nothing
		"a.xn--.",
		"a..b.example",
		"\u00ad",
		// A name that is, or maps to, a forbidden domain code point.
		"evil\uff20claude.example", // ＠ maps to @
		"evil\uff1f.claude.ai",
		"a\u3000b.claude.ai", // a space
		"a\u2100b.example",   // ℀ maps to a/c
		"a<b.claude.ai",
		"a%62.example",
		"a\uff03b.example",
		"a\uff1ab.example",
		"a\uff1eb.example",
		"a\uff3bb.example",
		"a\uff3cb.example",
		"a\uff3db.example",
		"a\uff3eb.example",
		"a\uff5cb.example",
		"a\x01b.example", // a C0 control
		"a\x7fb.example", // DEL
	} {
		if name, ok := BrowserNameOK(host); ok {
			t.Errorf("BrowserNameOK(%q) = %q, true; want the browser to refuse it", host, name)
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
