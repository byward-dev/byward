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

// BrowserHostOK tells a host the browser goes to from one it refuses or that names none, where
// BrowserHost is only the mapping got that far (xn--claude-.ai maps to claude.ai, but a browser
// refuses it).
func TestBrowserHostOKSaysWhetherABrowserGoesToTheHost(t *testing.T) {
	for host, want := range map[string]bool{
		"app.example":           true,
		"App.Example.":          true,
		"BÜCHER.example":        true,
		"ｍｙ_app.example":        true,
		"xn--bcher-kva.example": true,
		"127.0.0.1":             true,
		"xn--claude-.ai":        false, // invalid punycode
		"a‍b.example":           false, // a joiner out of context
		"xn--":                  false, // an empty label
		"xn--.example":          false,
		"a.xn--":                false, // a last label that decodes to nothing
		"a.xn--.":               false,
		"app.example\u3002":     true, // the host's own trailing full stop
		"a..b.example":          false,
		"­":                     false, // invisible characters only
		"":                      false,
	} {
		if _, got := BrowserHostOK(host); got != want {
			t.Errorf("BrowserHostOK(%q) ok = %v, want %v", host, got, want)
		}
	}
	if got, _ := BrowserHostOK("xn--claude-.ai"); got != BrowserHost("xn--claude-.ai") {
		t.Errorf("BrowserHostOK's name %q differs from BrowserHost's", got)
	}
}
