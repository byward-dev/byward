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
	} {
		if got := BrowserHost(host); got != want {
			t.Errorf("BrowserHost(%q) = %q, want %q", host, got, want)
		}
	}
}
