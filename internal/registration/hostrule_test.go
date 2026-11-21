package registration

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/host"
)

// nameProbes are host names a browser maps (case, a trailing dot, full-width forms, IDN, joiners,
// transitional letters) or refuses (a forbidden code point, an xn-- label decoding to xn--).
var nameProbes = []string{
	"app.example", "APP.Example", "app.example.", "ａｐｐ.example", "app。example", "bücher.example",
	"xn--bcher-kva.example", "faß.example", "Straẞe.example", "a\u200db.example", "my_host.example",
	"a--b.example", "＠.example", "xn--xn--abc-t2a.example", "", "127.0.0.1", "127.1", "::1", "single",
}

// redirectProbes are redirect URIs whose loopback hosts must stay the exact set (ADR-0009 §2,
// ADR-0032 §5): only 127.0.0.1, [::1] and localhost, written so.
var redirectProbes = []string{
	"http://localhost/cb", "http://LOCALHOST/cb", "http://Localhost/cb", "http://localhost./cb",
	"http://127.0.0.1:5000/cb", "http://127.0.0.2/cb", "http://127.1/cb", "http://[::1]/cb",
	"http://[0:0::1]/cb", "https://App.Example/cb",
}

// The browser's fold of a host name, the denylist's transitional fold, and the loopback redirect
// set are pinned in testdata/hostrule.golden, so a change to any of them shows as a diff. Moving the
// browser fold into one parser (#521, ADR-0032 slice 1) changed none of them. Regenerate with
// BYWARD_UPDATE_GOLDEN=1, and review the diff.
func TestHostFoldsAndTheLoopbackRedirectSetAreAsPinned(t *testing.T) {
	var b strings.Builder
	for _, h := range nameProbes {
		ascii, ok := host.BrowserNameOK(h)
		fmt.Fprintf(&b, "%q\n  browser: %q, goes there %v, unicode %q\n  transitional: %q\n", h, host.BrowserName(h), ok, host.BrowserUnicode(ascii), transitionalHost(h))
	}
	for _, r := range redirectProbes {
		fmt.Fprintf(&b, "redirect %s: %v\n", r, ValidateRedirect(r))
	}
	const golden = "testdata/hostrule.golden"
	if os.Getenv("BYWARD_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != string(want) {
		t.Errorf("a host fold or the loopback redirect set changed at %s; if intended, regenerate with BYWARD_UPDATE_GOLDEN=1 and review the diff", firstDiff(got, string(want)))
	}
}

// firstDiff is the first line where got and want differ, numbered from 1, with both versions.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d:\n got: %q\nwant: %q", i+1, gl, wl)
		}
	}
	return "no line differs"
}
