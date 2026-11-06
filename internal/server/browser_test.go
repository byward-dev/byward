package server

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
)

// consentFlow finds the sealed flow in the consent page's form.
var consentFlow = regexp.MustCompile(`name="flow" value="([^"]+)"`)

// testBrowser plays a user's browser against the wired server at base, which it reaches under
// public's host; it never follows redirects.
type testBrowser struct {
	t            *testing.T
	base, public string
	c            *http.Client
}

func newTestBrowser(t *testing.T, base, public string) *testBrowser {
	return &testBrowser{t: t, base: base, public: public,
		c: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// send requests path with cookies. A form is posted as our own page posts it: Origin and
// Sec-Fetch-Site same-origin.
func (b *testBrowser) send(method, path string, form url.Values, cookies []*http.Cookie) *http.Response {
	b.t.Helper()
	r, _ := http.NewRequest(method, b.base+path, nil)
	if form != nil {
		r, _ = http.NewRequest(method, b.base+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", b.public)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	u, _ := url.Parse(b.public)
	r.Host = u.Host
	for _, c := range cookies {
		r.AddCookie(c)
	}
	res, err := b.c.Do(r)
	if err != nil {
		b.t.Fatal(err)
	}
	return res
}

// allow answers the consent page (its body, already read) with Allow, after the consent delay.
func (b *testBrowser) allow(page *http.Response, body string) *http.Response {
	b.t.Helper()
	flow := consentFlow.FindStringSubmatch(body)
	if flow == nil {
		b.t.Fatalf("no consent form: %s", body)
	}
	time.Sleep(broker.ConsentDelay + 100*time.Millisecond) // Allow is accepted only after the delay
	return b.send(http.MethodPost, "/consent", url.Values{"flow": {html.UnescapeString(flow[1])}, "action": {"allow"}}, page.Cookies())
}
