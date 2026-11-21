package server

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/testutil/clientsim"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// testVerifier is the PKCE verifier the server tests sign in with; authorizeQuery sends its S256
// challenge.
const testVerifier = "verifier-0123456789-0123456789-0123456789-abc"

// authorizeQuery is a valid authorization request from the static client test-app to
// http://127.0.0.1/callback with testVerifier's challenge; extra overrides a parameter, and a nil
// value removes it.
func authorizeQuery(extra url.Values) url.Values {
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"},
		"code_challenge": {fakeidp.CodeChallenge(testVerifier)}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		if v == nil {
			delete(q, k)
		} else {
			q[k] = v
		}
	}
	return q
}

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

// viaIdP follows res's redirect to the fake IdP, which signs the user in, and sends the IdP's
// redirect back to the proxy with res's cookies, as the user's browser does.
func (b *testBrowser) viaIdP(fake *fakeidp.IdP, res *http.Response) *http.Response {
	b.t.Helper()
	idpRes, err := fake.HTTPClient().Get(res.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	return b.send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, res.Cookies())
}

// allow answers the consent page (its body, already read) with Allow, after the consent delay, and
// returns the answer: a 303 to the IdP.
func (b *testBrowser) allow(page *http.Response, body string) *http.Response {
	b.t.Helper()
	flow := consentFlow.FindStringSubmatch(body)
	if flow == nil {
		b.t.Fatalf("no consent form: %s", body)
	}
	res, err := clientsim.AnswerAllow(broker.ConsentDelay, func() (*http.Response, error) {
		return b.send(http.MethodPost, "/consent", url.Values{"flow": {html.UnescapeString(flow[1])}, "action": {"allow"}}, page.Cookies()), nil
	})
	if err != nil {
		b.t.Fatal(err)
	}
	return res
}

// An Allow sent before the consent delay gets the consent page again with clientsim.ConsentTooSoon,
// and clientsim.AnswerAllow, on that real page, waits out the delay and sends Allow again, which the
// broker then accepts: if the broker's words change, this fails, not a retry nobody sees (#598).
func TestAnAllowBeforeTheDelayIsShownThePageAgainAndAcceptedWhenSentAgain(t *testing.T) {
	const public = "https://mcp.example.com"
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/entra"}}
	useFakeEntra(t, fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app)), app)
	srv, err := New(loadConfig(t, public+"/mcp"), discard)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(srv.Public.Handler)
	t.Cleanup(h.Close)
	b := newTestBrowser(t, h.URL, public)
	page := b.send(http.MethodGet, "/authorize?"+authorizeQuery(nil).Encode(), nil, nil)
	body := readAll(t, page)
	flow := consentFlow.FindStringSubmatch(body)
	if page.StatusCode != http.StatusOK || flow == nil {
		t.Fatalf("authorize: %d, want the consent page: %.300s", page.StatusCode, body)
	}
	var answers []int
	// A delay of -100ms sends the first Allow at once, too soon; the second waits out the delay itself.
	res, err := clientsim.AnswerAllow(-100*time.Millisecond, func() (*http.Response, error) {
		if len(answers) == 1 {
			time.Sleep(broker.ConsentDelay)
		}
		res := b.send(http.MethodPost, "/consent", url.Values{"flow": {html.UnescapeString(flow[1])}, "action": {"allow"}}, page.Cookies())
		answers = append(answers, res.StatusCode)
		return res, nil
	})
	if err != nil || len(answers) != 2 || answers[0] != http.StatusOK {
		t.Fatalf("answers %v, %v; want the page again (200), then the redirect to the IdP", answers, err)
	}
	_ = res.Body.Close()
}
