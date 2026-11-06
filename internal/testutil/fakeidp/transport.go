package fakeidp

import (
	"net/http"
	"net/url"
	"testing"
)

// Transport sends every request to the fake, keeping path and query. Adapters whose endpoints are
// derived from a fixed authority (Entra) reach the fake through it, so production code needs no
// endpoint setting.
func (p *IdP) Transport() http.RoundTripper { return rewrite{base: p.srv.URL} }

// HTTPClient is a client using Transport that never follows redirects.
func (p *IdP) HTTPClient() *http.Client {
	return &http.Client{
		Transport:     p.Transport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type rewrite struct{ base string }

func (rw rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	base, err := url.Parse(rw.base)
	if err != nil {
		return nil, err
	}
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.Host = base.Scheme, base.Host, base.Host
	return http.DefaultTransport.RoundTrip(out)
}

// Authorize follows an adapter's login URL at the fake (auto-login) and returns the query of the
// redirect back to the client: code and state, or error.
func (p *IdP) Authorize(t testing.TB, loginURL string) url.Values {
	t.Helper()
	resp, err := p.HTTPClient().Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}
