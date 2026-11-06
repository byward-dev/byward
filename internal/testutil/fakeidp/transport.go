package fakeidp

import (
	"net/http"
	"net/url"
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
