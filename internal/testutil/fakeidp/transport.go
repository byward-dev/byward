package fakeidp

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// Transport sends every request to the fake, keeping path and query. Adapters whose endpoints are
// derived from a fixed authority (Entra) reach the fake through it, so production code needs no
// endpoint setting.
func (p *IdP) Transport() http.RoundTripper {
	return rewrite{base: p.srv.URL, next: p.srv.Client().Transport}
}

// Certificate is the fake's TLS certificate, for a client to trust; nil without WithTLS.
func (p *IdP) Certificate() *x509.Certificate { return p.srv.Certificate() }

// HTTPClient is a client using Transport that never follows redirects.
func (p *IdP) HTTPClient() *http.Client {
	return &http.Client{
		Transport:     p.Transport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type rewrite struct {
	base string
	next http.RoundTripper // trusts the fake's certificate under WithTLS
}

func (rw rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	base, err := url.Parse(rw.base)
	if err != nil {
		return nil, err
	}
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.Host = base.Scheme, base.Host, base.Host
	return rw.next.RoundTrip(out)
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

// AppToken runs the client credentials grant as a headless caller would (Entra only): caller, with
// secret, asks for an app-only token for the resource app api. It fails the test unless the fake
// issues one.
func (p *IdP) AppToken(t testing.TB, callerID, secret, api string) string {
	t.Helper()
	form := url.Values{"grant_type": {GrantClientCredentials}, "scope": {"api://" + api + "/.default"},
		"client_id": {callerID}, "client_secret": {secret}}
	resp, err := p.HTTPClient().PostForm(p.TokenURL(p.TenantID()), form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.AccessToken == "" {
		t.Fatalf("client credentials for %s: %d %s %v", callerID, resp.StatusCode, body.Error, err)
	}
	return body.AccessToken
}
