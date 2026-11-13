package fakeidp

import (
	"net/http"
	"strings"
	"testing"
)

// WithTLS serves the fake over https; its HTTPClient trusts the certificate Certificate returns.
func TestWithTLSServesHTTPSThatTheFakesClientTrusts(t *testing.T) {
	p := New(t, Generic, WithTLS())
	if !strings.HasPrefix(p.Issuer(), "https://") || p.Certificate() == nil {
		t.Fatalf("issuer %q, certificate %v; want https and a certificate", p.Issuer(), p.Certificate())
	}
	resp, err := p.HTTPClient().Get(p.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if New(t, Generic).Certificate() != nil {
		t.Fatal("a fake without WithTLS has a certificate")
	}
}

func TestTransportRoutesAnyHostToTheFake(t *testing.T) {
	f := newFixture(t, Entra)
	resp, err := f.idp.HTTPClient().Get(DefaultAuthority + "/" + f.tenant + "/v2.0/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
