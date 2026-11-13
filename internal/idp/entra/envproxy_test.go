package entra

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"

	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/closedport"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// A refresh through a proxy setting Go misread fails as Unavailable either way, so callers try
// later; with the IdP client's redaction its error never quotes the address Go dialled, which the
// bare transport's error does.
func TestARefreshThroughAMisreadProxySettingStaysUnavailableAndRedactionKeepsItsAddressOut(t *testing.T) {
	addr := closedport.Addr(t)
	pf := (&httpproxy.Config{HTTPSProxy: addr + "/pw-secret@egress.example:3128"}).ProxyFunc()
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = func(r *http.Request) (*url.URL, error) { return pf(r.URL) }
	for _, tc := range []struct {
		name      string
		transport http.RoundTripper
		redacted  bool
	}{
		{"without redaction the error quotes the address", base, false},
		{"with redaction it says only the cause", envproxy.Redact(base), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(Config{Tenant: fakeidp.NewGUID(), ClientID: fakeidp.NewGUID(), ClientAuth: idp.ClientSecret("s"), RedirectURL: redirect,
				HTTPClient: &http.Client{Transport: tc.transport}, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			p.fetch.Backoff = 0 // retries are idp's to test; here they would only add wall time
			_, _, err = p.Refresh(context.Background(), "refresh-token")
			if err == nil || idp.ClassOf(err) != idp.Unavailable {
				t.Fatalf("err %v, class %v; want an Unavailable error", err, idp.ClassOf(err))
			}
			if strings.Contains(err.Error(), addr) == tc.redacted || strings.Contains(err.Error(), envproxy.Cause) != tc.redacted {
				t.Fatalf("err %q; redacted %v", err, tc.redacted)
			}
		})
	}
}
