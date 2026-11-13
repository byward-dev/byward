package oidc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// A provider given no client uses the IdP client, which reads the environment's proxy (once per
// process, so the check runs in a child process): through a setting Go misread, discovery's error
// says only the cause.
func TestAProviderWithoutAClientNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if rerun.Child() {
		p, err := New(Config{Issuer: "https://idp.example", ClientID: "c", RedirectURL: redirect})
		if err != nil {
			t.Fatal(err)
		}
		p.fetch.Backoff = 0 // the production client, without the wait between retries
		fmt.Printf("ERR=%v\n", p.Ready(context.Background()))
		return
	}
	rerun.EachProxySetting(t, "TestAProviderWithoutAClientNeverQuotesAMisreadEnvironmentProxy", func(t *testing.T, got, addr string, misread bool) {
		if !strings.Contains(got, "ERR=") || strings.Contains(got, "ERR=<nil>") {
			t.Fatalf("child output %q; want discovery to fail", got)
		}
		if strings.Contains(got, addr) == misread || strings.Contains(got, envproxy.Cause) != misread {
			t.Fatalf("child output %q; misread %v", got, misread)
		}
	})
}
