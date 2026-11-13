package oidc

import (
	"context"
	"fmt"
	"testing"

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
	rerun.EachProxySetting(t, "TestAProviderWithoutAClientNeverQuotesAMisreadEnvironmentProxy", rerun.CallFailedWithCauseOnlyIfMisread)
}
