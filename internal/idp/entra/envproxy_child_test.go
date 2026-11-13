package entra

import (
	"context"
	"fmt"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// An Entra provider given no client uses the IdP client, which reads the environment's proxy (once per
// process, so the check runs in a child process): through a setting Go misread, discovery's error
// says only the cause.
func TestAnEntraProviderWithoutAClientNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if rerun.Child() {
		p, err := New(Config{Tenant: fakeidp.NewGUID(), ClientID: fakeidp.NewGUID(), ClientAuth: idp.ClientSecret("s"), RedirectURL: redirect})
		if err != nil {
			t.Fatal(err)
		}
		p.fetch.Backoff = 0 // the production client, without the wait between retries
		fmt.Printf("ERR=%v\n", p.Ready(context.Background()))
		return
	}
	rerun.EachProxySetting(t, "TestAnEntraProviderWithoutAClientNeverQuotesAMisreadEnvironmentProxy", rerun.CallFailedWithCauseOnlyIfMisread)
}
