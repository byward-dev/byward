package idp

import (
	"context"
	"fmt"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// The IdP client, as production builds it, reads the environment's proxy (once per process, so the
// check runs in a child process): through a setting Go misread, an IdP call's error says only the
// cause, never the address Go dialled.
func TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if rerun.Child() {
		f := NewFetcher(nil)
		f.Backoff = 0 // the production client, without the wait between retries
		err := f.GetJSON(context.Background(), "https://login.example/.well-known/openid-configuration", &struct{}{})
		fmt.Printf("ERR=%v\n", err)
		return
	}
	rerun.EachProxySetting(t, "TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy", rerun.CallFailedWithCauseOnlyIfMisread)
}
