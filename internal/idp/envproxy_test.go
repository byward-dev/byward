package idp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/testutil/closedport"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// The IdP client, as production builds it, reads the environment's proxy (once per process, so the
// check runs in a child process): through a setting Go misread, an IdP call's error says only the
// cause, never the address Go dialled.
func TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if rerun.Child() {
		err := NewFetcher(nil).GetJSON(context.Background(), "https://login.example/.well-known/openid-configuration", &struct{}{})
		fmt.Printf("ERR=%v\n", err)
		return
	}
	addr := closedport.Addr(t)
	for _, tc := range []struct {
		name    string
		setting string
		misread bool
	}{
		{"a misread setting says only the cause", addr + "/pw-secret@egress.example:3128", true},
		{"a well-formed setting's error is its own", "http://" + addr, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rerun.Run(t, "TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy", rerun.Proxy(tc.setting)...)
			if !strings.Contains(got, "ERR=") || strings.Contains(got, "ERR=<nil>") {
				t.Fatalf("child output %q; want the IdP call to fail", got)
			}
			if strings.Contains(got, addr) == tc.misread || strings.Contains(got, envproxy.Cause) != tc.misread {
				t.Fatalf("child output %q; misread %v", got, tc.misread)
			}
		})
	}
}
