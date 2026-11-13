package oidc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/testutil/closedport"
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
		fmt.Printf("ERR=%v\n", p.Ready(context.Background()))
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
			got := rerun.Run(t, "TestAProviderWithoutAClientNeverQuotesAMisreadEnvironmentProxy", rerun.Proxy(tc.setting)...)
			if !strings.Contains(got, "ERR=") || strings.Contains(got, "ERR=<nil>") {
				t.Fatalf("child output %q; want discovery to fail", got)
			}
			if strings.Contains(got, addr) == tc.misread || strings.Contains(got, envproxy.Cause) != tc.misread {
				t.Fatalf("child output %q; misread %v", got, tc.misread)
			}
		})
	}
}
