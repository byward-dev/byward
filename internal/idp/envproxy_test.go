package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/envproxy"
)

// The IdP client, as production builds it, reads the environment's proxy (once per process, so the
// check runs in a child process with HTTPS_PROXY set): through a setting Go misread, an IdP call's
// error says only the cause, never the address Go dialled.
func TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if os.Getenv("BYWARD_TEST_IDP_PROXY_CHILD") == "1" {
		err := NewFetcher(nil).GetJSON(context.Background(), "https://login.example/.well-known/openid-configuration", &struct{}{})
		fmt.Printf("ERR=%v\n", err)
		return
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	addr := gone.Listener.Addr().String() // nothing listens here once closed
	gone.Close()
	for _, tc := range []struct {
		name    string
		setting string
		misread bool
	}{
		{"a misread setting says only the cause", addr + "/pw-secret@egress.example:3128", true},
		{"a well-formed setting's error is its own", "http://" + addr, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy$", "-test.count=1") //nolint:gosec // G204: this test binary, re-run as its own child
			cmd.Env = append(os.Environ(), "BYWARD_TEST_IDP_PROXY_CHILD=1", "HTTPS_PROXY="+tc.setting, "https_proxy=", "NO_PROXY=", "no_proxy=")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			got := string(out)
			if !strings.Contains(got, "ERR=") || strings.Contains(got, "ERR=<nil>") {
				t.Fatalf("child output %q; want the IdP call to fail", got)
			}
			if strings.Contains(got, addr) == tc.misread || strings.Contains(got, envproxy.Cause) != tc.misread {
				t.Fatalf("child output %q; misread %v", got, tc.misread)
			}
		})
	}
}
