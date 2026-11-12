package server

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
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// Doctor's self-probe, with its own client, reads the environment's proxy (once per process, so the
// check runs in a child process with HTTPS_PROXY set): through a setting Go misread, an unreachable
// public URL is reported with the cause, never the address Go dialled.
func TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if os.Getenv("BYWARD_TEST_DOCTOR_PROXY_CHILD") == "1" {
		fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
			fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}}))
		rep, err := Doctor(context.Background(), authHopConfig(t, "http://10.0.0.7/mcp"), DoctorOptions{IdP: fake.HTTPClient(), UpstreamProxy: noProxy})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range rep.Checks {
			fmt.Printf("CHECK %s: %s\n", c.Name, c.Message)
		}
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
			cmd := exec.Command(os.Args[0], "-test.run=^TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxy$", "-test.count=1") //nolint:gosec // G204: this test binary, re-run as its own child
			cmd.Env = append(os.Environ(), "BYWARD_TEST_DOCTOR_PROXY_CHILD=1", "HTTPS_PROXY="+tc.setting, "https_proxy=", "NO_PROXY=", "no_proxy=")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			got := string(out)
			if !strings.Contains(got, "cannot reach") {
				t.Fatalf("child output %q; want the self-probe to report the public URL unreachable", got)
			}
			if strings.Contains(got, addr) == tc.misread || strings.Contains(got, envproxy.Cause) != tc.misread {
				t.Fatalf("child output %q; misread %v", got, tc.misread)
			}
		})
	}
}
