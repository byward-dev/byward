package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/testutil/closedport"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// Doctor, with its own clients, reads the environment's proxy (once per process, so the check runs
// in a child process): through a setting Go misread, the self-probe reports the public URL with the
// cause, never the address Go dialled, and the upstream line warns about the setting.
func TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if rerun.Child() {
		fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
			fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}}))
		rep, err := Doctor(context.Background(), authHopConfig(t, "http://10.0.0.7/mcp"), DoctorOptions{IdP: fake.HTTPClient()})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range rep.Checks {
			fmt.Printf("CHECK %s: %s\n", c.Name, c.Message)
		}
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
			got := rerun.Run(t, "TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxy", rerun.Proxy(tc.setting)...)
			if !strings.Contains(got, "cannot reach") {
				t.Fatalf("child output %q; want the self-probe to report the public URL unreachable", got)
			}
			if strings.Contains(got, addr) == tc.misread || strings.Contains(got, envproxy.Cause) != tc.misread {
				t.Fatalf("child output %q; misread %v", got, tc.misread)
			}
			// The upstream line reads the same environment proxy, through doctor's default.
			if strings.Contains(got, "unescaped character in its credentials") != tc.misread {
				t.Fatalf("child output %q; want the upstream line to warn exactly when the setting is misread", got)
			}
		})
	}
}
