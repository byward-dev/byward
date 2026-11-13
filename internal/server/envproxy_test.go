package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// Doctor's default self-probe and upstream line read the environment's proxy (once per process, so the check runs
// in a child process): through a setting Go misread, the self-probe reports the public URL with the
// cause, never the address Go dialled, and the upstream line warns about the setting.
func TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxyAndTheUpstreamLineWarnsOfIt(t *testing.T) {
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
	rerun.EachProxySetting(t, "TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxyAndTheUpstreamLineWarnsOfIt", func(t *testing.T, got, addr string, misread bool) {
		var probe []string // the self-probe's lines: the upstream line quotes a well-formed setting itself
		for _, l := range strings.Split(got, "\n") {
			if strings.Contains(l, "cannot reach") {
				probe = append(probe, l)
			}
		}
		if len(probe) == 0 {
			t.Fatalf("child output %q; want the self-probe to report the public URL unreachable", got)
		}
		rerun.CauseOnlyIfMisread(t, strings.Join(probe, "\n"), addr, misread)
		// The upstream line reads the same environment proxy, through doctor's default.
		if strings.Contains(got, "unescaped character in its credentials") != misread {
			t.Fatalf("child output %q; want the upstream line to warn exactly when the setting is misread", got)
		}
	})
}
