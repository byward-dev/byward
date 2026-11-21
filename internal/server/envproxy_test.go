package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// Doctor's default self-probe and upstream line read the environment's proxy (once per process, so the check runs
// in a child process): through a setting Go misread, the self-probe reports the public URL with the
// cause, never the address Go dialled, and the upstream line warns about the setting.
func TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxyAndTheUpstreamLineWarnsOfIt(t *testing.T) {
	if rerun.Child() {
		fake := fixtureEntra(t)
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

// Doctor's default self-probe dials through dialSelfProbe, which the package's tests replace: a
// public URL by name, or at an address off this machine, is refused before it is looked up or
// reached, so no test touches the network through it (#570). This fails if doctor dials the default
// way again, if TestMain stops replacing the dialer, or if the replacement lets more than loopback
// through.
func TestDoctorsDefaultSelfProbeDialsThroughTheTestsGuard(t *testing.T) {
	fake := fixtureEntra(t)
	for _, public := range []string{"https://mcp.example.com/mcp", "https://10.0.0.7/mcp", "https://[fd00::7]/mcp"} {
		t.Run(public, func(t *testing.T) {
			rep, err := Doctor(context.Background(), loadConfig(t, public, "BYWARD_UPSTREAM_URL=http://10.0.0.7/mcp"), DoctorOptions{IdP: fake.HTTPClient()})
			if err != nil {
				t.Fatal(err)
			}
			probed := false
			for _, c := range rep.Checks {
				if strings.Contains(c.Message, "cannot reach "+strings.TrimSuffix(public, "/mcp")) {
					probed = true
					if !strings.Contains(c.Message, "the tests dial no names and no address off this machine") {
						t.Fatalf("self-probe %q; want the tests' guard to have refused the dial", c.Message)
					}
				}
			}
			if !probed {
				t.Fatalf("checks %+v; want the self-probe to report the public URL unreachable", rep.Checks)
			}
		})
	}
}

// No DNS query leaves the machine from this package's tests: TestMain makes the default resolver,
// which every client here uses, the Go one, whose connection to a name server is refused (#585).
// This fails if the guard is removed. It looks no name up itself, so a run with
// GODEBUG=netdns=go+2 shows only the lookups some other test makes.
func TestTheTestsQueryNoNameServer(t *testing.T) {
	r := net.DefaultResolver
	if !r.PreferGo || r.Dial == nil {
		t.Fatalf("default resolver: PreferGo %v, Dial set %v; want the tests' guard", r.PreferGo, r.Dial != nil)
	}
	if _, err := r.Dial(context.Background(), "udp", "192.0.2.53:53"); err == nil || !strings.Contains(err.Error(), "the tests query no name server") {
		t.Fatalf("dial of a name server: %v; want the tests' guard to refuse it", err)
	}
}
