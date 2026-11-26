package origin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// The lists the decision columns judge against, as config stores them: names in lower case,
// addresses as browsers write them.
var (
	decisionHosts   = []string{"mcp.example.com", "127.0.0.1:8080", "[::1]:8080", "xn--bcher-kva.example", "[2001:db8::1]"}
	internalHosts   = []string{"byward-metrics.monitoring.svc:8080"}
	decisionOrigins = []string{"https://app.example", "http://127.0.0.1:8080", "https://[::1]", "https://xn--bcher-kva.example"}
)

// The public and internal Host checks and the Origin check decide every host family as pinned in
// testdata/hostdecisions.golden, against fixed lists, and pass only the inputs in
// testdata/hostdecisions.allowed, so a check that lets a new form through fails by name (#656).
// Each refusal is audited with the header as the client sent it, never as the check reduced it.
func TestEveryHostCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
	column := func(name string, check func(*audit.Log) http.Handler, probes []hostfamilies.Probe, event, field string, request func(string) *http.Request) hostfamilies.Column {
		return hostfamilies.Column{Name: name, Probes: probes, Judge: func(in string) (bool, string) {
			rec, out := recording()
			w := httptest.NewRecorder()
			check(rec).ServeHTTP(w, request(in))
			if w.Code == http.StatusNoContent {
				return true, ""
			}
			if got, ok := audited(out.String(), event, field); !ok || got != in {
				t.Errorf("%s refused %q with %d and audited %s as %q (found: %v); want it as sent", name, in, w.Code, field, got, ok)
			}
			return false, strconv.Itoa(w.Code)
		}}
	}
	hosts := hostfamilies.HostProbes()
	hostfamilies.Run(t, "internal/origin", []hostfamilies.Column{
		column("public Host", func(rec *audit.Log) http.Handler { return Hosts(rec, decisionHosts, ok) }, hosts, audit.HostRejected, "host", withHost),
		column("internal Host", func(rec *audit.Log) http.Handler { return InternalHosts(rec, internalHosts, ok) }, hosts, audit.HostRejected, "host", withHost),
		column("Origin", func(rec *audit.Log) http.Handler { return Origins(rec, decisionOrigins, ok) }, hostfamilies.URLProbes("", "https", "http"), audit.OriginRejected, "origin", withOrigin),
	})
}

// audited is field of the one audit record of event in a JSON audit stream, and whether there was
// exactly one.
func audited(stream, event, field string) (string, bool) {
	var found []string
	for _, l := range strings.Split(strings.TrimSpace(stream), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) != nil || rec["event"] != event {
			continue
		}
		v, _ := rec[field].(string)
		found = append(found, v)
	}
	if len(found) != 1 {
		return strings.Join(found, ", "), false
	}
	return found[0], true
}
