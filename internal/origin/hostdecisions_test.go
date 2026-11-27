package origin

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/host"
	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// The lists the decision columns judge against, fixed: each handler folds its own entries (MatchKey,
// host.Hostname, the origin key) as it folds a request's.
var (
	decisionHosts   = []string{"mcp.example.com", "127.0.0.1:8080", "[::1]:8080", "xn--bcher-kva.example", "[2001:db8::1]"}
	internalHosts   = []string{"byward-metrics.monitoring.svc:8080"}
	decisionOrigins = []string{"https://app.example", "https://mcp.example.com", "http://127.0.0.1:8080", "https://[::1]", "https://xn--bcher-kva.example"} // mcp.example.com is the URL shapes' host
)

// The public and internal Host checks and the Origin check decide every host family as pinned in
// testdata/hostdecisions.golden, against fixed lists, and pass only the inputs in
// testdata/hostdecisions.allowed, so a check that lets a new form through fails by name (#656).
// Each refusal is audited with the header as the client sent it, never as the check reduced it.
func TestEveryHostCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/origin", hostColumns(t))
}

// FuzzHostDecisions fuzzes the host each of these checks reads, beyond the golden's families (#661):
// see hostfamilies.Fuzz for what it fails.
func FuzzHostDecisions(f *testing.F) { hostfamilies.Fuzz(f, hostColumns, host.Split, host.Serialize) }

// hostColumns are the checks the golden test and FuzzHostDecisions judge.
func hostColumns(t testing.TB) []hostfamilies.Column {
	column := func(name string, lists bool, check func(*audit.Log) http.Handler, probes []hostfamilies.Probe, event, field string, request func(string) *http.Request) hostfamilies.Column {
		return hostfamilies.Column{Name: name, Probes: probes, Judge: func(in string) (bool, string) {
			rec, out := recording()
			w := httptest.NewRecorder()
			check(rec).ServeHTTP(w, request(in))
			if w.Code == http.StatusNoContent {
				return true, ""
			}
			// JSON carries no byte that is not UTF-8: the audit writes each as U+FFFD, as []rune does.
			if got, ok := audited(t, out.String(), event, field); !ok || got != string([]rune(in)) {
				t.Errorf("%s refused %q with %d and audited %s as %q (found: %v); want it as sent", name, in, w.Code, field, got, ok)
			}
			return false, strconv.Itoa(w.Code)
		}, Lists: lists}
	}
	hosts := hostfamilies.HostProbes()
	return []hostfamilies.Column{
		column("public Host", true, func(rec *audit.Log) http.Handler { return Hosts(rec, decisionHosts, ok) }, hosts, audit.HostRejected, "host", withHost),
		// Not a list: any IP literal passes, as kubelet probes and Prometheus address a pod by its IP.
		column("internal Host", false, func(rec *audit.Log) http.Handler { return InternalHosts(rec, internalHosts, ok) }, hosts, audit.HostRejected, "host", withHost),
		column("Origin", true, func(rec *audit.Log) http.Handler { return Origins(rec, decisionOrigins, ok) }, hostfamilies.URLProbes("", "https", "http"), audit.OriginRejected, "origin", withOrigin),
	}
}

// audited is field of the one audit record of event in a JSON audit stream, and whether there was
// exactly one.
func audited(t testing.TB, stream, event, field string) (string, bool) {
	var found []string
	for _, rec := range logsink.Records[map[string]any](t, stream) {
		if rec["event"] != event {
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
