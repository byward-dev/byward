package server

import (
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/metrics"
)

// #204: the label values operators copy into alert rules from the docs are the ones the proxy
// exports, so a renamed or added reason or operation fails here instead of leaving a rule that
// matches nothing.
func TestTheDocumentedIdPAlertLabelsAreTheExportedOnes(t *testing.T) {
	ref, err := os.ReadFile("../../docs/reference/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `byward_idp_alerts_total` \\|.*$").FindString(string(ref))
	if row == "" {
		t.Fatal("observability.md has no byward_idp_alerts_total row")
	}
	labels := []string{opOnBehalfOf}
	labels = append(labels, broker.IdPOperations...)
	for _, a := range idp.Alerts {
		labels = append(labels, string(a))
	}
	for _, l := range labels {
		if !strings.Contains(row, "`"+l+"`") {
			t.Errorf("the byward_idp_alerts_total row does not name %q:\n%s", l, row)
		}
	}
	m := metrics.New()
	m.SeedIdPAlerts("entra", broker.IdPOperations, []string{string(idp.AlertProtocol)}) // a family without series has no HELP line
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	help := regexp.MustCompile(`(?m)^# HELP byward_idp_alerts_total .*$`).FindString(rec.Body.String())
	if help == "" {
		t.Fatalf("/metrics has no HELP line for byward_idp_alerts_total:\n%s", rec.Body.String())
	}
	for _, l := range labels {
		if !strings.Contains(help, l) {
			t.Errorf("the /metrics HELP line does not name %q: %s", l, help)
		}
	}
	harden, err := os.ReadFile("../../docs/how-to/harden-a-deployment.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(selectedReasons(string(harden))) == 0 {
		t.Fatal("harden-a-deployment.md selects no byward_idp_alerts_total reason")
	}
	for doc, text := range map[string][]byte{"harden-a-deployment.md": harden, "observability.md": ref} {
		for _, r := range selectedReasons(string(text)) {
			if !slices.Contains(idp.Alerts, idp.Alert(r)) {
				t.Errorf("%s selects reason %q, which the proxy does not export", doc, r)
			}
		}
	}
}

var reasonMatcher = regexp.MustCompile(`byward_idp_alerts_total\{[^}]*reason(=|!=|=~|!~)"([^"]*)"`)

// selectedReasons is every reason a byward_idp_alerts_total selector in text names, with each
// alternative of a regex matcher on its own.
func selectedReasons(text string) []string {
	var out []string
	for _, m := range reasonMatcher.FindAllStringSubmatch(text, -1) {
		if strings.HasSuffix(m[1], "~") {
			out = append(out, strings.Split(m[2], "|")...)
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

// #204: a misspelled reason in any selector form (=, !=, =~, !~, an alternation) fails the docs
// check, not only in the = form.
func TestADocumentedSelectorInAnyMatcherFormIsChecked(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       []string
	}{
		{"=", `byward_idp_alerts_total{reason="protocl"}`, []string{"protocl"}},
		{"!=", `byward_idp_alerts_total{reason!="protocl"}`, []string{"protocl"}},
		{"=~ alternation", `byward_idp_alerts_total{idp="entra",reason=~"credential_rejected|protocl"}`, []string{"credential_rejected", "protocl"}},
		{"!~ alternation", `byward_idp_alerts_total{reason!~"credential_unusable|protocl"}`, []string{"credential_unusable", "protocl"}},
		{"every selector in a document", `byward_idp_alerts_total{reason="protocol"} byward_idp_alerts_total{reason="protocl"}`, []string{"protocol", "protocl"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := selectedReasons(c.text); !slices.Equal(got, c.want) {
				t.Errorf("selectedReasons(%s) = %q, want %q", c.text, got, c.want)
			}
		})
	}
}

// The upstream refusal labels the docs name are the ones the proxy exports, so an alert rule copied
// from them matches.
func TestTheDocumentedUpstreamRefusalLabelsAreTheExportedOnes(t *testing.T) {
	ref, err := os.ReadFile("../../docs/reference/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `byward_upstream_refusals_total` \\|.*$").FindString(string(ref))
	if row == "" {
		t.Fatal("observability.md has no byward_upstream_refusals_total row")
	}
	rec := httptest.NewRecorder()
	metrics.New().Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, status := range []string{"401", "403"} {
		if !strings.Contains(row, "`status`") || !strings.Contains(row, "`"+status+"`") {
			t.Errorf("the byward_upstream_refusals_total row does not name status %s:\n%s", status, row)
		}
		if !strings.Contains(rec.Body.String(), `byward_upstream_refusals_total{status="`+status+`"}`) {
			t.Errorf("/metrics does not export status %s", status)
		}
	}
}

var metricName = regexp.MustCompile(`byward_[a-z_]+`)

// Every metric an example alert rule or the alerts page queries is one the proxy exports, so a
// rule copied from the docs never matches nothing.
func TestTheAlertRulesInTheDocsQueryExportedMetrics(t *testing.T) {
	golden, err := os.ReadFile("../metrics/testdata/names.golden")
	if err != nil {
		t.Fatal(err)
	}
	exported := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(golden)), "\n") {
		exported[strings.Fields(line)[0]] = true
	}
	ref, err := os.ReadFile("../../docs/reference/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	rules := regexp.MustCompile("(?s)```yaml\ngroups:.*?```").FindString(string(ref))
	if rules == "" {
		t.Fatal("observability.md has no example alert rules")
	}
	alerts, err := os.ReadFile("../../docs/how-to/respond-to-alerts.md")
	if err != nil {
		t.Fatal(err)
	}
	for doc, text := range map[string]string{"observability.md's alert rules": rules, "respond-to-alerts.md": string(alerts)} {
		for _, name := range metricName.FindAllString(text, -1) {
			base := name
			for _, suffix := range []string{"_bucket", "_sum", "_count"} {
				base = strings.TrimSuffix(base, suffix)
			}
			if !exported[base] && !exported[name] {
				t.Errorf("%s queries %s, which the proxy does not export", doc, name)
			}
		}
	}
}
