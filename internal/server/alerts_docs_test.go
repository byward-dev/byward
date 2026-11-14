package server

import (
	"fmt"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
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
}

// The upstream refusal statuses the docs name are exactly the ones the proxy exports, so an alert
// rule copied from them matches.
func TestTheDocumentedUpstreamRefusalLabelsAreTheExportedOnes(t *testing.T) {
	row := regexp.MustCompile("(?m)^\\| `byward_upstream_refusals_total` \\|.*$").FindString(readDoc(t, "reference/observability.md"))
	if row == "" {
		t.Fatal("observability.md has no byward_upstream_refusals_total row")
	}
	if !strings.Contains(row, "`status`") {
		t.Errorf("the byward_upstream_refusals_total row does not name the `status` label:\n%s", row)
	}
	var exported, documented []string
	for _, m := range regexp.MustCompile(`byward_upstream_refusals_total\{status="([^"]+)"\}`).FindAllStringSubmatch(scrapeMetrics(t, metrics.New()), -1) {
		exported = append(exported, m[1])
	}
	for _, m := range regexp.MustCompile("`([0-9]{3})`").FindAllStringSubmatch(row, -1) {
		documented = append(documented, m[1])
	}
	slices.Sort(exported)
	slices.Sort(documented)
	if len(exported) == 0 || !slices.Equal(exported, documented) {
		t.Fatalf("the row names statuses %v, /metrics exports %v:\n%s", documented, exported, row)
	}
}

var metricName = regexp.MustCompile(`byward_[a-z0-9_]+`)

// Every metric an example alert rule or the alerts page queries is one the proxy exports, so a
// rule copied from the docs queries a real metric.
func TestTheAlertRulesInTheDocsQueryExportedMetrics(t *testing.T) {
	// The golden file, which TestMetricNamesMatchTheGoldenFile ties to a scrape, lists every metric:
	// a scrape alone misses a labelled family that has no series yet.
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
	for doc, text := range map[string]string{"observability.md's alert rules": rules, "respond-to-alerts.md": readDoc(t, "how-to/respond-to-alerts.md")} {
		names := metricName.FindAllString(text, -1)
		if len(names) == 0 {
			t.Errorf("%s queries no byward_ metric; the scan found nothing", doc)
		}
		for _, name := range names {
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

// knownLabels is, per metric, every label a documented alert rule may filter or group by, with the
// values the proxy exports for it. Many values appear only once they are observed, so a scrape
// cannot list them: each set comes from the code's own list where there is one, and from here where
// there is none. A doc that uses a new value fails until its set here names it.
func knownLabels(t *testing.T) map[string]map[string][]string {
	t.Helper()
	idps := append([]string{"entra", "oidc"}, config.OIDCPresets...)
	var reasons []string
	for _, a := range idp.Alerts {
		reasons = append(reasons, string(a))
	}
	golden, err := os.ReadFile("../audit/testdata/events.golden.jsonl") // one record per event, pinned to the code
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for _, m := range regexp.MustCompile(`"event":"([a-z_]+)"`).FindAllStringSubmatch(string(golden), -1) {
		if !slices.Contains(events, m[1]) {
			events = append(events, m[1])
		}
	}
	kinds := []string{"request", "stream"} // admit in server.go has no list
	return map[string]map[string][]string{
		"byward_idp_request_duration_seconds": {"idp": idps, "operation": broker.IdPOperations,
			"outcome": {"success", "rejected", "unavailable"}}, // idpOutcome in internal/broker, unexported
		"byward_idp_alerts_total":        {"idp": idps, "operation": append(slices.Clone(broker.IdPOperations), opOnBehalfOf), "reason": reasons},
		"byward_audit_events_total":      {"event": events, "outcome": {audit.Success, audit.Failure}},
		"byward_upstream_refusals_total": {"status": {"401", "403"}},
		"byward_upstream_busy_total":     {"kind": kinds},
		"byward_upstream_in_flight":      {"kind": kinds},
	}
}

// ruleLabel is one label a documented rule filters (op is the matcher) or groups by (op is "by" or
// "without"), and where the doc says it.
type ruleLabel struct {
	at, metric, label, op string
	values                []string
}

var (
	codeRegion   = regexp.MustCompile("(?s)```.*?```|`[^`\n]+`")
	selector     = regexp.MustCompile(`(byward_[a-z0-9_]+)\{([^}]*)\}`)
	labelMatcher = regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*"([^"]*)"\s*$`)
	grouping     = regexp.MustCompile(`\b(by|without)\s*\(([^)]*)\)`)
	plainOptions = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+(\|[A-Za-z0-9_.:/-]+)*$`)
)

// ruleLabels is every label filtered or grouped by in doc's code (fenced blocks and inline code),
// and an error for each selector or regex matcher it cannot read, so nothing unreadable passes.
func ruleLabels(doc, text string) ([]ruleLabel, []string) {
	var out []ruleLabel
	var errs []string
	for _, region := range codeRegion.FindAllStringIndex(text, -1) {
		code := text[region[0]:region[1]]
		at := func(i int) string {
			return fmt.Sprintf("%s:%d", doc, 1+strings.Count(text[:region[0]+i], "\n"))
		}
		for _, m := range selector.FindAllStringSubmatchIndex(code, -1) {
			metric, inner := code[m[2]:m[3]], code[m[4]:m[5]]
			for _, part := range strings.Split(inner, ",") {
				lm := labelMatcher.FindStringSubmatch(part)
				if lm == nil {
					errs = append(errs, fmt.Sprintf("%s: %s{%s}: cannot read the matcher %q", at(m[0]), metric, inner, part))
					continue
				}
				values := []string{lm[3]}
				if strings.HasSuffix(lm[2], "~") {
					if !plainOptions.MatchString(lm[3]) {
						errs = append(errs, fmt.Sprintf("%s: %s{%s}: the regex %q is not a plain a|b alternation, so its values cannot be checked", at(m[0]), metric, inner, lm[3]))
						continue
					}
					values = strings.Split(lm[3], "|")
				}
				out = append(out, ruleLabel{at(m[0]), metric, lm[1], lm[2], values})
			}
		}
		for _, g := range grouping.FindAllStringSubmatchIndex(code, -1) {
			metrics := metricName.FindAllString(groupedExpr(code, g[0], g[1]), -1)
			if len(metrics) == 0 {
				errs = append(errs, fmt.Sprintf("%s: %s: no byward_ metric in the grouped expression", at(g[0]), code[g[0]:g[1]]))
			}
			for _, metric := range metrics {
				for _, label := range strings.Split(code[g[4]:g[5]], ",") {
					out = append(out, ruleLabel{at(g[0]), metric, strings.TrimSpace(label), code[g[2]:g[3]], nil})
				}
			}
		}
	}
	return out, errs
}

// groupedExpr is the expression a by or without clause at code[start:end] groups: the parenthesised
// one right after it (sum by (x) (expr)), or else the one right before it (sum(expr) by (x)).
func groupedExpr(code string, start, end int) string {
	if rest := strings.TrimLeft(code[end:], " \t\n"); strings.HasPrefix(rest, "(") {
		depth := 0
		for i, r := range rest {
			switch r {
			case '(':
				depth++
			case ')':
				if depth--; depth == 0 {
					return rest[:i+1]
				}
			}
		}
		return rest
	}
	before := strings.TrimRight(code[:start], " \t\n")
	depth := 0
	for i := len(before) - 1; i >= 0; i-- {
		switch before[i] {
		case ')':
			depth++
		case '(':
			if depth--; depth == 0 {
				return before[i:]
			}
		}
	}
	return before
}

// badLabels is one error for each label the proxy does not export on its metric, and for each value
// outside the label's known set.
func badLabels(labels []ruleLabel, known map[string]map[string][]string) []string {
	var errs []string
	for _, l := range labels {
		base := l.metric
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			base = strings.TrimSuffix(base, suffix)
		}
		sets, ok := known[base]
		switch {
		case !ok:
			errs = append(errs, fmt.Sprintf("%s: %s has no known label set; add it to knownLabels", l.at, l.metric))
			continue
		case l.label == "le" && strings.HasSuffix(l.metric, "_bucket"):
			continue // a histogram bucket's bound, any number
		}
		values, ok := sets[l.label]
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: %s has no label %q", l.at, base, l.label))
			continue
		}
		for _, v := range l.values {
			if !slices.Contains(values, v) {
				errs = append(errs, fmt.Sprintf("%s: %s{%s%s%q}: the proxy never exports %s %q", l.at, l.metric, l.label, l.op, v, l.label, v))
			}
		}
	}
	return errs
}

// #354: every label an example alert rule or a documented selector filters or groups by is one the
// proxy exports on that metric, and every value it names is one the proxy exports, so a rule copied
// from the docs fires.
func TestTheDocumentedAlertRulesUseExportedLabelsAndValues(t *testing.T) {
	known := knownLabels(t)
	for doc, hasRules := range map[string]bool{"reference/observability.md": true, "how-to/harden-a-deployment.md": true,
		"how-to/respond-to-alerts.md": false} {
		labels, errs := ruleLabels(doc, readDoc(t, doc))
		if hasRules && len(labels) == 0 {
			t.Errorf("%s: no label filtered or grouped by; the scan found nothing", doc)
		}
		for _, e := range append(errs, badLabels(labels, known)...) {
			t.Error(e)
		}
	}
}

// #354: the check catches each kind of mistake in a rule, in every matcher form, and says where.
func TestABadLabelInADocumentedRuleIsReportedWithItsLine(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       string // in the one error; "" for none
	}{
		{"a valid rule", "```yaml\nexpr: sum by (idp, reason) (increase(byward_idp_alerts_total{reason=\"protocol\"}[5m])) > 0\n```", ""},
		{"a misspelled grouping label", "`sum by (stauts) (increase(byward_upstream_refusals_total[5m]))`", `has no label "stauts"`},
		{"a misspelled filter label", "`byward_upstream_busy_total{knd=\"request\"}`", `has no label "knd"`},
		{"a value never exported", "`byward_upstream_refusals_total{status=\"404\"}`", `never exports status "404"`},
		{"!=", "`byward_idp_alerts_total{reason!=\"protocl\"}`", `"protocl"`},
		{"=~ alternation", "`byward_idp_alerts_total{idp=\"entra\",reason=~\"credential_rejected|protocl\"}`", `"protocl"`},
		{"!~ alternation", "`byward_idp_alerts_total{reason!~\"credential_unusable|protocl\"}`", `"protocl"`},
		{"a regex that is not a plain alternation", "`byward_idp_alerts_total{reason=~\"cred.*\"}`", "not a plain a|b alternation"},
		{"an unquoted value", "`byward_idp_alerts_total{reason=protocol}`", "cannot read the matcher"},
		{"a metric with no known set", "`byward_cimd_fetches_total{outcome=\"failure\"}`", "has no known label set"},
		{"a histogram's count and bucket", "```\nbyward_idp_request_duration_seconds_count{outcome=\"unavailable\"} byward_idp_request_duration_seconds_bucket{le=\"0.5\"}\n```", ""},
		{"a misspelled outcome", "`byward_idp_request_duration_seconds_count{outcome=\"unavailble\"}`", `never exports outcome "unavailble"`},
		{"grouping after the expression", "`sum(rate(byward_upstream_busy_total[5m])) by (kidn)`", `has no label "kidn"`},
		{"an audit event never recorded", "`byward_audit_events_total{event=\"access_token_rejectd\"}`", `"access_token_rejectd"`},
		{"the line it is on", "prose\n\n```yaml\nrules:\n  - expr: byward_upstream_refusals_total{status=\"404\"}\n```", "doc.md:5:"},
		{"prose is not read", "sort by (status) in prose, byward_upstream_refusals_total{status=\"404\"} outside code", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			labels, errs := ruleLabels("doc.md", c.text)
			errs = append(errs, badLabels(labels, knownLabels(t))...)
			if c.want == "" {
				if len(errs) != 0 {
					t.Fatalf("want no error, got %q", errs)
				}
				return
			}
			if len(errs) != 1 || !strings.Contains(errs[0], c.want) {
				t.Fatalf("want one error containing %q, got %q", c.want, errs)
			}
		})
	}
}

// #354: the label names knownLabels gives each metric are the ones the proxy exports on it, so a
// renamed label fails here, not only in a rule.
func TestTheKnownLabelsAreTheMetricsOwn(t *testing.T) {
	m := metrics.New()
	m.IdP("entra", broker.OpCallback, "success", time.Millisecond)
	m.IdPAlert("entra", broker.OpRefresh, string(idp.AlertProtocol))
	m.AuditEvent(audit.Login, audit.Success)
	m.Busy("request")
	m.InFlight("stream", 1)
	scrape := scrapeMetrics(t, m)
	for metric, sets := range knownLabels(t) {
		series := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metric) + `(?:_count)?\{([^}]*)\}`).FindStringSubmatch(scrape)
		if series == nil {
			t.Errorf("/metrics has no series of %s", metric)
			continue
		}
		var exported, listed []string
		for _, pair := range regexp.MustCompile(`([a-z_]+)="`).FindAllStringSubmatch(series[1], -1) {
			exported = append(exported, pair[1])
		}
		for label := range sets {
			listed = append(listed, label)
		}
		slices.Sort(exported)
		slices.Sort(listed)
		if !slices.Equal(exported, listed) {
			t.Errorf("%s exports the labels %v, knownLabels lists %v", metric, exported, listed)
		}
	}
}
