package server

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/idp"
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
	harden, err := os.ReadFile("../../docs/how-to/harden-a-deployment.md")
	if err != nil {
		t.Fatal(err)
	}
	selected := regexp.MustCompile(`byward_idp_alerts_total\{[^}]*reason=~?"([^"]*)"`).FindAllStringSubmatch(string(harden), -1)
	if len(selected) == 0 {
		t.Fatal("harden-a-deployment.md selects no byward_idp_alerts_total reason")
	}
	for _, m := range selected {
		if !slices.Contains(idp.Alerts, idp.Alert(m[1])) {
			t.Errorf("harden-a-deployment.md selects reason %q, which the proxy does not export", m[1])
		}
	}
}
