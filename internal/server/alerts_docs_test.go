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

func TestSelectedReasonsReadsEveryMatcher(t *testing.T) {
	got := selectedReasons(`byward_idp_alerts_total{idp="entra",reason=~"credential_rejected|protocol"} byward_idp_alerts_total{reason!="protocl"}`)
	if want := []string{"credential_rejected", "protocol", "protocl"}; !slices.Equal(got, want) {
		t.Errorf("selectedReasons = %q, want %q", got, want)
	}
}
