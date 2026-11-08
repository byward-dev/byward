package config

import (
	"strings"
	"testing"
)

// One configuration error per check, reported in the order the checks run: authSettings, then the
// upstream credential, then dependentAuthSettings, then header clashes. The order is part of what
// an operator reads, so moving a check is a visible change.
func TestErrorsAreReportedInCheckOrder(t *testing.T) {
	_, err := load(t, nil, "BYWARD_OPERATOR_NAME="+strings.Repeat("x", 81), "BYWARD_IDP=bogus", "BYWARD_GATE_ROLES= , ",
		"BYWARD_APP_TOKENS=bogus", "BYWARD_DATA_DIR=relative", "BYWARD_REFRESH_GRACE=bogus", "BYWARD_ASSERTION_CLAIMS=bogus",
		"BYWARD_DCR=maybe", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", "BYWARD_OBO_SCOPES=User.Read", "BYWARD_ASSERTION_HEADER=X-Byward-Subject")
	if err == nil {
		t.Fatal("want configuration errors")
	}
	msg, at := err.Error(), -1
	for _, want := range []string{
		"BYWARD_OPERATOR_NAME:",             // consent
		"BYWARD_IDP:",                       // idp
		"BYWARD_GATE_ROLES is set",          // gate
		"BYWARD_APP_TOKENS:",                // appTokens
		"BYWARD_DATA_DIR:",                  // paths
		"BYWARD_REFRESH_GRACE:",             // refreshGrace
		"BYWARD_ASSERTION_CLAIMS:",          // assertion
		"BYWARD_DCR:",                       // clientSources
		"BYWARD_UPSTREAM_CREDENTIAL_HEADER", // upstreamCredential
		"BYWARD_OBO_SCOPES:",                // onBehalfOf (dependentAuthSettings)
		"BYWARD_ASSERTION_HEADER:",          // headerClashes
	} {
		i := strings.Index(msg, want)
		if i < 0 {
			t.Fatalf("no %q in %s", want, msg)
		}
		if i < at {
			t.Fatalf("%q reported before the check that runs ahead of it:\n%s", want, strings.ReplaceAll(msg, "; ", "\n"))
		}
		at = i
	}
}
