package config

import (
	"slices"
	"testing"
)

// gate-allow-empty is off by default and true only when given, by its variable or its flag. With it off,
// an empty gate for a Google or generic OIDC IdP refuses to start (ADR-0015 §3, pinned in internal/gate).
func TestGateAllowEmptyIsOffUntilGivenByItsVariableOrFlag(t *testing.T) {
	c, _, err := Load(nil, slices.Clone(oidcBase), oidcFiles)
	if err != nil || c.GateAllowEmpty {
		t.Fatalf("by default: GateAllowEmpty = %v, err %v, want false", c != nil && c.GateAllowEmpty, err)
	}
	for _, given := range []struct {
		args, env []string
	}{
		{nil, []string{"BYWARD_GATE_ALLOW_EMPTY=true"}},
		{[]string{"--gate-allow-empty"}, nil},
	} {
		c, _, err := Load(given.args, append(slices.Clone(oidcBase), given.env...), oidcFiles)
		if err != nil || !c.GateAllowEmpty {
			t.Errorf("%v %v: GateAllowEmpty = %v, err %v, want true", given.args, given.env, c != nil && c.GateAllowEmpty, err)
		}
	}
}
