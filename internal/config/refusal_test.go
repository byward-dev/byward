package config

import "testing"

// A refusal has one format, "BYWARD_X: want …; got …": a value or an entry refused for its form by
// its place and length, one refused for its meaning as the parser read it. It names the setting as the
// operator gave it, by its variable or its flag (#623).
func TestARefusalHasOneFormat(t *testing.T) {
	hosts := Setting{Name: "allowed-hosts", shape: asGivenShape}
	byEnv, byFlag := Value{Setting: hosts, Source: SourceEnv}, Value{Setting: hosts, Source: SourceFlag}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a value refused for its form", refusedForm(byEnv, whole, "a"+canaryText, "a host", "it has no dot"),
			"BYWARD_ALLOWED_HOSTS: want a host; got a value (11 characters, not shown): it has no dot"},
		{"an entry refused for its form", refusedForm(byEnv, entry{1, 3}, canaryText, "a host", "it has no dot"),
			"BYWARD_ALLOWED_HOSTS: want a host; got entry 2 of 3 (10 characters, not shown): it has no dot"},
		{"a value refused for its meaning", refusedMeaning(byEnv, whole, "10.0.0.1", "a loopback host", "it is not loopback"),
			"BYWARD_ALLOWED_HOSTS: want a loopback host; got 10.0.0.1: it is not loopback"},
		{"an entry refused for its meaning", refusedMeaning(byEnv, entry{0, 2}, "10.0.0.1", "a loopback host", "it is not loopback"),
			"BYWARD_ALLOWED_HOSTS: want a loopback host; got entry 1 of 2, 10.0.0.1: it is not loopback"},
		{"a list of none", listsNothing(byEnv), "BYWARD_ALLOWED_HOSTS: want at least one entry; got a list of none"},
		{"a value refused for its form, by flag", refusedForm(byFlag, whole, "a"+canaryText, "a host", "it has no dot"),
			"--allowed-hosts: want a host; got a value (11 characters, not shown): it has no dot"},
		{"an entry refused for its meaning, by flag", refusedMeaning(byFlag, entry{0, 2}, "10.0.0.1", "a loopback host", "it is not loopback"),
			"--allowed-hosts: want a loopback host; got entry 1 of 2, 10.0.0.1: it is not loopback"},
		{"a list of none, by flag", listsNothing(byFlag), "--allowed-hosts: want at least one entry; got a list of none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !isConfigError(tc.err) || tc.err.Error() != tc.want {
				t.Errorf("got %v, want the configuration error %q", tc.err, tc.want)
			}
		})
	}
}
