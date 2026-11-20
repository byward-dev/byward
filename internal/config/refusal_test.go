package config

import "testing"

// A refusal has one format, "BYWARD_X: want …; got …": a value or an entry refused for its form by
// its place and length, one refused for its meaning as the parser read it.
func TestARefusalHasOneFormat(t *testing.T) {
	s := Setting{Name: "allowed-hosts", shape: asGivenShape}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a value refused for its form", refusedForm(s, whole, "a"+canaryText, "a host", "it has no dot"),
			"BYWARD_ALLOWED_HOSTS: want a host; got a value (11 characters, not shown): it has no dot"},
		{"an entry refused for its form", refusedForm(s, entry{1, 3}, canaryText, "a host", "it has no dot"),
			"BYWARD_ALLOWED_HOSTS: want a host; got entry 2 of 3 (10 characters, not shown): it has no dot"},
		{"a value refused for its meaning", refusedMeaning(s, whole, "10.0.0.1", "a loopback host", "it is not loopback"),
			"BYWARD_ALLOWED_HOSTS: want a loopback host; got 10.0.0.1: it is not loopback"},
		{"an entry refused for its meaning", refusedMeaning(s, entry{0, 2}, "10.0.0.1", "a loopback host", "it is not loopback"),
			"BYWARD_ALLOWED_HOSTS: want a loopback host; got entry 1 of 2, 10.0.0.1: it is not loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !isConfigError(tc.err) || tc.err.Error() != tc.want {
				t.Errorf("got %v, want the configuration error %q", tc.err, tc.want)
			}
		})
	}
}

// An entry of BYWARD_CLIENT_DENYLIST that client registration refuses at wiring is named by its place
// and its length in characters, never shown, in the format of every refusal config makes.
func TestADenylistEntryRefusedAtWiringIsNamedByItsPlaceAndLength(t *testing.T) {
	const (
		want   = "BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got "
		reason = "it is not a client ID metadata document URL: only port 443 is fetched"
	)
	for _, tc := range []struct {
		name, list string
		index      int
		want       string
	}{
		{"the first entry", "https://app.example:8443/bü-" + canaryText + ".json, good.example", 0, want + "entry 1 of 2 (43 characters, not shown): " + reason},
		{"the second entry", "good.example, https://app.example:8443/c.json", 1, want + "entry 2 of 2 (31 characters, not shown): " + reason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, nil, "BYWARD_CLIENT_DENYLIST="+tc.list)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.RefusedDenylistEntry(tc.index, reason); !isConfigError(got) || got.Error() != tc.want {
				t.Errorf("got %v, want %q", got, tc.want)
			}
		})
	}
}
