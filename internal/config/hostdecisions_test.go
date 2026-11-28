package config

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/host"
	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// Each host and URL setting's decision on every host family is pinned in testdata/hostdecisions.golden,
// and the inputs a setting takes in testdata/hostdecisions.allowed, so a setting that takes a new
// form fails by name (#656). The messages are hostrule.golden's.
func TestEveryHostSettingDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/config", hostColumns(t))
}

// FuzzHostDecisions fuzzes the host each of these checks reads, beyond the golden's families (#661):
// see hostfamilies.Fuzz for what it fails.
func FuzzHostDecisions(f *testing.F) { hostfamilies.Fuzz(f, hostColumns, host.Split, host.Serialize) }

// hostColumns are the checks the golden test and FuzzHostDecisions judge.
func hostColumns(t testing.TB) []hostfamilies.Column {
	// An empty value is never parsed: it is the setting's empty meaning (unset, its default, or off
	// for internal-listen), which every setting takes, as Load reads it. A URL setting's column
	// records what its parser takes, the widest it decides: an http public URL or issuer on loopback
	// also needs --dev, which Load checks for the public URL and the oidc adapter for the issuer (the
	// oidc columns).
	// setting is the column of the setting name over probes, named col, or name when col is "".
	setting := func(name, col string, probes []hostfamilies.Probe, parse func(Value) error) hostfamilies.Column {
		if col == "" {
			col = name
		}
		return hostfamilies.Column{Name: col, Probes: probes, Judge: func(in string) (bool, string) {
			if in == "" {
				return true, ""
			}
			if err := parse(Value{Setting: lookup(name), Given: NewOpaque(in)}); err != nil {
				return false, reasonClass(err.Error())
			}
			return true, ""
		}}
	}
	list := func(parse func(Value) ([]string, []error)) func(Value) error {
		return func(v Value) error { _, errs := parse(v); return errors.Join(errs...) }
	}
	single := func(parse func(Value) (string, error)) func(Value) error {
		return func(v Value) error { _, err := parse(v); return err }
	}
	listen := func(want string) func(Value) error {
		return func(v Value) error { _, err := parseListen(v, want); return err }
	}
	// noAuth is the --insecure-no-auth fence on one setting, outside a container, which Load decides
	// (checkNoAuth); listen's 127.0.0.1:9090 is refused for being internal-listen's default, not by the
	// fence. The whole configuration loads with the probe in that setting, the rest as loadAnon sets
	// them.
	noAuth := func(name string, probes []hostfamilies.Probe) hostfamilies.Column {
		return hostfamilies.Column{Name: "no-auth " + name, Probes: probes, Judge: func(in string) (bool, string) {
			if _, err := loadAnon(t, nil, Setting{Name: name}.Env()+"="+in); err != nil {
				return false, reasonClass(err.Error())
			}
			return true, ""
		}}
	}
	https, both := hostfamilies.URLProbes("/mcp", "https"), hostfamilies.URLProbes("/mcp", "https", "http")
	hosts := hostfamilies.HostProbes()
	return []hostfamilies.Column{
		setting("public-url", "", both, func(v Value) error { _, err := parsePublicURL(v); return err }),
		setting("upstream-url", "", both, func(v Value) error { _, err := parseUpstreamURL(v); return err }),
		setting("resource-documentation", "", https, single(parseResourceDocumentation)),
		setting("oidc-issuer", "", both, single(parseIssuer)),
		setting("allowed-origins", "", hostfamilies.URLProbes("", "https", "http"), list(parseOrigins)),
		setting("allowed-hosts", "", hosts, list(parseAllowedHosts)),
		setting("cimd-trusted-hosts", "", hosts, list(parseCIMDHosts)),
		setting("cimd-allowed-hosts", "", hosts, list(parseCIMDHosts)),
		setting("client-denylist", "client-denylist host", hosts, list(func(v Value) ([]string, []error) { return parseChecked(v, denylistEntries) })),
		// Config refuses only a client ID that can carry a credential, or a zone; registration's
		// "denylist entry" column judges the rest of the URL. So this column judges every client ID
		// that holds what a credential or a zone is written with, whatever its family.
		setting("client-denylist", "client-denylist client ID", credentialOrZone(hostfamilies.URLProbes("/client.json", "https")), list(func(v Value) ([]string, []error) { return parseChecked(v, denylistEntries) })),
		setting("listen", "", hosts, listen("host:port such as 127.0.0.1:8080")),
		setting("internal-listen", "", hosts, listen("host:port such as 127.0.0.1:9090, or empty")),
		noAuth("public-url", both),
		noAuth("listen", hosts),
		noAuth("allowed-hosts", hosts),
		noAuth("allowed-origins", hostfamilies.URLProbes("", "https", "http")),
	}
}

var (
	lengthNote = regexp.MustCompile(`\(\d+ characters?, not shown\)`)
	entryNote  = regexp.MustCompile(`entry \d+ of \d+`)
	charPlace  = regexp.MustCompile(`at position \d+`)
)

// reasonClass is a refusal's message with its value's length, its entry's place and a character's
// position replaced, so that the refusals for one reason count as one class in the decision golden.
func reasonClass(msg string) string {
	msg = lengthNote.ReplaceAllString(msg, "(N characters, not shown)")
	msg = entryNote.ReplaceAllString(msg, "entry N of N")
	return charPlace.ReplaceAllString(msg, "at position N")
}

func TestAReasonClassCountsTheRefusalsForOneReasonAsOne(t *testing.T) {
	for in, want := range map[string]string{
		"BYWARD_ALLOWED_HOSTS: want a host; got entry 2 of 3 (12 characters, not shown): it has a port":              "BYWARD_ALLOWED_HOSTS: want a host; got entry N of N (N characters, not shown): it has a port",
		"got a value (1 character, not shown): its host has a character no host name holds at position 7":            "got a value (N characters, not shown): its host has a character no host name holds at position N",
		"got entry 12 of 13 (130 characters, not shown): its host has a character no host name holds at position 17": "got entry N of N (N characters, not shown): its host has a character no host name holds at position N",
		"BYWARD_LISTEN: want host:port": "BYWARD_LISTEN: want host:port",
	} {
		if got := reasonClass(in); got != want {
			t.Errorf("reasonClass(%q) = %q, want %q", in, got, want)
		}
	}
}

// credentialOrZone is the client ID probes that hold what a credential or a zone is written with
// (@ ? # %), whatever their family, and every URL shape.
func credentialOrZone(probes []hostfamilies.Probe) []hostfamilies.Probe {
	var out []hostfamilies.Probe
	for _, p := range probes {
		if p.Family == "url shape" || strings.ContainsAny(strings.TrimPrefix(p.Input, "https://"), "@?#%") {
			out = append(out, p)
		}
	}
	return out
}
