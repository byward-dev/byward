package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// probe is a new member of the family enabledBy turns on, which no code names.
func probe(enabledBy string) Setting {
	return Setting{Name: "probe-member", shape: asGivenShape, Group: GroupOperations, Auth: ForAuth, BothUpstreams: true, EnabledBy: enabledBy}
}

// A new member of a family (EnabledBy) is refused once given while its family is off, in the family's
// own words and with no other code (#658): a probe setting appended to the registry is named beside the
// family's settings, the CIMD one in its own error, the app-only one joined with the others; left
// unset, it is not refused.
func TestANewMemberOfAFamilyIsRefusedOnceGivenWhileItsFamilyIsOff(t *testing.T) {
	for _, tc := range []struct {
		name, enabledBy string
		env             []string
		check           func(c *Config, v *Values) []error
		want            string
	}{
		{"CIMD, a member given", "cimd", []string{"BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai", "BYWARD_PROBE_MEMBER=x"},
			(*Config).clientSources,
			"BYWARD_CIMD_TRUSTED_HOSTS has no effect while BYWARD_CIMD is false; remove one of them\nBYWARD_PROBE_MEMBER has no effect while BYWARD_CIMD is false; remove one of them"},
		{"CIMD, a member left unset", "cimd", []string{"BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"},
			(*Config).clientSources,
			"BYWARD_CIMD_TRUSTED_HOSTS has no effect while BYWARD_CIMD is false; remove one of them"},
		{"app-only, a member given", "app-tokens", []string{"BYWARD_APP_ROLES=r", "BYWARD_PROBE_MEMBER=x"},
			(*Config).appTokens,
			"BYWARD_APP_ROLES, BYWARD_PROBE_MEMBER set while BYWARD_APP_TOKENS=off: they configure app-only callers; set BYWARD_APP_TOKENS=entra, or remove them"},
		{"app-only, a member left unset", "app-tokens", []string{"BYWARD_APP_ROLES=r"},
			(*Config).appTokens,
			"BYWARD_APP_ROLES set while BYWARD_APP_TOKENS=off: they configure app-only callers; set BYWARD_APP_TOKENS=entra, or remove them"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := append(slices.Clone(registry), probe(tc.enabledBy))
			v, err := resolve(reg, nil, tc.env, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, e := range tc.check(&Config{}, v) {
				got = append(got, e.Error())
			}
			if strings.Join(got, "\n") != tc.want {
				t.Errorf("errors:\n%s\nwant:\n%s", strings.Join(got, "\n"), tc.want)
			}
		})
	}
}

// A new secret member counts once given, an empty file too: it has no reader of its own to refuse the
// empty file, so the family's check is what keeps it from loading while the family is off (#658).
func TestANewSecretMemberGivenAnEmptyFileIsRefusedWhileItsFamilyIsOff(t *testing.T) {
	secret := probe("cimd")
	secret.shape = secretShape
	reg := append(slices.Clone(registry), secret)
	empty := func(p string) ([]byte, error) {
		if p == "/run/secrets/probe-member" {
			return nil, nil
		}
		return baseFiles(p)
	}
	v, err := resolve(reg, nil, []string{"BYWARD_CIMD=false", "BYWARD_PROBE_MEMBER_FILE=/run/secrets/probe-member"}, empty, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range (&Config{}).clientSources(v) {
		got = append(got, e.Error())
	}
	if want := "BYWARD_PROBE_MEMBER_FILE has no effect while BYWARD_CIMD is false; remove one of them"; strings.Join(got, "\n") != want {
		t.Errorf("errors:\n%s\nwant:\n%s", strings.Join(got, "\n"), want)
	}
}

// A member refused for the upstream mode that is off is not also refused by its family: isSet skips it,
// as given does, so it gets the upstream mode's one refusal (#631), whatever family it is in.
func TestAMemberRefusedForTheUpstreamModeThatIsOffIsNotAlsoRefusedByItsFamily(t *testing.T) {
	for _, tc := range []struct {
		enabler, off string
		check        func(c *Config, v *Values) []error
	}{
		{"cimd", "BYWARD_CIMD=false", (*Config).clientSources},
		{"app-tokens", "BYWARD_APP_TOKENS=off", (*Config).appTokens},
	} {
		t.Run(tc.enabler, func(t *testing.T) {
			stdioOnly := probe(tc.enabler)
			stdioOnly.Group, stdioOnly.BothUpstreams = GroupStdioUpstream, false // beside base's HTTP upstream: refused
			v, err := resolve(append(slices.Clone(registry), stdioOnly), nil, append(slices.Clone(base), tc.off, "BYWARD_PROBE_MEMBER=x"), baseFiles, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !v.refusedOffMode("probe-member") {
				t.Fatal("the probe is not refused for the upstream mode that is off, so this test shows nothing")
			}
			if errs := tc.check(&Config{}, v); len(errs) != 0 {
				t.Errorf("%s's check: %v, want none: the upstream mode's refusal is its one error", tc.enabler, errs)
			}
		})
	}
}

// An enabler that does not parse is neither on nor off: a member given beside it adds nothing to the
// enabler's own parse error, never also "has no effect" or "set while … off" (#658), by its variable
// and as a flag set to nothing.
func TestAMemberBesideAnEnablerThatDoesNotParseAddsNothingToItsError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args, env []string
		member    string
	}{
		{"BYWARD_CIMD=bogus", nil, []string{"BYWARD_CIMD=bogus"}, "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"},
		{"--cimd=", []string{"--cimd="}, nil, "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"},
		{"BYWARD_APP_TOKENS=bogus", nil, []string{"BYWARD_APP_TOKENS=bogus"}, "BYWARD_APP_ROLES=r"},
		{"--app-tokens=", []string{"--app-tokens="}, nil, "BYWARD_APP_ROLES=r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, alone := load(t, tc.args, tc.env...)
			if !isConfigError(alone) {
				t.Fatalf("%s alone: err = %v, want its config error", tc.name, alone)
			}
			_, beside := load(t, tc.args, append(slices.Clone(tc.env), tc.member)...)
			if beside == nil || beside.Error() != alone.Error() {
				t.Errorf("%s with %s: err = %v, want only its parse error %q", tc.name, tc.member, beside, alone)
			}
		})
	}
}

// A CIMD host list beside a BYWARD_CIMD that does not parse is still parsed: its own form error shows
// beside the parse error, and only that, never also "has no effect" (#658).
func TestACIMDHostListBesideACIMDThatDoesNotParseStillGivesItsOwnFormError(t *testing.T) {
	for _, member := range []string{"BYWARD_CIMD_TRUSTED_HOSTS=https://claude.ai", "BYWARD_CIMD_ALLOWED_HOSTS=https://claude.ai"} { // a URL, not a host name
		_, own := load(t, nil, member) // beside CIMD at its default, true
		if !isConfigError(own) {
			t.Fatalf("%s alone: err = %v, want its form error", member, own)
		}
		for _, tc := range []struct {
			name      string
			args, env []string
		}{
			{"BYWARD_CIMD=bogus", nil, []string{"BYWARD_CIMD=bogus"}},
			{"--cimd=", []string{"--cimd="}, nil},
		} {
			t.Run(tc.name+" "+strings.SplitN(member, "=", 2)[0], func(t *testing.T) {
				_, alone := load(t, tc.args, tc.env...)
				if !isConfigError(alone) {
					t.Fatalf("%s alone: err = %v, want its config error", tc.name, alone)
				}
				_, beside := load(t, tc.args, append(slices.Clone(tc.env), member)...)
				if want := alone.Error() + "; " + own.Error(); beside == nil || beside.Error() != want {
					t.Errorf("%s with %s: err = %v, want %q", tc.name, member, beside, want)
				}
			})
		}
	}
}

// A setting whose EnabledBy names no family enabler stops the program at init, naming it: its family
// would never be checked, so it would load while the family is off (#658). The real registry passes.
func TestASettingEnabledByNoFamilyIsRefused(t *testing.T) {
	checkEnablers(registry) // a second catch for the real registry, should init stop calling it
	defer func() {
		const want = "config: setting probe is EnabledBy dcr, which no family walk checks: give it one of cimd, app-tokens"
		if r := recover(); r != want {
			t.Fatalf("recovered %v, want %q", r, want)
		}
	}()
	checkEnablers([]Setting{{Name: "probe", EnabledBy: "dcr"}})
}

// Each family enabler is a setting and turns at least one setting on, not itself: an enabler with no
// member checks nothing, and an enabler in its own family would be refused while it is off.
func TestEveryFamilyEnablerTurnsASettingOn(t *testing.T) {
	for _, enabler := range familyEnablers {
		lookup(enabler) // panics on a setting that does not exist
		var family []string
		for _, s := range registry {
			if s.EnabledBy == enabler {
				family = append(family, s.Name)
			}
		}
		if len(family) == 0 || slices.Contains(family, enabler) {
			t.Errorf("%s turns on %q: want at least one setting, and not itself", enabler, family)
		}
	}
}

// Every family enabler has a walk: a new member of each, given by its variable or as a flag set to
// nothing (#596), is refused by Load's own path while its family is off, in the family's words, and its
// variable set to nothing is unset and loads (#428). An enabler added to familyEnablers with no walk
// fails here (#658), as does one the test has no off value or refusal for.
func TestEveryFamilyEnablerRefusesANewMemberWhileItIsOffAndTakesTheMembersVariableSetToNothingAsUnset(t *testing.T) {
	off := map[string]string{"cimd": "false", "app-tokens": "off"}
	refusal := map[string]string{"cimd": "%s has no effect while BYWARD_CIMD is false", "app-tokens": "%s set while BYWARD_APP_TOKENS=off"}
	for _, enabler := range familyEnablers {
		t.Run(enabler, func(t *testing.T) {
			value, ok := off[enabler]
			if !ok || refusal[enabler] == "" {
				t.Fatalf("give %s's off value and refusal here, and a walk that refuses its family while it is off", enabler)
			}
			for _, tc := range []struct {
				given     string
				args, env []string
				named     string // the refused probe, as given; "" when it loads
			}{
				{"by its variable", nil, []string{"BYWARD_PROBE_MEMBER=x"}, "BYWARD_PROBE_MEMBER"},
				{"as a flag set to nothing", []string{"--probe-member="}, nil, "--probe-member"},
				{"as a variable set to nothing", nil, []string{"BYWARD_PROBE_MEMBER="}, ""},
			} {
				env := append(append(slices.Clone(base), lookup(enabler).Env()+"="+value), tc.env...)
				v, err := resolve(append(slices.Clone(registry), probe(enabler)), tc.args, env, baseFiles, nil)
				if err != nil {
					t.Errorf("%s=%s, a member %s: resolve: %v", lookup(enabler).Env(), value, tc.given, err)
					continue
				}
				_, err = validate(v, false, false)
				if tc.named == "" {
					if err != nil {
						t.Errorf("%s=%s, a member %s: err = %v, want it unset, loading", lookup(enabler).Env(), value, tc.given, err)
					}
					continue
				}
				if want := fmt.Sprintf(refusal[enabler], tc.named); !isConfigError(err) || !strings.Contains(err.Error(), want) {
					t.Errorf("%s=%s, a member %s: err = %v, want it refused: %q", lookup(enabler).Env(), value, tc.given, err, want)
				}
			}
		})
	}
}

// A CIMD host list counts once it holds an entry or is a flag set to nothing (#596), not merely once
// given: a list of none ("," or white space alone) while CIMD is false is refused for its form alone,
// never also as having no effect (#658), by its variable and its flag.
func TestACIMDHostListOfNoneIsRefusedOnlyForItsForm(t *testing.T) {
	for _, name := range []string{"cimd-trusted-hosts", "cimd-allowed-hosts"} {
		for _, none := range []string{",", " "} {
			for _, f := range givenForms(lookup(name), none) {
				_, err := load(t, f.args, append([]string{"BYWARD_CIMD=false"}, f.env...)...)
				if want := f.from + ": want at least one entry; got a list of none"; !isConfigError(err) || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "no effect") {
					t.Errorf("%s=%q beside BYWARD_CIMD=false: err = %v, want %q and no \"no effect\"", f.from, none, err, want)
				}
			}
		}
	}
}
