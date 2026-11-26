package config

import (
	"slices"
	"strings"
	"testing"
)

// A new member of a family (EnabledBy) is refused once given while its family is off, in the family's
// own words and with no other code (#658): a probe setting appended to the registry is named beside the
// family's settings, the CIMD one in its own error, the app-only one joined with the others; left
// unset, it is not refused.
func TestANewMemberOfAFamilyIsRefusedOnceGivenWhileItsFamilyIsOff(t *testing.T) {
	probe := func(enabledBy string) Setting {
		return Setting{Name: "probe-member", shape: asGivenShape, Group: GroupOperations, Auth: ForAuth, BothUpstreams: true, EnabledBy: enabledBy}
	}
	for _, tc := range []struct {
		name, enabledBy string
		env             []string
		check           func(c *Config, v *Values) []error
		want            string
	}{
		{"CIMD, a member given", "cimd", []string{"BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai", "BYWARD_PROBE_MEMBER=x"},
			func(c *Config, v *Values) []error { return c.clientSources(v) },
			"BYWARD_CIMD_TRUSTED_HOSTS has no effect while BYWARD_CIMD is false; remove one of them\nBYWARD_PROBE_MEMBER has no effect while BYWARD_CIMD is false; remove one of them"},
		{"CIMD, a member left unset", "cimd", []string{"BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"},
			func(c *Config, v *Values) []error { return c.clientSources(v) },
			"BYWARD_CIMD_TRUSTED_HOSTS has no effect while BYWARD_CIMD is false; remove one of them"},
		{"app-only, a member given", "app-tokens", []string{"BYWARD_APP_ROLES=r", "BYWARD_PROBE_MEMBER=x"},
			func(c *Config, v *Values) []error { return c.appTokens(v) },
			"BYWARD_APP_ROLES, BYWARD_PROBE_MEMBER set while BYWARD_APP_TOKENS=off: they configure app-only callers; set BYWARD_APP_TOKENS=entra, or remove them"},
		{"app-only, a member left unset", "app-tokens", []string{"BYWARD_APP_ROLES=r"},
			func(c *Config, v *Values) []error { return c.appTokens(v) },
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
	reg := append(slices.Clone(registry), Setting{Name: "probe-member", shape: secretShape, Group: GroupOperations, Auth: ForAuth, BothUpstreams: true, EnabledBy: "cimd"})
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

// Every family enabler has a walk: a new member of each is refused by Load's own path while its family
// is off, so an enabler added to familyEnablers with no walk fails here (#658). The off value is the
// test's, and an enabler it does not know fails until it is given one.
func TestEveryFamilyEnablerRefusesANewMemberWhileItIsOff(t *testing.T) {
	off := map[string]string{"cimd": "false", "app-tokens": "off"}
	for _, enabler := range familyEnablers {
		t.Run(enabler, func(t *testing.T) {
			value, ok := off[enabler]
			if !ok {
				t.Fatalf("give %s's off value here, and a walk that refuses its family while it is off", enabler)
			}
			reg := append(slices.Clone(registry), Setting{Name: "probe-member", shape: asGivenShape, Group: GroupOperations, Auth: ForAuth, BothUpstreams: true, EnabledBy: enabler})
			env := append(slices.Clone(base), lookup(enabler).Env()+"="+value, "BYWARD_PROBE_MEMBER=x")
			v, err := resolve(reg, nil, env, baseFiles, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validate(v, false, false); !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_PROBE_MEMBER") {
				t.Errorf("%s=%s with a new member given: err = %v, want it refused, named", lookup(enabler).Env(), value, err)
			}
		})
	}
}

// A CIMD host list counts once it holds an entry, not once given: a list of none while CIMD is false
// is refused for its form alone, never also as having no effect (#658), by its variable and its flag.
func TestACIMDHostListOfNoneIsRefusedOnlyForItsForm(t *testing.T) {
	for _, name := range []string{"cimd-trusted-hosts", "cimd-allowed-hosts"} {
		for _, f := range givenForms(lookup(name), ",") {
			_, err := load(t, f.args, append([]string{"BYWARD_CIMD=false"}, f.env...)...)
			if want := f.from + ": want at least one entry; got a list of none"; !isConfigError(err) || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "no effect") {
				t.Errorf("%s=, beside BYWARD_CIMD=false: err = %v, want %q and no \"no effect\"", f.from, err, want)
			}
		}
	}
}
