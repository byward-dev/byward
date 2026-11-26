package config

import (
	"slices"
	"strings"
	"testing"
)

// A setting that leaves a classification unstated, or states its upstream mode twice, is refused,
// naming it and the classification (#658): a probe setting appended to the registry is refused with
// no other code change, so a new setting is decided before it can be read open by default. The real
// registry passes, at init and here.
func TestASettingWhoseClassificationIsUnstatedOrContradictoryIsRefused(t *testing.T) {
	checkClassified(registry) // a second catch for the real registry, should init stop calling it
	probe := func(edit func(*Setting)) Setting {
		s := Setting{Name: "probe", shape: asGivenShape, Group: GroupOperations, Auth: NotForAuth, BothUpstreams: true}
		edit(&s)
		return s
	}
	for _, tc := range []struct {
		name  string
		probe Setting
		want  string // the panic, or "" for none
	}{
		{"classified", probe(func(*Setting) {}), ""},
		{"HTTP only, by its hint", probe(func(s *Setting) { s.BothUpstreams, s.StdioHint = false, httpOnlyRefusal }), ""},
		{"in an upstream group, by its group", probe(func(s *Setting) { s.Group, s.BothUpstreams = GroupHTTPUpstream, false }), ""},
		{"no Auth", probe(func(s *Setting) { s.Auth = authUnstated }),
			"config: setting probe does not say whether it configures authentication: give it Auth: ForAuth or Auth: NotForAuth"},
		{"an Auth out of range", probe(func(s *Setting) { s.Auth = AuthUse(9) }),
			"config: setting probe does not say whether it configures authentication: give it Auth: ForAuth or Auth: NotForAuth"},
		{"no upstream mode", probe(func(s *Setting) { s.BothUpstreams = false }),
			"config: setting probe does not say which upstream mode it is for: give it a StdioHint if only an HTTP upstream reads it, or BothUpstreams"},
		{"both modes and a hint", probe(func(s *Setting) { s.StdioHint = httpOnlyRefusal }),
			"config: setting probe has a StdioHint and BothUpstreams: give it one of them"},
		{"both modes in an upstream group", probe(func(s *Setting) { s.Group = GroupStdioUpstream }),
			"config: setting probe is in an upstream group, which decides its mode: drop BothUpstreams"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if got, ok := r.(string); (tc.want == "" && r != nil) || (tc.want != "" && (!ok || got != tc.want)) {
					t.Errorf("checkClassified recovered %v, want %q", r, tc.want)
				}
			}()
			checkClassified(append(slices.Clone(registry), tc.probe))
		})
	}
}

// Every setting of an IdP family's group is refused beside the other IdP, named as given: the family is
// the setting's group, so a new one is covered with no list to edit (#658).
func TestEverySettingOfAnIdPFamilyIsRefusedBesideTheOtherIdP(t *testing.T) {
	files := func(p string) ([]byte, error) {
		if p == "/run/secrets/other-idp" {
			return []byte("x\n"), nil
		}
		return filesPlusEmptyAndBlank(p)
	}
	n := map[Group]int{}
	for _, s := range registry {
		if s.Group != GroupEntra && s.Group != GroupOIDC {
			continue
		}
		n[s.Group]++
		env, idp := oidcBase, "keycloak" // an Entra setting beside an OIDC IdP (oidcBase: the keycloak preset)
		if s.Group == GroupOIDC {
			env, idp = base, "entra"
		}
		value := "x"
		if s.Secret() {
			value = "/run/secrets/other-idp"
		}
		for _, f := range givenForms(s, value) { // by its variable and by its flag
			want := f.from + " cannot be used with BYWARD_IDP=" + idp + ": they configure the "
			if _, _, err := Load(f.args, append(slices.Clone(env), f.env...), files); !isConfigError(err) || !strings.Contains(err.Error(), want) {
				t.Errorf("%s beside BYWARD_IDP=%s: err = %v, want it to say %q", f.from, idp, err, want)
			}
		}
	}
	if n[GroupEntra] == 0 || n[GroupOIDC] == 0 {
		t.Fatalf("settings checked by group: %v, want both IdP groups", n)
	}
}

// The other IdP's settings are those of its group, not of a name: a setting of GroupOIDC is refused
// beside Entra whatever its name, and one named oidc-… outside the group is not (#658).
func TestTheOtherIdPsSettingsAreThoseOfItsGroup(t *testing.T) {
	reg := []Setting{
		{Name: "in-the-group", shape: asGivenShape, Group: GroupOIDC},
		{Name: "oidc-elsewhere", shape: asGivenShape, Group: GroupOperations},
	}
	v, err := resolve(reg, nil, []string{"BYWARD_IN_THE_GROUP=x", "BYWARD_OIDC_ELSEWHERE=x"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	errs := (&Config{IdP: "entra"}).mixedIdPSettings(v, GroupOIDC, "oidc")
	const want = "BYWARD_IN_THE_GROUP cannot be used with BYWARD_IDP=entra: they configure the oidc IdP; remove them, or set BYWARD_IDP to match"
	if len(errs) != 1 || errs[0].Error() != want {
		t.Fatalf("errs = %v, want only %q", errs, want)
	}
}

// The settings that do not configure authentication, and so load beside --insecure-no-auth, are
// exactly these: a setting moved from ForAuth to NotForAuth would run open with no sign-in, so it
// fails here by name until it is listed on purpose (#658). A new ForAuth setting needs no edit.
func TestTheSettingsThatDoNotConfigureAuthenticationAreExactlyThese(t *testing.T) {
	want := []string{
		"public-url", "upstream-url", "upstream-header-timeout", "upstream-credential", "upstream-credential-header",
		"upstream-strip-headers", "upstream-command", "upstream-env", "stdio-max-processes", "stdio-max-processes-per-user",
		"stdio-stream-idle-timeout", "listen", "tls-cert-file", "tls-key-file", "allowed-origins", "allowed-hosts", "scope",
		"resource-name", "resource-documentation", "log-format", "trusted-proxies", "oauth-rate-limits", "internal-listen",
		"insecure-no-auth", "dev",
	}
	var got []string
	for _, s := range registry {
		if s.Auth == NotForAuth {
			got = append(got, s.Name)
		}
	}
	for _, name := range got {
		if !slices.Contains(want, name) {
			t.Errorf("%s is NotForAuth, so it loads beside --insecure-no-auth: list it here if it should, else make it ForAuth", name)
		}
	}
	for _, name := range want {
		if !slices.Contains(got, name) {
			t.Errorf("%s is listed as NotForAuth but is not: drop it from this list", name)
		}
	}
}
