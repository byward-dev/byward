package config

import (
	"slices"
	"testing"
)

// Every setting's Default is a value its parser takes: the setting left at its default loads, and given
// its Default explicitly, by its variable and by its flag, it loads to the same Config (#658). Each is
// read where it takes effect (readContextOf), so an off check or the upstream mode does not refuse it
// for being given. An enabler is read beside none of its family. The credential header is read beside
// an assertion header of its own, since both Defaults are Authorization and ADR-0016 §7 keeps the
// credential and the identity assertion apart. The whole Config is compared, the setting's own Value
// with its Source as the default's, as that alone differs by design. A Default its parser refuses
// fails here, the load error naming its variable; TestEverySettingSetToNothingLoadsAsIfUnset also
// loads each mode (emptyModes), every setting the mode does not set at its Default, naming the mode
// that refuses it.
func TestEverySettingsDefaultIsAValueItsParserTakes(t *testing.T) {
	n := 0
	for _, s := range registry {
		if s.Default == "" {
			continue
		}
		n++
		t.Run(s.Name, func(t *testing.T) {
			if s.Secret() {
				t.Fatalf("%s is a secret with a Default: give its file forms here", s.Name)
			}
			ctx := readContextOf(s)
			env := without(s.Env())(ctx.env) // the setting left at its default, even where its context sets it
			for _, m := range registry {
				if m.EnabledBy == s.Name { // an enabler at its default, beside none of its family (app-tokens' default, off, refuses its members as given)
					env = without(m.Env())(env)
				}
			}
			if s.Name == "upstream-credential-header" { // both Defaults are Authorization, and the credential and the identity assertion never share a header (ADR-0016 §7): the assertion takes a header of its own
				own := "X-Byward-Identity"
				if s.Default == own {
					own = "X-Byward-Assertion"
				}
				env = append(env, "BYWARD_ASSERTION_HEADER="+own)
			}
			want, _, err := Load(ctx.args, env, ctx.files)
			if err != nil {
				t.Fatalf("%s left at its default %q: %v, want it to load", s.Name, s.Default, err)
			}
			for _, f := range givenForms(s, s.Default) { // by its variable and by its flag; a stdio context's -- comes last
				given := f.from + "=" + s.Default
				got, _, err := Load(append(slices.Clone(f.args), ctx.args...), append(slices.Clone(env), f.env...), ctx.files)
				if err != nil {
					t.Errorf("%s: %v, want it to load as the default does", given, err)
					continue
				}
				gv := got.Values.byKey[s.Name]
				gv.Source = SourceDefault // differs by design: given, not defaulted; the rest must match
				got.Values.byKey[s.Name] = gv
				for _, d := range configDiff(*got, *want) {
					t.Errorf("%s: Config.%s, want it as the default loads", given, d)
				}
			}
		})
	}
	if n == 0 {
		t.Fatal("no setting has a Default")
	}
}
