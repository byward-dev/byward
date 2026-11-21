package config

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"
)

// loadsAlike fails t unless the two loads end the same way: the same error, and equal configurations
// or none.
func loadsAlike(t *testing.T, what string, got, want *Config, gotErr, wantErr error) {
	t.Helper()
	if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Errorf("%s: err %v, want %v", what, gotErr, wantErr)
	}
	if got == nil || want == nil {
		if got != want {
			t.Errorf("%s: Config %v, want %v", what, got, want)
		}
		return
	}
	for _, f := range configDiff(*got, *want) {
		t.Errorf("%s: Config.%s", what, f)
	}
}

// configDiff lists each field in which Config got differs from want, such as LoadEnvironment's from
// Load's, with both values. A setting in Values is named by its key, whichever side has it, so a mismatch
// reads as the setting, not as two pointer addresses.
func configDiff(got, want Config) []string {
	var out []string
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range gv.NumField() {
		name := gv.Type().Field(i).Name
		if name == "Values" {
			out = append(out, valuesDiff(got.Values, want.Values)...)
			continue
		}
		if g, w := gv.Field(i).Interface(), wv.Field(i).Interface(); !reflect.DeepEqual(g, w) {
			out = append(out, fmt.Sprintf("%s: got %+v, want %+v", name, g, w))
		}
	}
	if len(out) == 0 && !reflect.DeepEqual(got, want) { // a backstop, so a field this misses cannot hide a difference
		out = append(out, fmt.Sprintf("(a field configDiff names no difference in): got %+v %+v, want %+v %+v", got, got.Values, want, want.Values))
	}
	return out
}

// valuesDiff is configDiff for the resolved settings: each setting either side has that differs,
// then the setting order or the command after --, when only those differ.
func valuesDiff(got, want *Values) []string {
	if got == nil || want == nil {
		if got != want {
			return []string{fmt.Sprintf("Values: got nil %v, want nil %v", got == nil, want == nil)}
		}
		return nil
	}
	var out []string
	keys := slices.AppendSeq(slices.Collect(maps.Keys(got.byKey)), maps.Keys(want.byKey))
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		g, gok := got.byKey[k]
		w, wok := want.byKey[k]
		if gok != wok || !reflect.DeepEqual(g, w) {
			gs, ws := describeSetting(g, gok), describeSetting(w, wok)
			if gs == ws { // they differ in the registry entry only
				gs, ws = fmt.Sprintf("%+v", g), fmt.Sprintf("%+v", w)
			}
			out = append(out, fmt.Sprintf("Values[%s]: got %s, want %s", k, gs, ws))
		}
	}
	if len(out) == 0 && !reflect.DeepEqual(*got, *want) {
		out = append(out, "Values: the setting order or the command after -- differs")
	}
	return out
}

// describeSetting shows what the operator gave for a setting, without its registry entry: the value,
// where it came from, the file it was read from and the flag or variable that named that file, or
// that the setting is absent.
func describeSetting(v Value, present bool) string {
	if !present {
		return "absent"
	}
	return fmt.Sprintf("%q from %v, path %q named by %q", v.Given.raw(), v.Source, v.Path, v.From)
}
