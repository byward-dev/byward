package server

import (
	"testing"

	"github.com/byward-dev/byward/internal/doctor"
)

// A warning shows its fix after the setting it names; one without a setting (the access gate's,
// or doctor's "authentication is off") shows its message alone, with no fix, in check and in
// doctor.
func TestAWarningNamesItsSettingInItsFixAndOneWithoutASettingShowsNoFix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		w        Warning
		wantLine string
		wantFix  string
	}{
		{"with a setting", Warning{Message: "m", Setting: "BYWARD_X", Fix: "do y"}, "m (BYWARD_X: do y)", "BYWARD_X: do y"},
		{"without a setting", Warning{Message: "m", Fix: "do y"}, "m", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.String(); got != tc.wantLine {
				t.Errorf("check line %q, want %q", got, tc.wantLine)
			}
			want := doctor.Result{Class: doctor.ClassProxy, Name: "configuration", Status: doctor.Warn, Message: "m", Fix: tc.wantFix}
			if got := tc.w.result(doctor.CheckConfiguration); got != want {
				t.Errorf("doctor result %+v\nwant %+v", got, want)
			}
		})
	}
}
