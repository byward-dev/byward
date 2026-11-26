package recordtb_test

import (
	"slices"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/recordtb"
)

// Each way a helper reports is recorded, apart as an error or a fatal; an error carries on and a
// fatal ends the helper, as testing does. FailNow and Skip* end it too, never reaching the real
// test, whose FailNow and SkipNow must run on its own goroutine.
func TestRunRecordsWhatAHelperReportsAndAFatalEndsIt(t *testing.T) {
	for _, tc := range []struct {
		name           string
		report         func(testing.TB)
		errors, fatals []string
	}{
		{"nothing", func(testing.TB) {}, nil, nil},
		{"Error", func(tb testing.TB) { tb.Error("a", 1) }, []string{"a1"}, nil},
		{"Errorf", func(tb testing.TB) { tb.Errorf("a %d", 1) }, []string{"a 1"}, nil},
		{"Fail", func(tb testing.TB) { tb.Fail() }, []string{"Fail"}, nil},
		{"Fatal", func(tb testing.TB) { tb.Fatal("a", 1) }, nil, []string{"a1"}},
		{"Fatalf", func(tb testing.TB) { tb.Fatalf("a %d", 1) }, nil, []string{"a 1"}},
		{"FailNow", func(tb testing.TB) { tb.FailNow() }, nil, []string{"FailNow"}},
		{"Skip", func(tb testing.TB) { tb.Skip("a", 1) }, nil, []string{"skipped: a1"}},
		{"Skipf", func(tb testing.TB) { tb.Skipf("a %d", 1) }, nil, []string{"skipped: a 1"}},
		{"SkipNow", func(tb testing.TB) { tb.SkipNow() }, nil, []string{"skipped"}},
		{"errors, then a fatal", func(tb testing.TB) { tb.Errorf("one"); tb.Error("two"); tb.Fatalf("three") }, []string{"one", "two"}, []string{"three"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := false
			rep := recordtb.Run(t, func(tb testing.TB) {
				tb.Helper()
				tc.report(tb)
				after = true
			})
			if !slices.Equal(rep.Errors, tc.errors) || !slices.Equal(rep.Fatals, tc.fatals) {
				t.Errorf("errors %q, fatals %q; want %q, %q", rep.Errors, rep.Fatals, tc.errors, tc.fatals)
			}
			if want := tc.fatals == nil; after != want {
				t.Errorf("helper carried on after reporting: %v, want %v", after, want)
			}
			if want := tc.errors != nil || tc.fatals != nil; rep.Failed() != want {
				t.Errorf("Failed() = %v, want %v", rep.Failed(), want)
			}
		})
	}
}

// What the recorder does not record reaches the real test, such as its name and temp directory.
func TestRunPassesWhatItDoesNotRecordToTheTest(t *testing.T) {
	var name, dir string
	recordtb.Run(t, func(tb testing.TB) { name, dir = tb.Name(), tb.TempDir() })
	if name != t.Name() || dir == "" {
		t.Errorf("Name %q, TempDir %q; want %q and a directory", name, dir, t.Name())
	}
}
