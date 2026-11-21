package golden_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/golden"
)

// recorder is a testing.TB that keeps what Check reports. Fatalf ends the goroutine, as testing does.
type recorder struct {
	testing.TB
	errors, fatals []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
	runtime.Goexit()
}

// check runs golden.Check against a recorder, on its own goroutine so that Fatalf can end it.
func check(t *testing.T, path, got, hint string) *recorder {
	t.Helper()
	r := &recorder{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		golden.Check(r, path, got, hint)
	}()
	wg.Wait()
	return r
}

func goldenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.golden")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckPassesWhenTheOutputMatchesTheFile(t *testing.T) {
	t.Setenv(golden.UpdateEnv, "")
	if r := check(t, goldenFile(t, "a\nb\n"), "a\nb\n", "the hint"); len(r.errors)+len(r.fatals) != 0 {
		t.Fatalf("a match failed: %q %q", r.errors, r.fatals)
	}
}

// A mismatch names the first line that differs, both versions of it, and the site's hint.
func TestCheckNamesTheFirstDifferingLineAndTheHint(t *testing.T) {
	t.Setenv(golden.UpdateEnv, "")
	for _, tc := range []struct {
		name, want, got, line string
	}{
		{"the first line", "a\nb\nc\n", "x\nb\nc\n", "line 1:\n got: \"x\\n\"\nwant: \"a\\n\""},
		{"a middle line", "a\nb\nc\n", "a\nx\nc\n", "line 2:\n got: \"x\\n\"\nwant: \"b\\n\""},
		{"the last line", "a\nb\nc\n", "a\nb\nx\n", "line 3:\n got: \"x\\n\"\nwant: \"c\\n\""},
		{"a line the output adds", "a\n", "a\nb\n", "line 2:\n got: \"b\\n\"\nwant: (no line)"},
		{"a line the output lacks", "a\nb\n", "a\n", "line 2:\n got: (no line)\nwant: \"b\\n\""},
		{"only the final newline", "a\n", "a", "line 1:\n got: \"a\"\nwant: \"a\\n\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := goldenFile(t, tc.want)
			r := check(t, path, tc.got, "the metric names are a public interface")
			if len(r.fatals) != 0 || len(r.errors) != 1 {
				t.Fatalf("errors %q, fatals %q; want one error", r.errors, r.fatals)
			}
			want := path + " differs at " + tc.line + "\nthe metric names are a public interface; if intended, rerun with BYWARD_UPDATE_GOLDEN=1 and review the diff"
			if r.errors[0] != want {
				t.Fatalf("error\n%s\nwant\n%s", r.errors[0], want)
			}
		})
	}
}

// With BYWARD_UPDATE_GOLDEN=1, Check writes the output to the file and reports nothing.
func TestCheckRewritesTheFileUnderTheUpdateVariable(t *testing.T) {
	t.Setenv(golden.UpdateEnv, "1")
	path := goldenFile(t, "old\n")
	if r := check(t, path, "new\n", "the hint"); len(r.errors)+len(r.fatals) != 0 {
		t.Fatalf("the update failed: %q %q", r.errors, r.fatals)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "new\n" { //nolint:gosec // G304: the test's own temp file
		t.Fatalf("the file holds %q (%v), want the output", b, err)
	}
}

// Only 1 updates: another value compares, as an unset variable does.
func TestCheckComparesUnderAnyOtherValueOfTheUpdateVariable(t *testing.T) {
	t.Setenv(golden.UpdateEnv, "true")
	path := goldenFile(t, "old\n")
	if r := check(t, path, "new\n", "the hint"); len(r.errors) != 1 {
		t.Fatalf("errors %q, want the mismatch", r.errors)
	}
	if b, _ := os.ReadFile(path); string(b) != "old\n" { //nolint:gosec // G304: the test's own temp file
		t.Fatalf("the file holds %q, want it unchanged", b)
	}
}

// A golden file that cannot be read stops the test, and says how to write it.
func TestCheckStopsWhenTheFileCannotBeRead(t *testing.T) {
	t.Setenv(golden.UpdateEnv, "")
	r := check(t, filepath.Join(t.TempDir(), "missing.golden"), "a\n", "the hint")
	if len(r.fatals) != 1 || !strings.Contains(r.fatals[0], "BYWARD_UPDATE_GOLDEN=1 writes it") {
		t.Fatalf("fatals %q, want one naming the update variable", r.fatals)
	}
}
