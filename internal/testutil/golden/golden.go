// Package golden compares a test's output with a golden file, or rewrites the file when
// BYWARD_UPDATE_GOLDEN=1 is set, so an intended change is one rerun and a reviewed diff.
package golden

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// UpdateEnv is the variable that makes Check rewrite the golden file instead of comparing with it.
const UpdateEnv = "BYWARD_UPDATE_GOLDEN"

// Check fails t when got differs from the file at path, naming the first line that differs and
// then hint, which says what the file pins and what else a change to it needs. With UpdateEnv set to
// 1 it writes got to path instead.
func Check(t testing.TB, path, got, hint string) {
	t.Helper()
	if os.Getenv(UpdateEnv) == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write the golden file %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a test's own golden file
	if err != nil {
		t.Fatalf("read the golden file %s: %v (%s=1 writes it)", path, err, UpdateEnv)
	}
	if got != string(want) {
		t.Errorf("%s differs at %s\n%s; if intended, rerun with %s=1 and review the diff", path, FirstDiff(got, string(want)), hint, UpdateEnv)
	}
}

// FirstDiff names the first line where got and want differ, and both versions of it. A line one
// side lacks reads as "(no line)", so a missing final newline is named too.
func FirstDiff(got, want string) string {
	g, w := strings.SplitAfter(got, "\n"), strings.SplitAfter(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		gl, wl := line(g, i), line(w, i)
		if gl != wl {
			return fmt.Sprintf("line %d:\n got: %s\nwant: %s", i+1, gl, wl)
		}
	}
	return "no line"
}

// line is the i-th of lines, quoted with its newline, or "(no line)" when there is none.
func line(lines []string, i int) string {
	if i >= len(lines) || lines[i] == "" {
		return "(no line)"
	}
	return fmt.Sprintf("%q", lines[i])
}
