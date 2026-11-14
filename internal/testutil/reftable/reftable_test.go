package reftable

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const page = `# Page

Prose before.

## Things

Some prose.

| Thing | Kind | Meaning |
|---|---|---|
| ` + "`b`" + ` | old | written for b |
| ` + "`gone`" + ` | old | written for gone |
| ` + "`a`" + ` | old | written for a |
| short |

Prose after.

## Things

| Thing | Meaning |
|---|---|
| ` + "`a`" + ` | a second heading of the same text: not this table |
`

func row(key string, old []string) []string {
	meaning := Todo
	if len(old) == 3 {
		meaning = old[2]
	}
	return []string{"`" + key + "`", "new", meaning}
}

// The first table under the heading gets one row per key, in the keys' order: hand-written cells
// are kept for known keys, a new key gets Todo, a key the code no longer has is dropped, and
// nothing else on the page moves.
func TestRenderRebuildsOnlyTheTable(t *testing.T) {
	got, err := render(page, "## Things", 0, []string{"a", "b", "c"}, row)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(page, "| `b` | old | written for b |\n| `gone` | old | written for gone |\n| `a` | old | written for a |\n| short |",
		"| `a` | new | written for a |\n| `b` | new | written for b |\n| `c` | new | "+Todo+" |", 1)
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if u := undescribed(got, "## Things", 0); !slices.Equal(u, []string{"c"}) {
		t.Errorf("undescribed %v, want [c]", u)
	}
	if u := undescribed(page, "## Things", 0); u != nil {
		t.Errorf("undescribed in the page as written %v, want none", u)
	}
}

// A row too short to have the key column does not stop render; it is dropped.
func TestRenderDropsARowTooShortForTheKeyColumn(t *testing.T) {
	got, err := render(page, "## Things", 1, nil, row)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "| short |") {
		t.Fatalf("the short row is still there:\n%s", got)
	}
}

// A missing heading, or a heading with no table before the next heading, is an error.
func TestRenderNeedsATableUnderTheHeading(t *testing.T) {
	for _, tc := range []struct{ doc, heading, inErr string }{
		{page, "## Missing", `no line "## Missing"`},
		{"## Empty\n\nprose\n\n## Next\n\n| a |\n|---|\n", "## Empty", `no table under "## Empty"`},
		{"## Header only\n\n| a |\n", "## Header only", `no table under "## Header only"`},
	} {
		_, err := render(tc.doc, tc.heading, 0, nil, row)
		if err == nil || !strings.Contains(err.Error(), tc.inErr) {
			t.Errorf("%s: err %v, want %q", tc.heading, err, tc.inErr)
		}
	}
}

// A row splits on |, but not on one inside backticks; cells are trimmed.
func TestCellsSplitsOutsideCode(t *testing.T) {
	for _, tc := range []struct {
		row  string
		want []string
	}{
		{"| a | b |", []string{"a", "b"}},
		{"|`x|y`| z |", []string{"`x|y`", "z"}},
		{"|  a  |  |", []string{"a", ""}},
		{"| a | b | ", []string{"a", "b"}},
	} {
		if got := cells(tc.row); !slices.Equal(got, tc.want) {
			t.Errorf("cells(%q) = %q, want %q", tc.row, got, tc.want)
		}
	}
}

// recorder is a testing.TB that records failures; Fatal ends the goroutine running Sync.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, a ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, a...))
}

func (r *recorder) Fatal(a ...any) {
	r.failures = append(r.failures, fmt.Sprint(a...))
	runtime.Goexit()
}

func (r *recorder) Fatalf(format string, a ...any) {
	r.Errorf(format, a...)
	runtime.Goexit()
}

// runSync runs Sync on a copy of doc and returns its failures and the file afterwards.
func runSync(t *testing.T, doc string, keys []string, update bool) ([]string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "page.md")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	env := ""
	if update {
		env = "1"
	}
	t.Setenv("BYWARD_UPDATE_REFERENCE", env)
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Table{Path: path, Heading: "## Things", Package: "./internal/x/"}.Sync(r, keys, row)
	}()
	<-done
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	return r.failures, string(b)
}

// Sync fails on a stale table and names the package that regenerates it; with
// BYWARD_UPDATE_REFERENCE=1 it rewrites the table, then fails only on a row still to describe.
func TestSyncFailsUntilTheTableIsCurrentAndDescribed(t *testing.T) {
	current, err := render(page, "## Things", 0, []string{"a", "b"}, row)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, doc string
		keys      []string
		update    bool
		inFailure string
		rewritten bool
	}{
		{"current", current, []string{"a", "b"}, false, "", false},
		{"stale", page, []string{"a", "b"}, false, "run BYWARD_UPDATE_REFERENCE=1 go test ./internal/x/", false},
		{"updated", page, []string{"a", "b"}, true, "", true},
		{"a new key", current, []string{"a", "b", "c"}, true, "describe c", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failures, after := runSync(t, tc.doc, tc.keys, tc.update)
			switch {
			case tc.inFailure == "" && len(failures) > 0:
				t.Fatalf("failures %q, want none", failures)
			case tc.inFailure != "" && (len(failures) != 1 || !strings.Contains(failures[0], tc.inFailure)):
				t.Fatalf("failures %q, want one containing %q", failures, tc.inFailure)
			}
			if rewritten := after != tc.doc; rewritten != tc.rewritten {
				t.Fatalf("file rewritten = %v, want %v", rewritten, tc.rewritten)
			}
		})
	}
}
