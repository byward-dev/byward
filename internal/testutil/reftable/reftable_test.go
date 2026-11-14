package reftable

import (
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

Prose after.

## Other

| Thing | Meaning |
|---|---|
| ` + "`a`" + ` | not this table |
`

func row(key string, old []string) []string {
	meaning := Todo
	if old != nil {
		meaning = old[2]
	}
	return []string{"`" + key + "`", "new", meaning}
}

// The table gets one row per key, in the keys' order: hand-written cells are kept for known keys,
// a new key gets Todo, a key the code no longer has is dropped, and nothing else on the page moves.
func TestRenderRebuildsOnlyTheTable(t *testing.T) {
	got, err := Render(page, "## Things", 0, []string{"a", "b", "c"}, row)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(page, "| `b` | old | written for b |\n| `gone` | old | written for gone |\n| `a` | old | written for a |",
		"| `a` | new | written for a |\n| `b` | new | written for b |\n| `c` | new | "+Todo+" |", 1)
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if u := Undescribed(got, "## Things", 0); !slices.Equal(u, []string{"c"}) {
		t.Errorf("undescribed %v, want [c]", u)
	}
	if u := Undescribed(page, "## Things", 0); u != nil {
		t.Errorf("undescribed in the page as written %v, want none", u)
	}
}

// A missing heading, or a heading with no table before the next heading, is an error.
func TestRenderNeedsATableUnderTheHeading(t *testing.T) {
	for _, tc := range []struct{ doc, heading, inErr string }{
		{page, "## Missing", `no line "## Missing"`},
		{"## Empty\n\nprose\n\n## Next\n\n| a |\n|---|\n", "## Empty", `no table under "## Empty"`},
		{"## Header only\n\n| a |\n", "## Header only", `no table under "## Header only"`},
	} {
		_, err := Render(tc.doc, tc.heading, 0, nil, row)
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
		{"| a |  |", []string{"a", ""}},
	} {
		if got := Cells(tc.row); !slices.Equal(got, tc.want) {
			t.Errorf("Cells(%q) = %q, want %q", tc.row, got, tc.want)
		}
	}
}
