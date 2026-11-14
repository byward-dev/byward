// Package reftable keeps a table in a reference page in step with names from the code, as the
// settings reference is (BYWARD_UPDATE_REFERENCE=1 rewrites it, the test fails on drift). Only
// the table is generated: its key column comes from the code, the other cells are kept as written,
// and the prose around it is not touched.
package reftable

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Todo fills the hand-written cells of a row for a key the table did not have, until someone
// writes them; a table holding it fails.
const Todo = "TODO: describe"

// Table is one generated table: the first table after the line Heading in the Markdown file at
// Path, keyed by its KeyCol cell without backticks. Package is the go test argument that
// regenerates it, for the failure message.
type Table struct {
	Path, Heading string
	KeyCol        int
	Package       string
}

// Sync checks the table: one row per key, in order, each built by row from its key and the cells
// of the table's row for that key (nil when there is none). With BYWARD_UPDATE_REFERENCE=1 it first
// rewrites the file. A row still holding Todo fails.
func (table Table) Sync(t testing.TB, keys []string, row func(key string, old []string) []string) {
	t.Helper()
	b, err := os.ReadFile(table.Path) //nolint:gosec // G304: a reference page the calling test names
	if err != nil {
		t.Fatal(err)
	}
	want, err := render(string(b), table.Heading, table.KeyCol, keys, row)
	if err != nil {
		t.Fatalf("%s: %v", table.Path, err)
	}
	if os.Getenv("BYWARD_UPDATE_REFERENCE") == "1" {
		// Path is the calling test's constant, not input.
		if err := os.WriteFile(table.Path, []byte(want), 0o600); err != nil { //nolint:gosec // G703: see above
			t.Fatal(err)
		}
		b = []byte(want)
	}
	if string(b) != want {
		t.Fatalf("the table under %q in %s is stale; run BYWARD_UPDATE_REFERENCE=1 go test %s, then write any %q cells", table.Heading, table.Path, table.Package, Todo)
	}
	for _, k := range undescribed(want, table.Heading, table.KeyCol) {
		t.Errorf("%s: describe %s in the table under %q (its row says %q)", table.Path, k, table.Heading, Todo)
	}
}

// render is doc with the table that follows the line heading rebuilt: one row per key, in order.
// The header and everything outside the table stay as they are.
func render(doc, heading string, keyCol int, keys []string, row func(key string, old []string) []string) (string, error) {
	lines := strings.Split(doc, "\n")
	start, end, err := tableAfter(lines, heading)
	if err != nil {
		return "", err
	}
	old := map[string][]string{}
	for _, line := range lines[start+2 : end] {
		if c := cells(line); keyCol < len(c) {
			old[strings.Trim(c[keyCol], "`")] = c
		}
	}
	out := append([]string{}, lines[:start+2]...)
	for _, k := range keys {
		out = append(out, "| "+strings.Join(row(k, old[k]), " | ")+" |")
	}
	return strings.Join(append(out, lines[end:]...), "\n"), nil
}

// undescribed lists the keys of the rows under heading that still hold Todo.
func undescribed(doc, heading string, keyCol int) []string {
	lines := strings.Split(doc, "\n")
	start, end, err := tableAfter(lines, heading)
	if err != nil {
		return nil
	}
	var keys []string
	for _, line := range lines[start+2 : end] {
		if c := cells(line); strings.Contains(line, Todo) && keyCol < len(c) {
			keys = append(keys, strings.Trim(c[keyCol], "`"))
		}
	}
	return keys
}

// tableAfter finds the first table after the first line heading, before the next heading: the
// index of its header line and of the line after its last row.
func tableAfter(lines []string, heading string) (start, end int, err error) {
	h := -1
	for i, l := range lines {
		if l == heading {
			h = i
			break
		}
	}
	if h < 0 {
		return 0, 0, fmt.Errorf("no line %q", heading)
	}
	start = -1
	for i := h + 1; i < len(lines) && !strings.HasPrefix(lines[i], "#"); i++ {
		if strings.HasPrefix(lines[i], "|") {
			start = i
			break
		}
	}
	if start < 0 || start+1 >= len(lines) || !strings.HasPrefix(lines[start+1], "|") {
		return 0, 0, fmt.Errorf("no table under %q", heading)
	}
	end = start + 2
	for end < len(lines) && strings.HasPrefix(lines[end], "|") {
		end++
	}
	return start, end, nil
}

// cells splits a table row into its trimmed cells. A | inside backticks does not split.
func cells(row string) []string {
	row = strings.TrimSpace(row)
	row = strings.TrimSuffix(strings.TrimPrefix(row, "|"), "|")
	var out []string
	var cur strings.Builder
	inCode := false
	for _, r := range row {
		switch {
		case r == '`':
			inCode = !inCode
		case r == '|' && !inCode:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	return append(out, strings.TrimSpace(cur.String()))
}
