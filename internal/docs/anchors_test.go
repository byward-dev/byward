package docs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A heading's anchor is GitHub's: lowercase, punctuation and symbols dropped, spaces as hyphens,
// link text and code kept.
func TestAHeadingsAnchorIsGitHubs(t *testing.T) {
	for _, tc := range []struct{ heading, want string }{
		{"Proxy actions", "proxy-actions"},
		{"`byward store new-epoch`", "byward-store-new-epoch"},
		{"1. Create the database and a role", "1-create-the-database-and-a-role"},
		{"Direct competitors — auth proxies with an AS facade", "direct-competitors--auth-proxies-with-an-as-facade"},
		{"What's shared (and what isn't)", "whats-shared-and-what-isnt"},
		{"snake_case and kebab-case", "snake_case-and-kebab-case"},
		{"See [the ADR](adr/0007.md) here", "see-the-adr-here"},
		{"**Bold** heading", "bold-heading"},
		{"Café über", "café-über"},
		{"Step 2, helper 27: CI checks", "step-2-helper-27-ci-checks"},
	} {
		if got := anchorOf(tc.heading); got != tc.want {
			t.Errorf("anchorOf(%q) = %q, want %q", tc.heading, got, tc.want)
		}
	}
}

// A repeated heading gets -1, -2 and so on, and a heading that already reads like a suffixed one
// is suffixed again, as GitHub does.
func TestARepeatedHeadingIsNumbered(t *testing.T) {
	seen := map[string]int{}
	var got []string
	for _, a := range []string{"foo", "foo", "bar", "foo", "foo-1"} {
		got = append(got, uniqueAnchor(a, seen))
	}
	want := []string{"foo", "foo-1", "bar", "foo-2", "foo-1-1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// writeTree writes files (slash paths) under a new directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Only links in prose count: not in fenced code (indented or not), code spans or HTML comments,
// and not external URLs.
func TestOnlyRelativeLinksInProseAreChecked(t *testing.T) {
	root := writeTree(t, map[string]string{"a.md": strings.Join([]string{
		"# Title",
		"[ok](b.md#part) and [same](#title) and ![img](pic.png \"a title\")",
		"`[code](no.md)` and [web](https://example.com/x.md) and [mail](mailto:a@example.com) and [proto](//example.com)",
		"```sh",
		"[fenced](no.md)",
		"```",
		"   ~~~",
		"[tilde](no.md)",
		"   ~~~",
		"<!-- [commented](no.md)",
		"-->",
		"[last](c/)",
	}, "\n")})
	p, err := readPage(filepath.Join(root, "a.md"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range relativeLinks(p) {
		got = append(got, fmt.Sprintf("%s@%d", l.target, l.line))
	}
	want := []string{"b.md#part@2", "#title@2", "pic.png@2", "c/@12"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A link resolves as on GitHub: relative to its file, / from the repository root; a missing file,
// a missing heading or a path outside the repository is reported.
func TestALinkResolvesAsOnGitHub(t *testing.T) {
	root := writeTree(t, map[string]string{
		"README.md":         "# Top\n## Setup\n## Setup\n",
		"docs/guide.md":     "# Guide\n",
		"docs/sub/note.md":  "# Note\n",
		"internal/x/x.go":   "package x\n",
		"docs/img/logo.svg": "<svg/>",
	})
	pages := func(rel string) (page, error) { return readPage(filepath.Join(root, filepath.FromSlash(rel))) }
	for _, tc := range []struct{ file, target, inProblem string }{
		{"docs/guide.md", "../README.md#setup-1", ""},
		{"docs/guide.md", "/README.md#top", ""},
		{"docs/guide.md", "#guide", ""},
		{"docs/guide.md", "sub/note.md", ""},
		{"docs/guide.md", "sub/", ""},
		{"docs/guide.md", "img/logo.svg", ""},
		{"docs/guide.md", "../internal/x/x.go#L1-L2", ""},
		{"docs/guide.md", "../README.md#setup-2", "no heading in README.md has the anchor #setup-2"},
		{"docs/guide.md", "#nowhere", "no heading in docs/guide.md has the anchor #nowhere"},
		{"docs/guide.md", "missing.md", "no such file or directory: docs/missing.md"},
		{"docs/guide.md", "../../outside.md", "outside the repository"},
		{"docs/guide.md", "../internal/x/x.go#func", "only line anchors"},
		{"docs/guide.md", "bad%zz.md", "not valid URL escaping"},
	} {
		problem := resolve(root, tc.file, tc.target, pages)
		if tc.inProblem == "" && problem != "" || tc.inProblem != "" && !strings.Contains(problem, tc.inProblem) {
			t.Errorf("%s → %s: problem %q, want %q", tc.file, tc.target, problem, tc.inProblem)
		}
	}
}
