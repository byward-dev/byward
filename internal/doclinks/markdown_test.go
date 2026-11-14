package doclinks

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A heading's anchor is GitHub's: lowercase, punctuation and symbols dropped, spaces as hyphens,
// link text and code kept.
func TestAHeadingGetsGitHubsAnchor(t *testing.T) {
	for _, tc := range []struct{ heading, want string }{
		{"Proxy actions", "proxy-actions"},
		{"`byward store new-epoch`", "byward-store-new-epoch"},
		{"1. Create the database and a role", "1-create-the-database-and-a-role"},
		{"Direct competitors — auth proxies with an AS facade", "direct-competitors--auth-proxies-with-an-as-facade"},
		{"What's shared (and what isn't)", "whats-shared-and-what-isnt"},
		{"snake_case and kebab-case", "snake_case-and-kebab-case"},
		{"See [the ADR](adr/0007.md) here", "see-the-adr-here"},
		{"**Bold** heading", "bold-heading"},
		{"A <code>b</code>", "a-b"},
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
	if want := []string{"foo", "foo-1", "bar", "foo-2", "foo-1-1"}; !slices.Equal(got, want) {
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

// Only ATX headings in prose give anchors: not one in a fence, an indented one, one with seven #,
// and closing #s are not part of the text.
func TestOnlyHeadingsInProseGiveAnchors(t *testing.T) {
	root := writeTree(t, map[string]string{"a.md": strings.Join([]string{
		"## Setup ##",
		"####### Seven",
		"    # Indented code",
		"```",
		"# Not a heading",
		"```",
		"# Last",
	}, "\n")})
	p, err := readPage(filepath.Join(root, "a.md"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for a := range p.anchors {
		got = append(got, a)
	}
	slices.Sort(got)
	if want := []string{"last", "setup"}; !slices.Equal(got, want) {
		t.Fatalf("anchors %v, want %v", got, want)
	}
}

// Only links in prose count: not in fenced code (even an indented fence, or one holding a shorter
// or other fence), code spans or HTML comments, and not external URLs. Titles and <dest> are read.
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
		"````md",
		"```",
		"[nested](no.md)",
		"````",
		"```",
		"~~~",
		"[other fence](no.md)",
		"```",
		"``a ` b`` then [after span](d.md) and [single](e.md 'title') and [paren](f.md (title)) and [angle](<g h.md>)",
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
	want := []string{"b.md#part@2", "#title@2", "pic.png@2", "d.md@20", "e.md@20", "f.md@20", "g h.md@20", "c/@21"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A link resolves as on GitHub: relative to its file, / from the repository root; a missing file,
// a missing heading or a path outside the repository is reported.
func TestALinkResolvesAsOnGitHub(t *testing.T) {
	root := writeTree(t, map[string]string{
		"README.md":         "# Top\n## Setup\n## Setup\n## Café\n",
		"docs/guide.md":     "# Guide\n",
		"docs/sub/note.md":  "# Note\n",
		"internal/x/x.go":   "package x\n",
		"docs/img/logo.svg": "<svg/>",
	})
	pageAt := func(rel string) (page, error) { return readPage(filepath.Join(root, filepath.FromSlash(rel))) }
	for _, tc := range []struct{ file, target, inProblem string }{
		{"docs/guide.md", "../README.md#setup-1", ""},
		{"docs/guide.md", "/README.md#top", ""},
		{"docs/guide.md", "../README.md#caf%C3%A9", ""},
		{"docs/guide.md", "../README.md?plain=1#top", ""},
		{"docs/guide.md", "#guide", ""},
		{"docs/guide.md", "sub/note.md", ""},
		{"docs/guide.md", "sub/", ""},
		{"docs/guide.md", "sub/#anything", ""},
		{"docs/guide.md", "img/logo.svg", ""},
		{"docs/guide.md", "../internal/x/x.go#L1-L2", ""},
		{"docs/guide.md", "../README.md#setup-2", "no heading in README.md has the anchor #setup-2"},
		{"docs/guide.md", "#nowhere", "no heading in docs/guide.md has the anchor #nowhere"},
		{"docs/guide.md", "missing.md", "no such file or directory: docs/missing.md"},
		{"docs/guide.md", "../../outside.md", "outside the repository"},
		{"README.md", "..", "outside the repository"},
		{"docs/guide.md", "../internal/x/x.go#func", "only line anchors"},
		{"docs/guide.md", "../internal/x/x.go#L1foo", "only line anchors"},
		{"docs/guide.md", "bad%zz.md", "not valid URL escaping"},
	} {
		problem := linkProblem(root, tc.file, tc.target, pageAt)
		if tc.inProblem == "" {
			if problem != "" {
				t.Errorf("%s → %s: problem %q, want none", tc.file, tc.target, problem)
			}
			continue
		}
		if !strings.Contains(problem, tc.inProblem) {
			t.Errorf("%s → %s: problem %q, want one containing %q", tc.file, tc.target, problem, tc.inProblem)
		}
	}
}

// The walk reads every *.md file but none in build output or agent worktrees.
func TestTheWalkSkipsBuildOutputAndWorktrees(t *testing.T) {
	root := writeTree(t, map[string]string{".claude/worktrees/x/a.md": "", "build/b.md": "", "docs/c.md": "", ".github/d.md": "", "e.txt": ""})
	got, err := markdownFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{".github/d.md", "docs/c.md"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A site link must be a blob link to a file or a tree link to a directory that exists in the tree.
func TestASiteLinkNamesAPageInTheTree(t *testing.T) {
	root := writeTree(t, map[string]string{"docs/a.md": ""})
	for _, tc := range []struct{ line, inProblem string }{
		{"", ""},
		{"# a comment", ""},
		{repoURL + "blob/main/docs/a.md", ""},
		{repoURL + "tree/main/docs", ""},
		{repoURL + "blob/main/docs", "is a directory"},
		{repoURL + "tree/main/docs/a.md", "is a file"},
		{repoURL + "blob/main/docs/gone.md", "which is not in this tree"},
		{repoURL + "blob/main/docs/a.md#part", "without its #anchor"},
		{repoURL + "raw/main/docs/a.md", "is not a"},
		{repoURL + "blob/v1/docs/a.md", "is not a"},
		{repoURL + "blob/main/", "is not a"},
		{"https://example.com/docs/a.md", "is not a"},
		{repoURL + "blob/main/../x.md", "outside the repository"},
	} {
		problem := siteLinkProblem(root, tc.line)
		if tc.inProblem == "" {
			if problem != "" {
				t.Errorf("%q: problem %q, want none", tc.line, problem)
			}
			continue
		}
		if !strings.Contains(problem, tc.inProblem) {
			t.Errorf("%q: problem %q, want one containing %q", tc.line, problem, tc.inProblem)
		}
	}
}
