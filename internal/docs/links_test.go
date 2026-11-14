// Package docs holds the checks that keep the repository's Markdown true to its own tree: every
// relative link and #anchor resolves, and every page byward.dev links to exists. They read whatever
// *.md files the tree has, so a PR that moves, renames or deletes a page is checked as it stands.
package docs

import (
	"bufio"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// skippedDirs are never walked: version control, build output, and agent worktrees, which are
// whole other checkouts.
var skippedDirs = []string{".git", ".claude", "build", "dist", "node_modules"}

// repoRoot is the directory that holds go.mod, found upward from the test's directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// markdownFiles lists every *.md file under root, as slash paths relative to it.
func markdownFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root && slices.Contains(skippedDirs, d.Name()) {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

var (
	fence      = regexp.MustCompile("^\\s*(```|~~~)")
	codeSpan   = regexp.MustCompile("`+[^`]*`+")
	comment    = regexp.MustCompile(`(?s)<!--.*?-->`)
	inlineLink = regexp.MustCompile(`\]\(([^)\s]*)(?:\s+"[^"]*")?\)`)
	heading    = regexp.MustCompile(`^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$`)
	headingRef = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	htmlTag    = regexp.MustCompile(`<[^>]+>`)
	lineAnchor = regexp.MustCompile(`^L\d+(-L\d+)?$`)
)

// page is what one Markdown file offers to links: its prose lines (outside code blocks and
// comments) and the anchors its headings get on GitHub.
type page struct {
	lines   []string
	anchors map[string]bool
}

func readPage(path string) (page, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a file the walk found in the repository
	if err != nil {
		return page{}, err
	}
	p := page{anchors: map[string]bool{}}
	seen := map[string]int{}
	inFence := false
	sc := bufio.NewScanner(strings.NewReader(comment.ReplaceAllStringFunc(string(b), blankKeepingLines)))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if fence.MatchString(line) {
			inFence = !inFence
			p.lines = append(p.lines, "")
			continue
		}
		if inFence {
			p.lines = append(p.lines, "")
			continue
		}
		p.lines = append(p.lines, line)
		if m := heading.FindStringSubmatch(line); m != nil {
			p.anchors[uniqueAnchor(anchorOf(m[2]), seen)] = true
		}
	}
	return p, sc.Err()
}

// blankKeepingLines replaces an HTML comment with its newlines only, so line numbers still match.
func blankKeepingLines(s string) string { return strings.Repeat("\n", strings.Count(s, "\n")) }

// anchorOf is the anchor GitHub gives a heading: the rendered text (link text kept, code kept
// without its backticks, emphasis and HTML dropped), lowercased, without punctuation and
// symbols, each space a hyphen (github-slugger, which GitHub's anchors follow).
func anchorOf(text string) string {
	text = headingRef.ReplaceAllString(text, "$1")
	text = htmlTag.ReplaceAllString(text, "")
	text = strings.NewReplacer("`", "", "*", "").Replace(text)
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// uniqueAnchor suffixes a repeated anchor -1, -2 and so on, as GitHub does.
func uniqueAnchor(a string, seen map[string]int) string {
	result := a
	for {
		if _, taken := seen[result]; !taken {
			break
		}
		seen[a]++
		result = fmt.Sprintf("%s-%d", a, seen[a])
	}
	seen[result] = 0
	return result
}

// link is one relative link found in a page.
type link struct {
	line   int
	target string
}

// relativeLinks lists the page's inline links that point into the repository: no scheme, not a
// protocol-relative URL.
func relativeLinks(p page) []link {
	var links []link
	for i, line := range p.lines {
		for _, m := range inlineLink.FindAllStringSubmatch(codeSpan.ReplaceAllString(line, ""), -1) {
			target := m[1]
			if target == "" || strings.HasPrefix(target, "//") {
				continue
			}
			if u, err := url.Parse(target); err == nil && u.Scheme != "" {
				continue
			}
			links = append(links, link{line: i + 1, target: target})
		}
	}
	return links
}

// resolve checks one link from file (a slash path relative to root) and says what is wrong, or "".
// A leading / is the repository root, as on GitHub.
func resolve(root, file, target string, pages func(string) (page, error)) string {
	pathPart, fragment, _ := strings.Cut(target, "#")
	pathPart, err := url.PathUnescape(pathPart)
	if err != nil {
		return "the path is not valid URL escaping"
	}
	dest := file
	switch {
	case pathPart == "":
	case strings.HasPrefix(pathPart, "/"):
		dest = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(pathPart, "/")))
	default:
		dest = filepath.ToSlash(filepath.Join(filepath.Dir(file), pathPart))
	}
	if dest == ".." || strings.HasPrefix(dest, "../") {
		return "it points outside the repository"
	}
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(dest)))
	if err != nil {
		return "no such file or directory: " + dest
	}
	if fragment == "" || fi.IsDir() {
		return ""
	}
	if !strings.HasSuffix(dest, ".md") {
		if lineAnchor.MatchString(fragment) {
			return ""
		}
		return "#" + fragment + " on a file that is not Markdown: only line anchors (#L12, #L12-L20) are checked there"
	}
	p, err := pages(dest)
	if err != nil {
		return err.Error()
	}
	if !p.anchors[fragment] {
		return fmt.Sprintf("no heading in %s has the anchor #%s", dest, fragment)
	}
	return ""
}

// Every relative link and #anchor in the repository's Markdown resolves in this tree, as GitHub
// would resolve it. External URLs are not fetched.
func TestEveryRelativeLinkInTheMarkdownResolves(t *testing.T) {
	root := repoRoot(t)
	cache := map[string]page{}
	pages := func(rel string) (page, error) {
		if p, ok := cache[rel]; ok {
			return p, nil
		}
		p, err := readPage(filepath.Join(root, filepath.FromSlash(rel)))
		if err == nil {
			cache[rel] = p
		}
		return p, err
	}
	files := markdownFiles(t, root)
	if len(files) == 0 {
		t.Fatal("no Markdown files found")
	}
	for _, file := range files {
		p, err := pages(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range relativeLinks(p) {
			if problem := resolve(root, file, l.target, pages); problem != "" {
				t.Errorf("%s:%d: (%s): %s", file, l.line, l.target, problem)
			}
		}
	}
}

// siteLinks is the file listing every link from byward.dev into this repository.
const siteLinks = "site-links.txt"

// Every page byward.dev links to exists in this tree, so a PR that moves one without leaving a
// pointer at the old path fails here. The list is kept in step with the site by a check in the
// site's repository (site-links.txt says how).
func TestEveryPageTheWebsiteLinksToExists(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(siteLinks)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "https://github.com/byward-dev/byward/"
	n := 0
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		rest, ok := strings.CutPrefix(line, prefix)
		kind, path, found := strings.Cut(rest, "/main/")
		if !ok || !found || (kind != "blob" && kind != "tree") || path == "" {
			t.Errorf("%s:%d: %q is not a %sblob/main/<path> or tree/main/<path> link", siteLinks, i+1, line, prefix)
			continue
		}
		fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
		switch {
		case err != nil:
			t.Errorf("%s:%d: byward.dev links to %s, which is not in this tree: keep the file, or leave a page at the old path that links to the new one", siteLinks, i+1, path)
		case kind == "blob" && fi.IsDir(), kind == "tree" && !fi.IsDir():
			t.Errorf("%s:%d: %s is a %s link, but the path is %s", siteLinks, i+1, path, kind, map[bool]string{true: "a directory", false: "a file"}[fi.IsDir()])
		}
	}
	if n == 0 {
		t.Fatalf("%s lists no links", siteLinks)
	}
}
