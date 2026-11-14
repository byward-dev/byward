// Package doclinks holds the checks that keep the repository's Markdown true to its own tree: every
// relative link and #anchor resolves, and every page byward.dev links to exists. They read whatever
// *.md files the tree has, so a PR that moves, renames or deletes a page is checked as it stands.
//
// What is checked: inline links and images ([text](dest), with an optional "title", 'title' or
// (title), and <dest> in angle brackets) outside fenced code, code spans and HTML comments; their
// #anchors against ATX headings (# Heading), as GitHub names them. Not checked: external URLs,
// reference-style links ([text][ref]), HTML href/src, anchors from setext headings or <a id>, and
// prose after an HTML comment opened inside code (<!-- in a fence) until its -->; the docs use none
// of these. Untracked files are read too, and path case is only enforced on a
// case-sensitive file system (CI's Linux, not macOS's default).
package doclinks

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
func markdownFiles(root string) ([]string, error) {
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
	return files, err
}

var (
	openingFence = regexp.MustCompile("^ {0,3}(?:(`{3,})[^`]*$|(~{3,}))") // a ``` fence's info string has no backtick
	htmlComment  = regexp.MustCompile(`(?s)<!--.*?-->`)
	inlineLink   = regexp.MustCompile(`\]\((?:<([^>]*)>|([^)\s]*))(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\)`)
	heading      = regexp.MustCompile(`^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$`)
	linkWithText = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	htmlTag      = regexp.MustCompile(`<[^>]+>`)
	lineAnchor   = regexp.MustCompile(`^L\d+(-L\d+)?$`)
)

// page is what one Markdown file offers to links: its prose lines (code blocks and comments
// blanked, so line numbers still match) and the anchors its headings get on GitHub.
type page struct {
	lines   []string
	anchors map[string]bool
}

func readPage(path string) (page, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a Markdown file of the repository, or a test's own
	if err != nil {
		return page{}, err
	}
	p := page{anchors: map[string]bool{}}
	seen := map[string]int{}
	fence := "" // the opening fence while inside a fenced code block
	sc := bufio.NewScanner(strings.NewReader(htmlComment.ReplaceAllStringFunc(string(b), blankKeepingLines)))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case fence != "":
			if closesFence(line, fence) {
				fence = ""
			}
			line = ""
		case openingFence.MatchString(line):
			m := openingFence.FindStringSubmatch(line)
			fence = m[1] + m[2]
			line = ""
		}
		p.lines = append(p.lines, line)
		if m := heading.FindStringSubmatch(line); m != nil {
			p.anchors[uniqueAnchor(anchorOf(m[2]), seen)] = true
		}
	}
	return p, sc.Err()
}

// closesFence reports whether line closes a block opened by fence: the same character, at least
// as many, up to three spaces before and nothing but spaces after (CommonMark, as GitHub renders).
func closesFence(line, fence string) bool {
	indent := leadingRun(line, " ")
	if indent > 3 {
		return false
	}
	run := leadingRun(line[indent:], fence[:1])
	return run >= len(fence) && strings.TrimSpace(line[indent+run:]) == ""
}

// leadingRun is the length of the run of chars that s starts with.
func leadingRun(s, chars string) int { return len(s) - len(strings.TrimLeft(s, chars)) }

// blankKeepingLines replaces an HTML comment with its newlines only, so line numbers still match.
func blankKeepingLines(s string) string { return strings.Repeat("\n", strings.Count(s, "\n")) }

// withoutCodeSpans drops the code spans of a line: a run of backticks up to the next run of the
// same length. A run that is never closed is literal text.
func withoutCodeSpans(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			b.WriteByte(line[i])
			i++
			continue
		}
		n := leadingRun(line[i:], "`")
		end := closingRun(line, i+n, n)
		if end < 0 {
			b.WriteString(line[i : i+n])
			i += n
			continue
		}
		i = end + n
	}
	return b.String()
}

// closingRun is the index of the next run of exactly n backticks at or after from, or -1.
func closingRun(line string, from, n int) int {
	for j := from; j < len(line); {
		if line[j] != '`' {
			j++
			continue
		}
		m := leadingRun(line[j:], "`")
		if m == n {
			return j
		}
		j += m
	}
	return -1
}

// anchorOf is the anchor GitHub gives a heading (github-slugger, which GitHub's anchors follow):
// the rendered text (link text kept, code kept without its backticks, * emphasis and HTML tags
// dropped), lowercased, without punctuation and symbols, each space a hyphen. _ emphasis is not
// dropped: an underscore is kept, as in snake_case.
func anchorOf(text string) string {
	text = linkWithText.ReplaceAllString(text, "$1")
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
		for _, m := range inlineLink.FindAllStringSubmatch(withoutCodeSpans(line), -1) {
			target := m[1] + m[2]
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

// linkProblem checks one link from file (a slash path relative to root) and says what is wrong, or
// "". A leading / is the repository root, as on GitHub; a ?query is ignored.
func linkProblem(root, file, target string, pageAt func(string) (page, error)) string {
	pathPart, fragment, _ := strings.Cut(target, "#")
	pathPart, _, _ = strings.Cut(pathPart, "?")
	pathPart, err := url.PathUnescape(pathPart)
	if err != nil {
		return "the path is not valid URL escaping"
	}
	if fragment, err = url.PathUnescape(fragment); err != nil {
		return "the #anchor is not valid URL escaping"
	}
	dest := file
	switch {
	case pathPart == "":
	case strings.HasPrefix(pathPart, "/"):
		dest = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(pathPart, "/")))
	default:
		dest = filepath.ToSlash(filepath.Join(filepath.Dir(file), pathPart))
	}
	if !filepath.IsLocal(filepath.FromSlash(dest)) {
		return "it points outside the repository"
	}
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(dest)))
	if err != nil {
		return "no such file or directory: " + dest + "; fix the link, or restore the file"
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
	p, err := pageAt(dest)
	if err != nil {
		return err.Error()
	}
	if !p.anchors[fragment] {
		return fmt.Sprintf("no heading in %s has the anchor #%s; fix the link, or restore the heading", dest, fragment)
	}
	return ""
}

// Every relative link and #anchor in the repository's Markdown resolves in this tree, as GitHub
// would resolve it. External URLs are not fetched; the package comment lists the link forms read.
func TestEveryRelativeLinkInTheMarkdownResolves(t *testing.T) {
	root := repoRoot(t)
	cache := map[string]page{}
	pageAt := func(rel string) (page, error) {
		if p, ok := cache[rel]; ok {
			return p, nil
		}
		p, err := readPage(filepath.Join(root, filepath.FromSlash(rel)))
		if err == nil {
			cache[rel] = p
		}
		return p, err
	}
	files, err := markdownFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no Markdown files found")
	}
	for _, file := range files {
		p, err := pageAt(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range relativeLinks(p) {
			if problem := linkProblem(root, file, l.target, pageAt); problem != "" {
				t.Errorf("%s:%d: link %s: %s", file, l.line, l.target, problem)
			}
		}
	}
}
