// Package fixtures holds the repository-wide fixture privacy test (ADR-0024 §13): this repository
// is public, so no real tenant, user or project identifier may reach it, and test data uses
// generated GUIDs and reserved example domains only.
package fixtures

import (
	"bytes"
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// forbiddenEnv names the CI secret listing identifiers and names that must never appear in the
// repository, one per line. It is never printed; findings name only the file and line.
const forbiddenEnv = "BYWARD_FORBIDDEN_IDENTIFIERS"

var emailShape = regexp.MustCompile(`[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})`)

// exampleDomain reports whether d is reserved for examples (RFC 2606, RFC 6761): example.com,
// example.net, example.org and their subdomains, and any name under .example.
func exampleDomain(d string) bool {
	d = strings.ToLower(d)
	for _, base := range []string{"example.com", "example.net", "example.org"} {
		if d == base || strings.HasSuffix(d, "."+base) {
			return true
		}
	}
	return strings.HasSuffix(d, ".example")
}

// finding is a place a rule matched: never the matched text itself.
type finding struct {
	file string
	line int
	kind string
}

func (f finding) String() string { return fmt.Sprintf("%s:%d: %s", f.file, f.line, f.kind) }

const (
	kindForbidden = "an identifier or name listed in " + forbiddenEnv
	kindEmail     = "an email address outside the reserved example domains"
)

// fixture reports whether a tracked file is test data whose every line the email rule reads:
// anything under a testdata directory, and golden files.
func fixture(rel string) bool {
	slash := filepath.ToSlash(rel)
	return strings.HasPrefix(slash, "testdata/") || strings.Contains(slash, "/testdata/") || strings.Contains(filepath.Base(rel), ".golden")
}

// scan applies the rules to the files (paths relative to root): the forbidden list to every
// file, the email rule to fixtures and to the string literals of Go test files.
func scan(root string, files []string, forbidden []string) ([]finding, error) {
	var out []finding
	for _, rel := range files {
		src, err := committed(filepath.Join(root, rel))
		if err != nil {
			if os.IsNotExist(err) {
				continue // deleted in the working tree, still in the index
			}
			return nil, err
		}
		out = append(out, forbiddenHits(rel, src, forbidden)...)
		switch {
		case fixture(rel):
			for i, line := range strings.Split(string(src), "\n") {
				if hasRealEmail(line) {
					out = append(out, finding{rel, i + 1, kindEmail})
				}
			}
		case strings.HasSuffix(rel, "_test.go"):
			out = append(out, testLiteralEmails(rel, src)...)
		}
	}
	return out, nil
}

// committed is what git would commit for path: a regular file's content, or a symlink's target
// path (never the target's content, which git does not commit). Anything else is an error.
func committed(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return nil, err
	case fi.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		return []byte(target), err
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return os.ReadFile(path) //nolint:gosec // G304: this repository's own files
}

// forbiddenHits reports each place in src where an entry of forbidden (lower case) appears, in
// any case.
func forbiddenHits(rel string, src []byte, forbidden []string) []finding {
	var out []finding
	lower := bytes.ToLower(src)
	for _, f := range forbidden {
		for at := 0; ; {
			i := bytes.Index(lower[at:], []byte(f))
			if i < 0 {
				break
			}
			// Counted in lower: ToLower can change byte lengths (invalid UTF-8, some runes), never
			// newlines.
			out = append(out, finding{rel, 1 + bytes.Count(lower[:at+i], []byte("\n")), kindForbidden})
			at += i + len(f)
		}
	}
	return out
}

// hasRealEmail reports whether s holds an email-shaped string whose domain is not reserved for
// examples.
func hasRealEmail(s string) bool {
	for _, m := range emailShape.FindAllStringSubmatch(s, -1) {
		if !exampleDomain(m[1]) {
			return true
		}
	}
	return false
}

// testLiteralEmails reads the string literals of a Go test file (comments and code are not test
// data) and reports each line where one holds a real-looking email address.
func testLiteralEmails(rel string, src []byte) []finding {
	var out []finding
	fset := token.NewFileSet()
	file := fset.AddFile(rel, -1, len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, 0)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}
		if tok != token.STRING {
			continue
		}
		text, err := strconv.Unquote(lit)
		if err != nil {
			text = lit
		}
		start := fset.Position(pos).Line
		for i, line := range strings.Split(text, "\n") {
			if !hasRealEmail(line) {
				continue
			}
			// A raw literal spans source lines; an interpreted one's \n escapes stay on its line.
			at := start
			if lit[0] == '`' {
				at += i
			}
			out = append(out, finding{rel, at, kindEmail})
		}
	}
}

// forbiddenList reads the CI secret: one entry per line, matched case-insensitively.
func forbiddenList(raw string) []string {
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// checkoutFiles lists what git would commit: tracked files and untracked ones it does not ignore,
// so a file is checked before it is added (and its content keys Go's test cache). A nested
// repository, such as a worktree under .claude/worktrees, is listed as one "dir/" entry and left
// out. A missing git is an exec.ErrNotFound; any other failure is an error the check must not
// pass over.
func checkoutFiles(root string) ([]string, error) {
	b, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output() //nolint:gosec // G204: root is this repository, fixed by the test
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var out []string
	for _, f := range strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00") {
		if f != "" && !strings.HasSuffix(f, "/") {
			out = append(out, f)
		}
	}
	return out, nil
}

// statInputs stats git's index and every directory that holds a listed file. Go's test cache keys
// a result on the files the test opens or stats, so a file created or added since the last run
// re-runs the check instead of returning a cached pass. The directories matter in a git worktree,
// whose index sits outside this module, where the cache does not look.
func statInputs(root string, files []string) error {
	out, err := exec.Command("git", "-C", root, "rev-parse", "--git-path", "index").Output() //nolint:gosec // G204: as above
	if err != nil {
		return fmt.Errorf("git rev-parse: %w", err)
	}
	idx := strings.TrimSpace(string(out))
	if !filepath.IsAbs(idx) { // relative to root, which git -C ran in
		idx = filepath.Join(root, idx)
	}
	if _, err := os.Stat(idx); err != nil {
		return err
	}
	dirs := map[string]bool{".": true}
	for _, f := range files {
		for d := filepath.Dir(f); d != "." && !dirs[d]; d = filepath.Dir(d) {
			dirs[d] = true
		}
	}
	for d := range dirs {
		if _, err := os.Stat(filepath.Join(root, d)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// The repository holds none of the identifiers and names the CI secret lists, in any file git
// would commit, and its test data no real email address (ADR-0024 §13). Without the secret (forks, local runs) only the
// email rule runs.
func TestTheRepositoryHoldsNoForbiddenIdentifiersAndItsTestDataNoRealEmails(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("not at the repository root: %v", err)
	}
	forbidden := forbiddenList(os.Getenv(forbiddenEnv))
	if len(forbidden) == 0 {
		t.Logf("%s is not set: the identifier check is skipped, only email addresses are checked", forbiddenEnv)
	}
	files, err := checkoutFiles(root)
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("no git: the privacy check needs the repository's file list")
	}
	if err != nil {
		t.Fatal(err) // never pass by checking nothing
	}
	if err := statInputs(root, files); err != nil {
		t.Fatalf("the check's inputs: %v", err)
	}
	if !slices.Contains(files, "internal/testutil/fixtures/privacy_test.go") {
		t.Fatalf("git listed %d files, not this one: the scan would check the wrong tree", len(files))
	}
	found, err := scan(root, files, forbidden)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Error(f)
	}
}
