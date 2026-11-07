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
		src, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // G304: this repository's own files
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

// trackedFiles lists the repository's tracked files, as git does. It skips the test only where
// there is no git at all; any other failure fails it, so the check never passes by checking
// nothing.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "ls-files", "-z") //nolint:gosec // G204: root is this repository, fixed by the test
	b, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("no git: the privacy check needs the repository's file list")
	}
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	// Go caches a test's result by the files it opens: stat git's index, so a newly added file
	// re-runs the check instead of returning a cached pass.
	idx, err := exec.Command("git", "-C", root, "rev-parse", "--path-format=absolute", "--git-path", "index").Output() //nolint:gosec // G204: as above
	if err != nil {
		t.Fatalf("git rev-parse: %v", err)
	}
	if _, err := os.Stat(strings.TrimSpace(string(idx))); err != nil {
		t.Fatalf("git's index: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
}

// The repository holds none of the identifiers and names the CI secret lists, anywhere, and its
// test data no real email address (ADR-0024 §13). Without the secret (forks, local runs) only the
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
	files := trackedFiles(t, root)
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
