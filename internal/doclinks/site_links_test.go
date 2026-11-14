package doclinks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// siteLinksFile lists every link from byward.dev into this repository.
const siteLinksFile = "site-links.txt"

const repoURL = "https://github.com/byward-dev/byward/"

// siteLinkProblem checks one line of site-links.txt against the tree at root and says what is
// wrong, or "". Blank lines and # comments are fine.
func siteLinkProblem(root, line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	rest, ok := strings.CutPrefix(line, repoURL)
	kind, path, found := strings.Cut(rest, "/main/")
	if !ok || !found || (kind != "blob" && kind != "tree") || path == "" {
		return line + " is not a " + repoURL + "blob/main/<path> or tree/main/<path> link"
	}
	if strings.ContainsAny(path, "#?") {
		return line + ": list the page without its #anchor or ?query"
	}
	if !filepath.IsLocal(filepath.FromSlash(path)) {
		return line + " points outside the repository"
	}
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))) //nolint:gosec // G703: path is filepath.IsLocal, checked above
	switch {
	case err != nil:
		return "byward.dev links to " + path + ", which is not in this tree: keep the file, or leave a page at the old path that links to the new one"
	case kind == "blob" && fi.IsDir():
		return path + " is a directory: a blob link needs a file (or list it as tree/main/" + path + ")"
	case kind == "tree" && !fi.IsDir():
		return path + " is a file: a tree link needs a directory (or list it as blob/main/" + path + ")"
	}
	return ""
}

// Every page byward.dev links to exists in this tree, so a PR that moves one without leaving a
// pointer at the old path fails here. The list is kept in step with the site by a check in the
// site's repository (site-links.txt says how).
func TestEveryPageTheWebsiteLinksToExists(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(siteLinksFile)
	if err != nil {
		t.Fatal(err)
	}
	listed := 0
	for i, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), repoURL) {
			listed++
		}
		if problem := siteLinkProblem(root, line); problem != "" {
			t.Errorf("%s:%d: %s", siteLinksFile, i+1, problem)
		}
	}
	if listed == 0 {
		t.Fatalf("%s lists no links", siteLinksFile)
	}
}
