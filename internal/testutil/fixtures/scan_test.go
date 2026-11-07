package fixtures

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// guid is a fresh random GUID, so no planted value is ever written into this repository.
func guid(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// A planted identifier or name is found in any file, in any case, and an email address only in
// test data, outside the example domains; no finding repeats what it found.
func TestTheScanFindsPlantedValuesAndNeverPrintsThem(t *testing.T) {
	id, name := guid(t), "Project"+"Unnamed"+guid(t)[:6]
	real, example := "ops"+"@"+"corp.test", "alex"+"@"+"contoso.example"
	root := t.TempDir()
	files := map[string]string{
		"internal/x/testdata/fixture.json": "{\n\"tid\": \"" + strings.ToUpper(id) + "\",\n\"mail\": \"" + real + "\",\n\"ok\": \"" + example + "\"\n}\n",
		"internal/x/x_test.go":             "package x\n\n// a comment, not test data: " + real + "\nvar a = \"" + real + "\"\nvar b = `\n" + example + "\n" + real + "`\nvar c = \"x\\n" + real + "\"\n",
		"docs/notes.md":                    "line one\nthe " + strings.ToLower(name) + " project\nwrite to " + real + "\nagain: " + name + "\n",
		"internal/x/x.golden":              "\n\n" + real + "\n",
		"testdata/root.json":               example + " cc " + real + "\n",
		// Lowering shrinks each İ (2 bytes to 1) and grows invalid bytes (1 to 3): line counts must
		// not mix the two byte offsets.
		"assets/blob.bin": strings.Repeat("\u0130", 20) + "\xff\n" + strings.ToUpper(name) + "\n",
		"internal/x/x.go": "package x\n\nconst mail = \"" + real + "\"\n",
	}
	var rels []string
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		rels = append(rels, rel)
	}
	rels = append(rels, "deleted/in/the/working/tree.json")
	got, err := scan(root, rels, forbiddenList("\n  "+id+"  \n\n"+name+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"internal/x/testdata/fixture.json:2: " + kindForbidden: true,
		"internal/x/testdata/fixture.json:3: " + kindEmail:     true,
		"internal/x/x_test.go:4: " + kindEmail:                 true,
		"internal/x/x_test.go:7: " + kindEmail:                 true,
		"internal/x/x_test.go:8: " + kindEmail:                 true,
		"docs/notes.md:2: " + kindForbidden:                    true,
		"docs/notes.md:4: " + kindForbidden:                    true,
		"internal/x/x.golden:3: " + kindEmail:                  true,
		"testdata/root.json:1: " + kindEmail:                   true,
		"assets/blob.bin:2: " + kindForbidden:                  true,
	}
	gotSet := map[string]bool{}
	for _, f := range got {
		s := f.String()
		gotSet[s] = true
		for _, secret := range []string{id, strings.ToUpper(id), name, strings.ToLower(name), real} {
			if strings.Contains(s, secret) {
				t.Errorf("a finding repeats what it found: %q", s)
			}
		}
	}
	if !reflect.DeepEqual(gotSet, want) || len(got) != len(want) {
		t.Fatalf("findings %v\nwant %v", gotSet, want)
	}
}

func TestOnlyTheExampleDomainsAreAllowedInTestEmails(t *testing.T) {
	for d, want := range map[string]bool{
		"example.com": true, "Mail.EXAMPLE.com": true, "mail.example.org": true, "example.net": true, "contoso.example": true, "a.b.example": true,
		"contoso.com": false, "example.com.evil.net": false, "notexample.com": false, "corp.test": false, "example": false,
	} {
		if got := exampleDomain(d); got != want {
			t.Errorf("exampleDomain(%q) = %v, want %v", d, got, want)
		}
	}
}

func TestTestDataIsWhatIsUnderATestdataDirectoryOrAGoldenFile(t *testing.T) {
	for rel, want := range map[string]bool{
		"testdata/a.json": true, "internal/x/testdata/a": true, "x.golden": true, "internal/x/events.golden.jsonl": true,
		"internal/x/x.go": false, "docs/testdata.md": false, "mytestdata/a": false, "internal/x/x_test.go": false,
	} {
		if got := fixture(rel); got != want {
			t.Errorf("fixture(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestALineHoldsARealEmailWhereverItsAddressStands(t *testing.T) {
	real, example := "ops"+"@"+"corp.test", "alex"+"@"+"contoso.example"
	for line, want := range map[string]bool{
		example + " then " + real: true,
		example + ", " + example:  false,
		"a" + "@" + "x.corp.test": true,
		"a bare @ sign":           false,
		"user@localhost":          false,
		"a" + "@" + "example.com": false,
	} {
		if got := hasRealEmail(line); got != want {
			t.Errorf("hasRealEmail(%q) = %v, want %v", line, got, want)
		}
	}
}

// No git means no check (the test skips); any other git failure is an error, never an empty list.
func TestOnlyAMissingGitLeavesTheFileListUnchecked(t *testing.T) {
	for name, tc := range map[string]struct {
		path, root  string
		wantMissing bool
	}{
		"no git on PATH":   {path: t.TempDir(), root: t.TempDir(), wantMissing: true},
		"not a repository": {path: os.Getenv("PATH"), root: t.TempDir()},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			t.Setenv("GIT_DIR", filepath.Join(tc.root, ".git")) // not a repository even under a TMPDIR inside one
			files, err := checkoutFiles(tc.root)
			if err == nil || files != nil || errors.Is(err, exec.ErrNotFound) != tc.wantMissing {
				t.Fatalf("files %v, err %v; want an error, missing git %v", files, err, tc.wantMissing)
			}
		})
	}
}

// A file the scan cannot read (here, a directory) is an error, not a skipped file: only one that is
// gone from the working tree is skipped.
func TestAFileTheScanCannotReadIsAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a-directory"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := scan(root, []string{"a-directory"}, nil); err == nil {
		t.Fatal("scan read a directory as a file without an error")
	}
}

// A symlink is checked as git commits it: its target path, never the target's content.
func TestASymlinkIsCheckedAsTheLinkGitCommits(t *testing.T) {
	name := "Project" + "Unnamed" + guid(t)[:6]
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte(name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for link, target := range map[string]string{"to-outside": outside, "named": "/opt/" + name, "to-dir": t.TempDir()} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := scan(root, []string{"to-outside", "named", "to-dir"}, forbiddenList(name))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "named:1: "+kindForbidden {
		t.Fatalf("findings %v, want only the link whose target path names it", got)
	}
}
