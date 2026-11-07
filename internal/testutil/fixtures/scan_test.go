package fixtures

import (
	"crypto/rand"
	"fmt"
	"os"
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
		"internal/x/x_test.go":             "package x\n\n// a comment, not test data: " + real + "\nvar a = \"" + real + "\"\nvar b = `\n" + example + "\n" + real + "`\n",
		"docs/notes.md":                    "line one\nthe " + strings.ToLower(name) + " project\nwrite to " + real + "\nagain: " + name + "\n",
		"internal/x/x.golden":              "\n\n" + real + "\n",
		"internal/x/x.go":                  "package x\n\nconst mail = \"" + real + "\"\n",
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
		"docs/notes.md:2: " + kindForbidden:                    true,
		"docs/notes.md:4: " + kindForbidden:                    true,
		"internal/x/x.golden:3: " + kindEmail:                  true,
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

func TestOnlyReservedDomainsAreExamples(t *testing.T) {
	for d, want := range map[string]bool{
		"example.com": true, "mail.example.org": true, "example.net": true, "contoso.example": true, "a.b.example": true,
		"contoso.com": false, "example.com.evil.net": false, "notexample.com": false, "corp.test": false, "example": false,
	} {
		if got := exampleDomain(d); got != want {
			t.Errorf("exampleDomain(%q) = %v, want %v", d, got, want)
		}
	}
}
