package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// A setting read as a boolean is a Bool flag, so a bare --name means true on the command line, as
// --dev does; without Bool, the flag package would want an argument.
func TestEveryBooleanSettingIsABoolFlag(t *testing.T) {
	byName := map[string]Setting{}
	for _, s := range registry {
		byName[s.Name] = s
	}
	read := regexp.MustCompile(`\.boolean\("([^"]+)"\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, f := range files {
		src, err := os.ReadFile(f) //nolint:gosec // G304: reads this package's own files
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range read.FindAllStringSubmatch(string(src), -1) {
			seen++
			if s, ok := byName[m[1]]; !ok || !s.Bool {
				t.Errorf("%s reads %s as a boolean, but the registry does not mark it Bool", f, m[1])
			}
		}
	}
	if seen < 7 { // dev, insecure-no-auth, dcr, cimd, gate-allow-empty, identity-headers, assertion-unverified-email
		t.Fatalf("found %d boolean reads, want at least 7: has the reader been renamed?", seen)
	}
}
