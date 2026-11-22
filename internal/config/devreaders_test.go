package config

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"testing"
)

// devReader is how many .Dev selectors a production file has, and the relaxation config records
// for them with --dev; "" where config itself decides beside its Relaxations entries, or where the
// field is not Config.Dev.
type devReader struct {
	reads      int
	relaxation string
}

// devReaders are the production files that select a .Dev field (security invariant 12).
var devReaders = map[string]devReader{
	"internal/config/config.go":           {4, ""}, // the setting, and the relaxations it records
	"internal/config/config_idp.go":       {1, ""}, // OIDCLoopbackHTTP, beside its relaxation
	"internal/config/config_store.go":     {1, ""}, // the PostgreSQL relaxation
	"internal/servingcert/fileid_unix.go": {1, ""}, // syscall.Stat_t.Dev, the device of the certificate file
	"internal/server/wire_parts.go":       {1, "secret file permissions are not checked"},
	"internal/server/wire_store.go":       {1, "the PostgreSQL store accepts a connection without verify-full TLS"},
	"internal/server/doctor.go":           {1, "the PostgreSQL store accepts a connection without verify-full TLS"},
}

// decidedReaders are the production files that select a field config decides from --dev beside its
// relaxation, and how often: the field is --dev under another name.
var decidedReaders = map[string]int{
	"internal/config/config_idp.go": 1, // set beside its relaxation
	"internal/server/idp.go":        1, // the oidc adapter's AllowLoopbackHTTP
}

// --dev relaxes nothing that is not logged (#355): only the files in devReaders select a .Dev
// field, each as many times as listed, and each one's relaxation is recorded with --dev; only those
// in decidedReaders select OIDCLoopbackHTTP, and only config names the dev setting. A new reader
// relaxes something the startup log may not name; decide it in config beside its relaxation
// instead, as OIDCLoopbackHTTP is. The scan is syntactic, so it also catches Config.Dev reached
// through a field (w.cfg.Dev) in a file that does not import this package.
func TestOnlyKnownCodeReadsDevelopmentMode(t *testing.T) {
	found, named, decided := map[string]int{}, map[string]int{}, map[string]int{}
	eachProductionGoFile(t, func(rel string, fset *token.FileSet, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Dev" {
				if _, known := devReaders[rel]; !known {
					t.Errorf("%s: selects a .Dev field; if it is Config.Dev, decide the relaxation in config beside its Relaxations entry, otherwise list it in devReaders (#355)", fset.Position(sel.Pos()))
				}
				found[rel]++
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "OIDCLoopbackHTTP" {
				decided[rel]++
			}
			// The setting by name reaches --dev without the field (Values.Effective, v.boolean).
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if name, err := strconv.Unquote(lit.Value); err == nil && (name == "dev" || name == "BYWARD_DEV") {
					named[rel]++
				}
			}
			return true
		})
	})
	// Only config names the setting: the registry entry, and reading it (Values.boolean).
	checkCounts(t, "names the dev setting", named, map[string]int{"internal/config/settings.go": 1, "internal/config/config.go": 1})
	checkCounts(t, "selects OIDCLoopbackHTTP, --dev under another name,", decided, decidedReaders)
	devCounts := map[string]int{}
	for rel, r := range devReaders {
		devCounts[rel] = r.reads
	}
	checkCounts(t, "selects .Dev", found, devCounts)
	c, err := loadDSN(t, []string{"--dev"}, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
	if err != nil {
		t.Fatal(err)
	}
	for rel, r := range devReaders {
		if r.relaxation != "" && !slices.Contains(c.Relaxations, r.relaxation) {
			t.Errorf("%s: --dev records no relaxation %q (it records %q)", rel, r.relaxation, c.Relaxations)
		}
	}
}

// checkCounts fails for each file whose count of what differs from want, saying which way: more is a
// new reader of --dev the startup log may not name, fewer is a count to lower.
func checkCounts(t *testing.T, what string, got, want map[string]int) {
	t.Helper()
	files := slices.Sorted(maps.Keys(got))
	for rel := range want {
		if _, ok := got[rel]; !ok {
			files = append(files, rel)
		}
	}
	for _, rel := range files {
		switch {
		case got[rel] > want[rel]:
			t.Errorf("%s %s %d times, want %d: a new reader relaxes what the log may not name; decide it in config beside its relaxation (#355)", rel, what, got[rel], want[rel])
		case got[rel] < want[rel]:
			t.Errorf("%s %s %d times, want %d: lower its count, or remove it", rel, what, got[rel], want[rel])
		}
	}
}
