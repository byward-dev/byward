package sqlite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A database symlinked to a file not yet created on another volume passes: Open creates it.
func TestCheckPathsAcceptsADatabaseLinkToAFileOpenCreates(t *testing.T) {
	for name, target := range map[string]func(volume string) string{
		"absolute target": func(volume string) string { return filepath.Join(volume, fileName) },
		"relative target": func(string) string { return filepath.Join("..", "volume", fileName) },
		// byward.db -> hop -> volume/byward.db: the chain is followed to its end.
		"two links": func(volume string) string {
			hop := filepath.Join(volume, "hop")
			if err := os.Symlink(filepath.Join(volume, fileName), hop); err != nil {
				panic(err)
			}
			return hop
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			state, volume := filepath.Join(root, "state"), filepath.Join(root, "volume")
			for _, d := range []string{state, volume} {
				if err := os.Mkdir(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target(volume), filepath.Join(state, fileName)); err != nil {
				t.Fatal(err)
			}
			opts := Options{Dir: state, CounterFile: filepath.Join(root, "store-writes")}
			if err := CheckPaths(opts); err != nil {
				t.Fatalf("CheckPaths refused a layout Open accepts: %v", err)
			}
			st, err := Open(t.Context(), opts)
			if err != nil {
				t.Fatalf("the premise does not hold, Open refuses it too: %v", err)
			}
			_ = st.Close()
		})
	}
}

// An existing store that Open accepts passes, counter file included.
func TestCheckPathsAcceptsAnOpenedStore(t *testing.T) {
	root := t.TempDir()
	opts := Options{Dir: filepath.Join(root, "state"), CounterFile: filepath.Join(root, "store-writes")}
	st, err := Open(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckPaths(opts); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPathsAcceptsWhatOpenCanCreateAndWritesNothing(t *testing.T) {
	root := t.TempDir()
	// Open creates the state directory with MkdirAll, missing parents included.
	opts := Options{Dir: filepath.Join(root, "a", "b", "state"), CounterFile: filepath.Join(root, "store-writes")}
	if err := CheckPaths(opts); err != nil {
		t.Fatal(err)
	}
	// The counter file's directory may be missing when it is the state directory's parent.
	nested := Options{Dir: filepath.Join(root, "data", "state"), CounterFile: filepath.Join(root, "data", "store-writes")}
	if err := CheckPaths(nested); err != nil {
		t.Fatalf("counter next to a state directory MkdirAll creates: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("CheckPaths wrote %v (%v)", entries, err)
	}
}

// layout builds file-system fixtures under one root, failing the test on any error.
type layout struct {
	t    *testing.T
	root string
}

func (l layout) path(parts ...string) string {
	return filepath.Join(append([]string{l.root}, parts...)...)
}

func (l layout) dir(parts ...string) string {
	l.t.Helper()
	p := l.path(parts...)
	if err := os.MkdirAll(p, 0o700); err != nil {
		l.t.Fatal(err)
	}
	return p
}

// withParent creates p's directory and returns p.
func (l layout) withParent(p string) string {
	l.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		l.t.Fatal(err)
	}
	return p
}

func (l layout) file(content string, parts ...string) string {
	l.t.Helper()
	p := l.withParent(l.path(parts...))
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		l.t.Fatal(err)
	}
	return p
}

func (l layout) link(target string, parts ...string) string {
	l.t.Helper()
	p := l.withParent(l.path(parts...))
	if err := os.Symlink(target, p); err != nil {
		l.t.Fatal(err)
	}
	return p
}

func TestCheckPathsRefusesWhatOpenWouldFailOn(t *testing.T) {
	cases := []struct {
		name  string
		setup func(l layout) (opts Options, inErr string)
	}{
		{"relative state directory", func(l layout) (Options, string) {
			return Options{Dir: "state", CounterFile: l.path("c")}, "absolute paths"
		}},
		{"counter file inside the state directory", func(l layout) (Options, string) {
			return Options{Dir: l.path("state"), CounterFile: l.path("state", "c")}, "outside the state directory"
		}},
		{"state directory is a file", func(l layout) (Options, string) {
			f := l.file("", "file")
			return Options{Dir: f, CounterFile: l.path("c")}, "state directory " + f + " is not a directory"
		}},
		{"state directory below a file", func(l layout) (Options, string) {
			f := l.file("", "file")
			return Options{Dir: filepath.Join(f, "state"), CounterFile: l.path("c")}, f + " is not a directory"
		}},
		{"state directory is a dangling symlink", func(l layout) (Options, string) {
			return Options{Dir: l.link(l.path("nowhere"), "dangling"), CounterFile: l.path("c")}, "symlink to nothing"
		}},
		{"state directory below a dangling symlink", func(l layout) (Options, string) {
			d := l.link(l.path("nowhere"), "dangling")
			return Options{Dir: filepath.Join(d, "state"), CounterFile: filepath.Join(d, "c")}, "symlink to nothing"
		}},
		{"counter directory missing", func(l layout) (Options, string) {
			return Options{Dir: l.path("state"), CounterFile: l.path("missing", "c")}, "does not exist; create it"
		}},
		{"counter directory is a file", func(l layout) (Options, string) {
			f := l.file("", "file")
			return Options{Dir: l.path("state"), CounterFile: filepath.Join(f, "c")}, "the counter file's directory " + f + " is not a directory"
		}},
		{"counter file is a directory", func(l layout) (Options, string) {
			return Options{Dir: l.path("state"), CounterFile: l.dir("dir")}, "is not a regular file"
		}},
		{"counter file is corrupt", func(l layout) (Options, string) {
			return Options{Dir: l.path("state"), CounterFile: l.file("not a number\n", "corrupt")}, "is corrupt"
		}},
		{"database is a directory", func(l layout) (Options, string) {
			db := l.dir("state", fileName)
			return Options{Dir: l.path("state"), CounterFile: l.path("c")}, "database file " + db + " is not a regular file"
		}},
		{"database is a symlink to nothing", func(l layout) (Options, string) {
			l.link(l.path("gone", fileName), "state", fileName)
			return Options{Dir: l.path("state"), CounterFile: l.path("c")}, "byward.db is a symlink to nothing"
		}},
		{"database is a symlink to itself", func(l layout) (Options, string) {
			l.link(fileName, "state", fileName)
			return Options{Dir: l.path("state"), CounterFile: l.path("c")}, "byward.db is a symlink to nothing"
		}},
		{"database links through a second link to nothing", func(l layout) (Options, string) {
			l.link("hop", "state", fileName)
			l.link(l.path("nodir", "x"), "state", "hop")
			return Options{Dir: l.path("state"), CounterFile: l.path("c")}, "byward.db is a symlink to nothing"
		}},
		// The target's directory exists, which is enough for the database but not for SQLite's WAL.
		{"write-ahead log is a symlink to a file not yet created", func(l layout) (Options, string) {
			l.link(filepath.Join(l.dir("volume"), "wal"), "state", fileName+"-wal")
			return Options{Dir: l.path("state"), CounterFile: l.path("c")}, "byward.db-wal is a symlink to nothing"
		}},
		{"write-ahead log is a directory", func(l layout) (Options, string) {
			l.dir("state", fileName+"-wal")
			return Options{Dir: l.path("state"), CounterFile: l.path("c")}, "byward.db-wal is not a regular file"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, inErr := tc.setup(layout{t: t, root: t.TempDir()})
			if err := CheckPaths(opts); err == nil || !strings.Contains(err.Error(), inErr) {
				t.Fatalf("err = %v, want %q", err, inErr)
			}
		})
	}
}
