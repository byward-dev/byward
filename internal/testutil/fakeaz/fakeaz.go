// Package fakeaz runs a script printed by `byward init` against stand-ins for the Azure CLI and
// uuidgen, so tests check what the script does (the az calls, the files it writes) without a tenant.
package fakeaz

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Fixed answers of the stand-in az.
const (
	AppID  = "aaaaaaaa-0000-0000-0000-000000000001"
	Secret = "fake-client-secret-value" //nolint:gosec // G101: a test stand-in, not a credential
)

// Result is what one run of the script did.
type Result struct {
	// Calls are the az command lines, in order.
	Calls []string
	// GraphBody is the request body of the `az rest` call, "" without one.
	GraphBody string
	Stdout    string
	Stderr    string
	Err       error
	// Dir is the working directory the script ran in.
	Dir string
}

// File returns a file the script wrote in its working directory and its mode.
func (r Result) File(t testing.TB, name string) (string, os.FileMode) {
	t.Helper()
	p := filepath.Join(r.Dir, name)
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own temp dir
	if err != nil {
		t.Fatalf("the script did not write %s: %v", name, err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), fi.Mode().Perm()
}

// azStub logs every call and answers the ones the script reads from.
const azStub = `#!/bin/sh
printf '%s\n' "az $*" >> "$FAKEAZ_LOG"
case "$*" in
  "account show"*) printf '%s\n' "$FAKEAZ_TENANT" ;;
  "ad app create"*) printf '%s\n' "` + AppID + `" ;;
  "ad sp create"*) printf '%s\n' "bbbbbbbb-0000-0000-0000-000000000001" ;;
  "ad app credential reset"*) printf '%s\n' "` + Secret + `" ;;
  rest*) for a in "$@"; do case "$a" in @*) cat "${a#@}" > "$FAKEAZ_LOG.body" ;; esac; done ;;
esac
`

// Run runs script with sh in a fresh directory; az answers `account show` with signedInTenant.
// The PATH holds only the stand-ins and the system's basic tools.
func Run(t testing.TB, script, signedInTenant string) Result {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	bin := t.TempDir()
	dir, err := filepath.EvalSymlinks(t.TempDir()) // as the script's $PWD sees it (macOS: /private/var)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"az": azStub, "uuidgen": "#!/bin/sh\necho 0F0F0F0F-0000-0000-0000-000000000000\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // G306: an executable stand-in
			t.Fatal(err)
		}
	}
	log := filepath.Join(t.TempDir(), "az.log")
	cmd := exec.Command(sh, "-c", script) //nolint:gosec // G204: the script under test
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + dir, "FAKEAZ_LOG=" + log, "FAKEAZ_TENANT=" + signedInTenant}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	r := Result{Err: cmd.Run(), Stdout: stdout.String(), Stderr: stderr.String(), Dir: dir}
	if b, err := os.ReadFile(log); err == nil { //nolint:gosec // G304: the test's own temp file
		r.Calls = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	if b, err := os.ReadFile(log + ".body"); err == nil { //nolint:gosec // G304: the test's own temp file
		r.GraphBody = string(b)
	}
	return r
}
