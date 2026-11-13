// Package rerun runs the current test again in a child process with more environment variables:
// the way to test code that reads the environment once per process, such as Go's environment proxy.
package rerun

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/testutil/closedport"
)

// childVar marks the child, so the test can tell which side of the run it is on. It is not a
// BYWARD_ name, which is kept for settings.
const childVar = "RERUN_TEST_CHILD"

// Child reports whether this process is the child of a Run.
func Child() bool { return os.Getenv(childVar) == "1" }

// Run runs the test named name again in a child process, with env added to this process's
// environment, and returns the child's combined output. The child gets what is left of this test's
// deadline, and a child that fails fails the test.
func Run(t *testing.T, name string, env ...string) string {
	t.Helper()
	args := []string{"-test.run=^" + name + "$", "-test.count=1"}
	if d, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout="+time.Until(d).String())
	}
	cmd := exec.Command(os.Args[0], args...) //nolint:gosec // G204: this test binary, re-run as its own child
	cmd.Env = append(append(os.Environ(), childVar+"=1"), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	return string(out)
}

// ProxyEnv is the environment for a child whose requests go through setting as the environment
// proxy, whatever proxy variables this process has.
func ProxyEnv(setting string) []string {
	return []string{"HTTPS_PROXY=" + setting, "HTTP_PROXY=" + setting, "https_proxy=", "http_proxy=", "NO_PROXY=", "no_proxy=", "REQUEST_METHOD="}
}

// EachProxySetting runs the test named name in a child once per environment proxy setting aimed at a
// local address nothing listens on: one Go misreads (its credentials split by a /), whose dialled
// address is part of the credentials, and a well-formed one. check gets the child's output, the
// dialled address, and whether the setting was misread.
func EachProxySetting(t *testing.T, name string, check func(t *testing.T, out, addr string, misread bool)) {
	t.Helper()
	addr := closedport.Addr(t)
	for _, tc := range []struct {
		name    string
		setting string
		misread bool
	}{
		{"a misread setting", addr + "/pw-secret@egress.example:3128", true},
		{"a well-formed setting", "http://" + addr, false},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, Run(t, name, ProxyEnv(tc.setting)...), addr, tc.misread) })
	}
}

// CauseOnlyIfMisread fails t unless the child's output out names envproxy.Cause and never addr when
// the setting was misread, and quotes addr without the cause when it was well-formed.
func CauseOnlyIfMisread(t *testing.T, out, addr string, misread bool) {
	t.Helper()
	if strings.Contains(out, addr) == misread || strings.Contains(out, envproxy.Cause) != misread {
		t.Fatalf("child output %q; misread %v", out, misread)
	}
}

// CallFailedWithCauseOnlyIfMisread is the check for a child that prints its call's error as ERR=:
// the call failed, and its error says CauseOnlyIfMisread.
func CallFailedWithCauseOnlyIfMisread(t *testing.T, out, addr string, misread bool) {
	t.Helper()
	if !strings.Contains(out, "ERR=") || strings.Contains(out, "ERR=<nil>") {
		t.Fatalf("child output %q; want the call to fail", out)
	}
	CauseOnlyIfMisread(t, out, addr, misread)
}
