// Package rerun runs the current test again in a child process with more environment variables:
// the way to test code that reads the environment once per process, such as Go's environment proxy.
package rerun

import (
	"os"
	"os/exec"
	"testing"
)

// childVar marks the child, so the test can tell which side of the run it is on.
const childVar = "RERUN_TEST_CHILD"

// Child reports whether this process is the child of a Run.
func Child() bool { return os.Getenv(childVar) == "1" }

// Run runs the test named name again in a child process, with env added to this process's
// environment, and returns the child's combined output. A child that fails fails the test.
func Run(t *testing.T, name string, env ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1") //nolint:gosec // G204: this test binary, re-run as its own child
	cmd.Env = append(append(os.Environ(), childVar+"=1"), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	return string(out)
}

// Proxy is the environment for a child whose requests go through setting as the environment proxy,
// whatever proxy variables this process has.
func Proxy(setting string) []string {
	return []string{"HTTPS_PROXY=" + setting, "HTTP_PROXY=" + setting, "https_proxy=", "http_proxy=", "NO_PROXY=", "no_proxy=", "REQUEST_METHOD="}
}
