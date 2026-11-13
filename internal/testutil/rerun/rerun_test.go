package rerun

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The marker a shell might leave set never makes a test take the child's side, which would pass it
// without checking anything; the child Run starts still does. The test tells its own sides apart by
// a variable of its own, not by Child, so a broken Child cannot skip the check.
func TestOnlyTheChildOfARunTakesTheChildsSide(t *testing.T) {
	if os.Getenv("RERUN_SELF_TEST_CHILD") == "1" {
		fmt.Println("child: Child() =", Child())
		return
	}
	t.Setenv(childVar, "1")
	if Child() {
		t.Fatalf("%s=1 from the shell made this process a child", childVar)
	}
	if out := Run(t, "TestOnlyTheChildOfARunTakesTheChildsSide", "RERUN_SELF_TEST_CHILD=1"); !strings.Contains(out, "child: Child() = true") {
		t.Fatalf("child output %q; want the child of Run to take the child's side", out)
	}
}
