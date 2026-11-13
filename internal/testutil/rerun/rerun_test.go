package rerun

import (
	"fmt"
	"strings"
	"testing"
)

// The marker a shell might leave set never makes a test take the child's side, which would pass it
// without checking anything; the child Run starts still does.
func TestOnlyTheChildOfARunTakesTheChildsSide(t *testing.T) {
	if Child() {
		fmt.Println("on the child's side")
		return
	}
	t.Setenv(childVar, "1")
	if Child() {
		t.Fatalf("%s=1 from the shell made this process a child", childVar)
	}
	if out := Run(t, "TestOnlyTheChildOfARunTakesTheChildsSide"); !strings.Contains(out, "on the child's side") {
		t.Fatalf("child output %q; want the child to take the child's side", out)
	}
}
