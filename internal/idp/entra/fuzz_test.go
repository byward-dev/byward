package entra

import (
	"regexp"
	"strconv"
	"testing"
)

var digits = regexp.MustCompile(`^AADSTS(\d+):`)

func FuzzCodeOf(f *testing.F) {
	f.Add("AADSTS50105: The signed in user", 0)
	f.Add("AADSTS99999999999999999999: overflow", 0)
	f.Add("", 7000215)
	f.Fuzz(func(t *testing.T, description string, first int) {
		if first != 0 {
			if got := codeOf([]int{first}, description); got != first {
				t.Fatalf("codeOf prefers %d over error_codes %d", got, first)
			}
		}
		want := 0
		if m := digits.FindStringSubmatch(description); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				want = n
			}
		}
		if got := codeOf(nil, description); got != want {
			t.Fatalf("codeOf(%q) = %d, want %d", description, got, want)
		}
	})
}

func TestCodeOfIgnoresOverflowingCodes(t *testing.T) {
	if got := codeOf(nil, "AADSTS99999999999999999999: x"); got != 0 {
		t.Fatalf("got %d", got)
	}
}
