package fakeidp

import (
	"strings"
	"testing"
)

func TestIsGUID(t *testing.T) {
	g := NewGUID()
	for s, want := range map[string]bool{
		g:                                      true,
		strings.ToUpper(g):                     true,
		g[:35]:                                 false,
		g + "0":                                false,
		g[:8] + "0" + g[9:]:                    false, // dash missing
		"g" + g[1:]:                            false,
		"organizations":                        false,
		"":                                     false,
		"00000000-0000-0000-0000-00000000000g": false,
	} {
		if got := isGUID(s); got != want {
			t.Errorf("isGUID(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestAudContainsOnlyStringsAndJSONArrays(t *testing.T) {
	for name, tc := range map[string]struct {
		aud  any
		want bool
	}{
		"string hit":        {"a", true},
		"string miss":       {"b", false},
		"array hit":         {[]any{"x", "a"}, true},
		"array miss":        {[]any{"x"}, false},
		"array non-strings": {[]any{1, nil}, false},
		"nil":               {nil, false},
		"[]string":          {[]string{"a"}, false},
	} {
		if got := audContains(tc.aud, "a"); got != tc.want {
			t.Errorf("%s: audContains = %v, want %v", name, got, tc.want)
		}
	}
}
