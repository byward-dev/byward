package entra

import "testing"

func FuzzCodeOf(f *testing.F) {
	f.Add("AADSTS50105: The signed in user")
	f.Add("AADSTS99999999999999999999: overflow")
	f.Add("")
	f.Fuzz(func(t *testing.T, description string) {
		if code := codeOf(nil, description); code < 0 {
			t.Fatalf("negative code %d for %q", code, description)
		}
	})
}
