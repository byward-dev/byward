package logging_test

import (
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// NotShown names a value by its length in characters, never by its text (ADR-0031 §1).
func TestNotShownGivesOnlyTheLengthInCharacters(t *testing.T) {
	for value, want := range map[string]string{
		"https://u:S3CRET@h.example/x?k=S3CRET": "(37 characters, not shown)",
		"ä€":                                    "(2 characters, not shown)",
		"S":                                     "(1 character, not shown)",
		"":                                      "(0 characters, not shown)",
	} {
		if got := logging.NotShown(value); got != want {
			t.Errorf("NotShown(%q) = %q, want %q", value, got, want)
		}
	}
}
