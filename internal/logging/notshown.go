package logging

import (
	"fmt"
	"unicode/utf8"
)

// NotShown is how a message names a value it must not show (ADR-0031 §1): by its length only, as
// "(9 characters, not shown)", so a secret pasted into the wrong place is never printed.
func NotShown(raw string) string {
	if n := utf8.RuneCountInString(raw); n != 1 {
		return fmt.Sprintf("(%d characters, not shown)", n)
	}
	return "(1 character, not shown)"
}
