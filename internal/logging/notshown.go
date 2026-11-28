package logging

import (
	"fmt"
	"strconv"
	"strings"
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

// AsGiven is raw as given, or quoted (strconv.Quote) when it holds a character that is not
// printable, such as a newline, which would start a line of its own in --print-config and could
// forge another setting's line there (#505), or a byte that is not UTF-8, which the printable test
// reads as U+FFFD and would let through (a raw 0x9b is a terminal's CSI). Config shows a value of a
// setting shown as given this way, and LooksSecret reads a value as it would be shown (#657).
func AsGiven(raw string) string {
	if !utf8.ValidString(raw) || strings.ContainsFunc(raw, func(r rune) bool { return !strconv.IsPrint(r) }) {
		return strconv.Quote(raw)
	}
	return raw
}
