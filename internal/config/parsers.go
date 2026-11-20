package config

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The parsers of the settings that hold a word, a number, a duration or free text (ADR-0031 §1): each
// takes the setting's Value and refuses through refusedForm or refusedMeaning, so no refusal shows a
// value as given.

// parseText is a free-text setting's value as given: a name, a path or a secret config takes as it
// is. A check a caller makes on it refuses through refusedForm, never by quoting it.
func parseText(val Value) string { return val.Given.raw() }

// parseBool reads a true/false setting. Every setting read this way must be Bool in the registry, so a
// bare --name means true (TestBooleanSettingsAreExactlyTheBoolFlags, TestEveryBooleanReadIsOfABoolFlag).
func parseBool(val Value) (bool, error) {
	raw := val.Given.raw()
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, refusedForm(val.Setting, whole, raw, "true or false", "it is neither true nor false")
	}
	return b, nil
}

// parseWord reads a setting that takes one of words, exactly as written there.
func parseWord(val Value, words ...string) (string, error) {
	raw := val.Given.raw()
	if !slices.Contains(words, raw) {
		return "", refusedForm(val.Setting, whole, raw, oneOf(words), "it is not one of them")
	}
	return raw, nil
}

// oneOf lists two or more words as a want: "json or text", "entra, oidc or google".
func oneOf(words []string) string {
	return strings.Join(words[:len(words)-1], ", ") + " or " + words[len(words)-1]
}

// parseDuration reads a duration setting. want names its form and range, such as "a duration from
// 1s to 1h, such as 5m"; fits says whether a duration is in range. One out of range is shown as the
// parser read it.
func parseDuration(val Value, want string, fits func(time.Duration) bool) (time.Duration, error) {
	raw := val.Given.raw()
	d, err := time.ParseDuration(raw)
	switch {
	case err != nil:
		return 0, refusedForm(val.Setting, whole, raw, want, "it is not a duration")
	case !fits(d):
		return 0, refusedMeaning(val.Setting, whole, d.String(), want, "it is out of range")
	}
	return d, nil
}

// parseWholeNumber reads a whole number from lo to hi. One out of range is shown as the parser read it.
func parseWholeNumber(val Value, lo, hi int) (int, error) {
	raw := val.Given.raw()
	want := fmt.Sprintf("a whole number from %d to %d", lo, hi)
	n, err := strconv.Atoi(raw)
	switch {
	case err != nil:
		return 0, refusedForm(val.Setting, whole, raw, want, "it is not a whole number")
	case n < lo || n > hi:
		return 0, refusedMeaning(val.Setting, whole, strconv.Itoa(n), want, "it is out of range")
	}
	return n, nil
}

// parseList reads a comma-separated list setting of free text, such as role names: its entries.
func parseList(val Value) ([]string, error) {
	list, _, err := parseEntries(val)
	return list, err
}

// parseWording reads page wording: no control or format characters (bidi overrides), at most max
// characters.
func parseWording(val Value, max int) (string, error) {
	raw := val.Given.raw()
	want := fmt.Sprintf("text of at most %d characters, without control or formatting characters", max)
	switch {
	case strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }):
		return "", refusedForm(val.Setting, whole, raw, want, "it has a control or formatting character")
	case utf8.RuneCountInString(raw) > max:
		return "", refusedForm(val.Setting, whole, raw, want, "it is too long")
	}
	return raw, nil
}

// parseScope reads BYWARD_SCOPE: one scope token (RFC 6749 §3.3), since it is written into a quoted
// challenge.
func parseScope(val Value) (string, error) {
	raw := val.Given.raw()
	if !isScopeToken(raw) {
		return "", refusedForm(val.Setting, whole, raw, "one scope token, such as mcp", notScopeToken)
	}
	return raw, nil
}

// isScopeToken reports whether s is a scope token (RFC 6749 §3.3): printable ASCII but a space, a
// double quote or a backslash, and not empty.
func isScopeToken(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e || r == '"' || r == '\\' })
}

// notScopeToken is the reason a value is not a scope token.
const notScopeToken = "it has a character a scope token cannot hold: white space, a double quote, a backslash or one that is not printable ASCII"

// parseEntries splits val, a comma-separated list setting, into its entries, each with its place in
// the list. A value set but naming no entry, such as ",", is refused (listsNothing).
func parseEntries(val Value) ([]string, func(i int) entry, error) {
	raw := val.Given.raw()
	list := splitList(raw)
	if raw != "" && len(list) == 0 {
		return nil, nil, listsNothing(val.Setting)
	}
	return list, func(i int) entry { return entry{i, len(list)} }, nil
}

// listsNothing refuses a list setting that is set but names no entry, such as ",": it would read as
// unset, and a gate list would silently open the gate.
func listsNothing(s Setting) error {
	return errorf("%s: want at least one entry; got a list of none", s.Env())
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
