package config

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
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

// oneOf lists words as a want: "json or text", "entra, oidc or google".
func oneOf(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
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
	raw := val.Given.raw()
	list := splitList(raw)
	if raw != "" && len(list) == 0 {
		return nil, listsNothing(val.Setting)
	}
	return list, nil
}

// listsNothing refuses a list setting that is set but names no entry, such as ",": it would read as
// unset, and a gate list would silently open the gate.
func listsNothing(s Setting) error {
	return errorf("%s: want at least one entry, or leave it unset; got a list of none", s.Env())
}
