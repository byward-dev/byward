package config

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The shared parsers (ADR-0031 §1): of a word, a boolean, a whole number, a duration, free text, page
// wording and a comma-separated list, and of a scope token, which two settings take; and the
// per-entry rules of list settings (entryCheck, parseChecked) with the rules for GUIDs, names, Entra
// app role values and domain names, kept together because the gate, app-token and Entra sections
// share most of them. Each parser takes the setting's Value and refuses through refusedForm or
// refusedMeaning (an entry rule only returns a reason, which parseChecked refuses with), so no
// refusal shows a value as given; a setting's own parser sits in its section's file.

// parseText is a free-text setting's value as given: a name, a path or a secret config takes as it
// is. A check a caller makes on it refuses through refusedForm, never by quoting it.
func parseText(val Value) string { return val.Given.raw() }

// parseBool reads a true/false setting. Every setting read this way must be Bool in the registry, so a
// bare --name means true (TestBooleanSettingsAreExactlyTheBoolFlags, TestEveryBooleanReadIsOfABoolFlag).
func parseBool(val Value) (bool, error) {
	raw := val.Given.raw()
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, refusedForm(val, whole, raw, "true or false", "it is neither true nor false")
	}
	return b, nil
}

// parseWord reads a setting that takes one of words, exactly as written there.
func parseWord(val Value, words ...string) (string, error) {
	raw := val.Given.raw()
	if !slices.Contains(words, raw) {
		return "", refusedForm(val, whole, raw, oneOf(words), "it is not one of them")
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
		return 0, refusedForm(val, whole, raw, want, durationReason(err))
	case !fits(d):
		return 0, refusedMeaning(val, whole, d.String(), want, "it is out of range")
	}
	return d, nil
}

// durationUnits are the units a duration takes, as a refusal lists them.
const durationUnits = "ns, us, ms, s, m or h"

// durationReason says why time.ParseDuration refused a value, from its error, as a clause that never
// quotes the value. The error's type is unexported, so its message is read: only its fixed start,
// before the quoted value.
func durationReason(err error) string {
	switch msg := err.Error(); {
	case strings.HasPrefix(msg, "time: missing unit"):
		return "it has a number without a unit; give one of " + durationUnits
	case strings.HasPrefix(msg, "time: unknown unit"):
		return "it has a unit that is not one of " + durationUnits
	}
	return "it is not a duration"
}

// parseWholeNumber reads a whole number from lo to hi. One out of range is shown as the parser read it.
func parseWholeNumber(val Value, lo, hi int) (int, error) { //nolint:unparam // the range is the setting's, not the parser's; the stdio caps are its only caller today
	raw := val.Given.raw()
	want := fmt.Sprintf("a whole number from %d to %d", lo, hi)
	n, err := strconv.Atoi(raw)
	switch {
	case errors.Is(err, strconv.ErrRange):
		return 0, refusedForm(val, whole, raw, want, "it is out of range")
	case err != nil:
		return 0, refusedForm(val, whole, raw, want, "it is not a whole number")
	case n < lo || n > hi:
		return 0, refusedMeaning(val, whole, strconv.Itoa(n), want, "it is out of range")
	}
	return n, nil
}

// parseWording reads page wording: no control or format characters (bidi overrides), at most max
// characters.
func parseWording(val Value, max int) (string, error) {
	raw := val.Given.raw()
	want := fmt.Sprintf("text of at most %d characters, without control or formatting characters", max)
	switch {
	case strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }):
		return "", refusedForm(val, whole, raw, want, "it has a control or formatting character")
	case utf8.RuneCountInString(raw) > max:
		return "", refusedForm(val, whole, raw, want, "it is too long")
	}
	return raw, nil
}

// parseScope reads BYWARD_SCOPE: one scope token (RFC 6749 §3.3), since it is written into a quoted
// challenge.
func parseScope(val Value) (string, error) {
	raw := val.Given.raw()
	if !isScopeToken(raw) {
		return "", refusedForm(val, whole, raw, "one scope token, such as mcp", scopeCharsReason)
	}
	return raw, nil
}

// isScopeToken reports whether s is a scope token (RFC 6749 §3.3): printable ASCII but a space, a
// double quote or a backslash, and not empty.
func isScopeToken(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e || r == '"' || r == '\\' })
}

// scopeCharsReason is the reason a value is not a scope token.
const scopeCharsReason = "it has a character a scope token cannot hold: white space, a double quote, a backslash or one that is not printable ASCII"

// parseEntries splits val, a comma-separated list setting, into its entries, each with its place in
// the list. A value set but naming no entry, such as ",", is refused (listsNothing).
func parseEntries(val Value) ([]string, func(i int) entry, error) {
	raw := val.Given.raw()
	list := splitList(raw)
	if raw != "" && len(list) == 0 {
		return nil, nil, listsNothing(val)
	}
	return list, func(i int) entry { return entry{i, len(list)} }, nil
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

// entryCheck is what one entry of a list setting must be: want, as a refusal says it, and the
// reason an entry is not, or "".
type entryCheck struct {
	want   string
	reason func(entry string) string
}

// parseChecked reads a comma-separated list setting whose every entry check takes. A value that looks
// like a secret never reaches it: validate refuses it first (parseSecretKinds).
func parseChecked(val Value, check entryCheck) ([]string, []error) {
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	var errs []error
	for i, e := range list {
		if reason := check.reason(e); reason != "" {
			errs = append(errs, refusedForm(val, at(i), e, check.want, reason))
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return list, nil
}

// guidsOf is a list of GUIDs: tenant IDs, Entra group object IDs, application (client) IDs.
func guidsOf(what string) entryCheck {
	return entryCheck{what + ", each a GUID such as 00000000-0000-0000-0000-000000000000", guidReason}
}

// guidReason is why s is not a GUID, or "": a domain name is named as one, the likely mistake.
func guidReason(s string) string {
	switch {
	case isGUID(s):
		return ""
	case validDomain(strings.ToLower(s)):
		return "it looks like a domain name, not a GUID"
	}
	return "it is not a GUID"
}

// names is a list of names a token carries, such as roles or groups: gate's name rule, at most 256
// bytes and no control character, a copy TestConfigsGateRulesAreGates keeps in step with gate's.
func names(what string) entryCheck {
	return entryCheck{what + ", each at most 256 bytes without control characters", func(s string) string {
		switch {
		case len(s) > 256:
			return "it is longer than 256 bytes"
		case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			return "it has a control character"
		}
		return ""
	}}
}

// appRoleValues is a list of Entra app role values, the roles claim, as Microsoft Graph defines an
// appRole's value (https://learn.microsoft.com/en-us/graph/api/resources/approle?view=graph-rest-1.0,
// value): "Must not exceed 120 characters in length. Allowed characters are : ! # $ % & ' ( ) * + , -
// . / : ; < = > ? @ [ ] ^ + _ ` { | } ~, and characters in the ranges 0-9, A-Z and a-z. Any other
// character, including the space character, aren't allowed. May not begin with `.`." So each is
// printable ASCII but for a space, " and \, which also keeps it within gate's 256-byte name rule.
var appRoleValues = entryCheck{"app role values, each at most 120 letters, digits or ASCII punctuation (no space, \" or \\), not starting with .", func(s string) string {
	switch { // the characters first: once each is ASCII, a byte is a character
	case strings.ContainsFunc(s, func(r rune) bool { return r <= 0x20 || r >= 0x7f || r == '"' || r == '\\' }):
		return "it has a character an app role value cannot hold"
	case len(s) > 120:
		return "it is longer than 120 characters"
	case strings.HasPrefix(s, "."):
		return "it starts with ."
	}
	return ""
}}

// domainNames is a list of domain names, as gate takes them: no @, no wildcards.
var domainNames = entryCheck{"domain names such as example.com, without @ or wildcards", func(s string) string {
	if validDomain(strings.ToLower(s)) {
		return ""
	}
	return "it is not a domain name"
}}

// validDomain is gate's domain rule: a host name of at least two labels, each of letters, digits
// and hyphens, no hyphen at either end. config keeps its own copy, as it keeps isGUID's: importing
// gate would bring idp and go-jose into config, and internal/host holds a different rule (ADR-0032's
// WHATWG host, which allows what a claim's domain does not). TestConfigsGateRulesAreGates, not
// review, keeps the two copies in step.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
