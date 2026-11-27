package logging

import (
	"regexp"
	"strconv"
	"strings"
)

// The catalogue of secret kinds (#657): what a value that is not a secret must never show, read as
// it is shown (ShownSecretKind, ShownListSecretKind).

// tokenPrefixes are the token prefixes vendors document, each with the class secretKind names. The
// list is closed: a secret with no documented prefix is a known gap (docs/security-posture.md).
var tokenPrefixes = []struct{ prefix, class string }{
	// GitHub's token formats:
	// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
	{"ghp_", "a GitHub token"},        // personal access token (classic)
	{"github_pat_", "a GitHub token"}, // fine-grained personal access token
	{"gho_", "a GitHub token"},        // OAuth access token
	{"ghu_", "a GitHub token"},        // user access token for a GitHub App
	{"ghs_", "a GitHub token"},        // installation access token for a GitHub App
	{"ghr_", "a GitHub token"},        // refresh token for a GitHub App
	// Slack's token types: https://docs.slack.dev/authentication/tokens
	{"xoxb-", "a Slack token"},      // bot token
	{"xoxp-", "a Slack token"},      // user token
	{"xapp-", "a Slack token"},      // app-level token
	{"xoxe.xapp-", "a Slack token"}, // rotating app-level token
	{"xwfp-", "a Slack token"},      // workflow token
}

// prefixAt is where a prefix starts a token: at the start of the text, or after a character that
// cannot be part of a word, so --token=ghp_… and "Bearer ghp_…" count and app-ghp_x does not. At
// least ten token characters must follow it, as every documented token's do (Slack's shortest
// example, a legacy user token, has 18), so prose naming a prefix, bare or as in "xoxb-style", is none.
const prefixAt = `(?:^|[^A-Za-z0-9_.-])`

var tokenPatterns = func() []struct {
	re    *regexp.Regexp
	class string
} {
	out := make([]struct {
		re    *regexp.Regexp
		class string
	}, len(tokenPrefixes))
	for i, p := range tokenPrefixes {
		out[i].re = regexp.MustCompile(prefixAt + regexp.QuoteMeta(p.prefix) + `[A-Za-z0-9][A-Za-z0-9_-]{9}`)
		out[i].class = p.class
	}
	return out
}()

// urlPassword is a URL with a password in its user part, such as postgres://user:pass@host/db. An
// empty password (user:@host) is none. A comma is a user part's character (RFC 3986's sub-delims);
// a list's entries never hold one, and are each read on their own (ShownListSecretKind). A " is
// none (RFC 3986 §3.2.1: userinfo is unreserved, pct-encoded, sub-delims and ":"), so the user name
// stops at one, and a JSON log line naming an origin and, later, an email is no URL with a password
// ({"url":"https://api.example","user":"bob@example.com"}); the password is still read past a ", so
// one a reader would mistake for a quote is still found (#657).
var urlPassword = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/@\s"]*:[^/@\s]+@`)

// keyValuePassword is a password given by its key, as connection strings do: Server=db;Password=x,
// libpq's host=db password=x, or a URL query's ?password=x. A " counts as a start too, as a value
// shown quoted (strconv.Quote) starts with one.
var keyValuePassword = regexp.MustCompile(`(?i)(?:^|[;\s?&,"])(?:password|pwd)\s*=`)

// passwordKind is the kind secretKind names for a connection string with a password.
const passwordKind = "a connection string with a password"

// jwtKind is the kind secretKind names for a compact JWS or JWE (HoldsJWT). A Bearer or Basic
// credential is no kind here: LooksSecret matches everyday wording such as "Basic tier", so it
// only decides how a value is shown, never whether it is accepted.
const jwtKind = "a JWT"

// secretKind names the kind of secret s holds, or is "" when it holds none: a token by a vendor's
// documented prefix, a connection string with a password, or a JWT.
func secretKind(s string) string {
	for _, p := range tokenPatterns {
		if p.re.MatchString(s) {
			return p.class
		}
	}
	if urlPassword.MatchString(s) || keyValuePassword.MatchString(s) {
		return passwordKind
	}
	if HoldsJWT(s) {
		return jwtKind
	}
	return ""
}

// goEscape is an escape strconv.Quote writes for a character that is not printable: a value that
// holds one is shown quoted, and the escape's letters must not join the token after it into a word.
// It is matched wherever it appears, quoted or not, which can only find more.
var goEscape = regexp.MustCompile(`\\(?:[abfnrtv\\"]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})`)

// percentEscape is one %XX, as a URL's path is shown; each is undone on its own, once, so a stray
// % elsewhere in the value never stops the others being read, and %255F reads as %5F.
var percentEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// ShownSecretKind is the secret's kind shown holds, read as a reader would, or "" when it holds
// none. Each Go escape is read once as a break between words, and once as a character that is
// neither a word's nor a separator (NUL), as an escape inside a URL's user part is a character of
// that part, user name or password, where a space would end it; each reading is checked as it is
// and with each percent-escape undone, an escaped space or control character to the reading's own
// character, as a Go escape is.
func ShownSecretKind(shown string) string {
	for _, escape := range []string{" ", "\x00"} {
		read := goEscape.ReplaceAllString(shown, escape)
		decoded := percentEscape.ReplaceAllStringFunc(read, func(e string) string {
			b, _ := strconv.ParseUint(e[1:], 16, 8)
			if b <= ' ' || b == 0x7f {
				return escape
			}
			return string([]byte{byte(b)})
		})
		for _, r := range []string{read, decoded} {
			if k := secretKind(r); k != "" {
				return k
			}
		}
	}
	return ""
}

// splitURLEntry is a list entry that is a URL's start up to a password a comma ended: scheme://X:Y,
// with no @ or / after the ://. Y is the password's first part.
var splitURLEntry = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/@\s]*:([^/@\s]*)$`)

// splitPassword reports whether a list's entries, as shown, hold a connection string whose password
// a comma split across two entries, which the list shows whole: an entry splitURLEntry matches with
// a Y that is neither empty nor a port (all digits), and a later entry with an @ before any /. A
// password of digits only, split by a comma, is not found (docs/security-posture.md).
func splitPassword(entries []string) bool {
	for i, e := range entries {
		m := splitURLEntry.FindStringSubmatch(strings.Trim(strings.TrimSpace(goEscape.ReplaceAllString(e, "\x00")), `"`))
		if m == nil || strings.Trim(m[1], "0123456789") == "" {
			continue
		}
		for _, later := range entries[i+1:] {
			if at := strings.IndexByte(later, '@'); at >= 0 && !strings.Contains(later[:at], "/") {
				return true
			}
		}
	}
	return false
}

// ShownListSecretKind is the secret's kind a comma-separated list shows, given its entries as shown,
// or "" when it shows none: an entry's kind (ShownSecretKind), each read on its own since no entry
// holds a comma, or a connection string whose password a comma split (splitPassword).
func ShownListSecretKind(entries []string) string {
	for _, e := range entries {
		if k := ShownSecretKind(e); k != "" {
			return k
		}
	}
	if splitPassword(entries) {
		return passwordKind
	}
	return ""
}
