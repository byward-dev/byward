package oidc

import (
	"strings"
	"unicode"

	"github.com/byward-dev/byward/internal/logging"
)

// MaxSubject is the longest sub an IdP may send. OIDC Core 1.0 §2: "It MUST NOT exceed 255 ASCII
// [RFC20] characters in length. The sub value is a case-sensitive string."
const MaxSubject = 255

// UserKey is the user key s, for an IdP whose user key is claim (BYWARD_OIDC_SUBJECT_CLAIM): trimmed,
// never empty or with a control character, and as it is, case and all. Sign-in stores a subject
// only as UserKey returns it, and revoke-user takes an operator's key through it, so revoke-user
// accepts exactly the keys sign-in can store (#594).
//
// For sub, OIDC Core 1.0 §2 binds the IdP, so a sub is at most MaxSubject characters of printable
// ASCII, and never shaped like a credential (logging.LooksSecret), which no IdP issues as a sub: a
// token pasted as a key is refused. Any other claim (email, preferred_username, upn, name) may hold
// non-ASCII, longer or prose-like values, so only the rule above applies; a value LooksSecret
// matches there is a real user's, revoked but never shown.
func UserKey(claim, s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	if claim != "sub" {
		return s, true
	}
	if len(s) > MaxSubject || logging.LooksSecret(s) {
		return "", false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "", false
		}
	}
	return s, true
}

// UserKey is the package's UserKey for p's subject claim.
func (p *Provider) UserKey(s string) (string, bool) { return UserKey(p.cfg.SubjectClaim, s) }
