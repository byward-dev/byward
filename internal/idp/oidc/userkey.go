package oidc

import (
	"strings"
	"unicode"
)

// MaxSub is the longest sub an IdP may send. OIDC Core 1.0 §2: "It MUST NOT exceed 255 ASCII
// [RFC20] characters in length. The sub value is a case-sensitive string."
const MaxSub = 255

// UserKey is the user key s names under p's subject claim (BYWARD_OIDC_SUBJECT_CLAIM), and whether s
// is one. Sign-in stores a subject only as UserKey returns it, and revoke-user takes an operator's
// key through it, so revoke-user accepts exactly the keys sign-in can store (#594).
func (p *Provider) UserKey(s string) (string, bool) { return userKey(p.cfg.SubjectClaim, s) }

// userKey is s as a user key under claim: trimmed, never empty or with a control character, and as
// it is, case and all. A sub is also at most MaxSub characters of ASCII, as OIDC Core 1.0 §2 binds the
// IdP to send; any other claim (email, preferred_username, upn, name) may hold non-ASCII or longer
// values. Whether a key looks like a credential decides only how it is shown, never whether it is
// one: a sub such as eyJohn.Smith is a real user's (#594).
func userKey(claim, s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	if claim != "sub" {
		return s, true
	}
	if len(s) > MaxSub {
		return "", false
	}
	for i := range len(s) {
		if s[i] > 0x7e { // a control byte, DEL among them, is refused above
			return "", false
		}
	}
	return s, true
}
