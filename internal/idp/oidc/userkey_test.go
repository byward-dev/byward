package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const aJWS = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"

// A sub is a user key as OIDC Core 1.0 §2 allows an IdP to send one: at most 255 ASCII characters,
// without a control character, trimmed, case and all. A value shaped like a credential is within that
// rule, so it is a key: a sub such as eyJohn.Smith is a real user's (#594).
func TestASubIsAtMost255ASCIICharactersWithoutAControlCharacter(t *testing.T) {
	long := strings.Repeat("a", 255) // a literal: OIDC Core §2, not MaxSub
	for name, key := range map[string]string{
		"Google, numeric":              "110169484474386276334",
		"Okta":                         "00u1abcd2EFGHijkl3m4",
		"Keycloak, a UUID":             "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"Auth0, provider|id":           "auth0|5f7c8ec7c33c6c004bbafe82",
		"255 ASCII characters":         long,
		"with a space inside":          "user one",
		"printable ASCII symbols":      "a!~#$%&'()*+,-./:;<=>?@[]^_`{|}",
		"case kept":                    "F3A1-Alice",
		"a username shaped like a JWT": "eyJohn.Smith",
		"a username after Basic":       "Basic x",
		"a compact JWS":                aJWS,
		"a Bearer credential":          "Bearer abc123",
	} {
		if got, ok := userKey("sub", " "+key+" "); !ok || got != key {
			t.Errorf("%s: userKey(sub, %q) = %q, %v; want it as given, trimmed", name, key, got, ok)
		}
	}
	for name, key := range map[string]string{
		"empty":                          "",
		"only spaces":                    "  ",
		"256 characters":                 long + "a",
		"non-ASCII":                      "ålice",
		"non-ASCII last":                 "alicé",
		"a byte that is no UTF-8, first": "\xffalice",
		"a byte that is no UTF-8, last":  "alice\xff",
		"a control character":            "a\x00b",
		"a control character first":      "\x00alice",
		"a control character last":       "alice\x00",
		"U+001F, the last C0 control":    "a\x1fb",
		"a line break":                   "alice\nbob",
		"DEL":                            "a\x7fb",
		"a full-width letter U+FF41":     "ａlice",
	} {
		if got, ok := userKey("sub", key); ok {
			t.Errorf("%s: userKey(sub, %q) = %q, accepted; want it refused", name, key, got)
		}
	}
}

// Any other subject claim (email, preferred_username, upn, name) holds what the IdP put there, so
// its user key is only trimmed, never empty, valid UTF-8 and without a control character: a non-ASCII, long or
// credential-shaped value is a real user's, whom revoke-user must be able to revoke (#594).
func TestAnotherSubjectClaimsUserKeyIsAnyValueWithoutAControlCharacter(t *testing.T) {
	for _, tc := range []struct{ claim, key string }{
		{"email", "jöhn@exämple.com"},
		{"name", "José Núñez"},
		{"name", "Ann Basic Lee"},
		{"email", "heyJoe.Smith.Jr@example.com"},
		{"email", aJWS},
		{"preferred_username", strings.Repeat("a", 256)},
	} {
		if got, ok := userKey(tc.claim, " "+tc.key+" "); !ok || got != tc.key {
			t.Errorf("userKey(%s, %q) = %q, %v; want it as given, trimmed", tc.claim, tc.key, got, ok)
		}
	}
	for _, key := range []string{"", "  ", "a\x00b", "alice\nbob", "a\x7fb", "alice\xff", "\xffalice", "\u0080x", "a\u0085b", "a\u009fb"} {
		if got, ok := userKey("email", key); ok {
			t.Errorf("userKey(email, %q) = %q, accepted; want it refused", key, got)
		}
	}
}

// Sign-in refuses, as Fatal, an ID token whose subject revoke-user could not name (#594): a sub OIDC
// Core forbids, or a subject under any claim with white space at either end. Sign-in never strips it:
// " alice" and "alice" are two subs, and trimming one would merge them into one user. So a stored
// subject is always its own trimmed form, and revoke-user can trim what an operator pastes. The error
// names the claim and gives the value only by its length.
func TestSignInRefusesASubjectRevokeUserCouldNotNameAndDoesNotShowIt(t *testing.T) {
	const canary = "LK7CANARY"
	for name, tc := range map[string]struct{ claim, value, shown string }{
		"a sub longer than 255 characters": {"sub", strings.Repeat("a", 255) + canary, "sub claim (264 characters, not shown)"},
		"a non-ASCII sub":                  {"sub", "å" + canary, "sub claim (10 characters, not shown)"},
		"a sub with a space first":         {"sub", " alice" + canary, "sub claim (15 characters, not shown)"},
		"a sub with a newline last":        {"sub", "alice" + canary + "\n", "sub claim (15 characters, not shown)"},
		"an email with a space first":      {"email", " alice" + canary + "@example.com", "email claim (27 characters, not shown)"},
	} {
		t.Run(name, func(t *testing.T) {
			user, cfg := fakeidp.User{Subject: "f47ac10b-58cc-4372-a567-0e02b2c3d479"}, Config{}
			if tc.claim == "sub" {
				user.Subject = tc.value
			} else {
				user.Email, cfg.SubjectClaim = tc.value, tc.claim
			}
			e := newEnv(t, cfg, fakeidp.WithUser(user))
			_, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
			var ie *idp.Error
			if !errors.As(err, &ie) || ie.Class != idp.Fatal || strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), tc.shown) ||
				!strings.Contains(err.Error(), "at most 255 printable ASCII characters") {
				t.Fatalf("err = %v, want a Fatal IdP error naming the %q, not the value", err, tc.shown)
			}
		})
	}
}

// Sign-in takes any subject revoke-user can name as the IdP wrote it (#594): a sub shaped like a
// credential, and under another claim a non-ASCII or token-shaped value.
func TestSignInTakesASubjectRevokeUserCanNameAsWritten(t *testing.T) {
	for _, tc := range []struct{ claim, key string }{
		{"sub", "eyJohn.Smith"},
		{"sub", "Basic x"},
		{"sub", aJWS},
		{"email", "jöhn@exämple.com"},
		{"email", aJWS},
	} {
		t.Run(tc.claim+"/"+tc.key, func(t *testing.T) {
			user := fakeidp.User{Subject: "f47ac10b-58cc-4372-a567-0e02b2c3d479"}
			cfg := Config{}
			if tc.claim == "sub" {
				user.Subject = tc.key
			} else {
				user.Email, cfg.SubjectClaim = tc.key, tc.claim
			}
			e := newEnv(t, cfg, fakeidp.WithUser(user))
			if id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login); err != nil || id.Subject != tc.key {
				t.Errorf("subject %q, err %v; want it signed in as %q", id.Subject, err, tc.key)
			}
		})
	}
}
