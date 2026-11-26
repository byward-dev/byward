package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// A sub is a user key as OIDC Core 1.0 §2 allows an IdP to send one: at most 255 printable ASCII
// characters, never shaped like a credential. The subjects real IdPs issue are taken as they are,
// trimmed, case and all; a pasted token or credential is refused (#594).
func TestASubIsAtMost255PrintableASCIICharactersAndNeverACredential(t *testing.T) {
	long := strings.Repeat("a", MaxSubject)
	for name, key := range map[string]string{
		"Google, numeric":         "110169484474386276334",
		"Okta":                    "00u1abcd2EFGHijkl3m4",
		"Keycloak, a UUID":        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"Auth0, provider|id":      "auth0|5f7c8ec7c33c6c004bbafe82",
		"255 ASCII characters":    long,
		"with a space inside":     "user one",
		"printable ASCII symbols": "a!~#$%&'()*+,-./:;<=>?@[]^_`{|}",
		"case kept":               "F3A1-Alice",
	} {
		if got, ok := UserKey("sub", " "+key+" "); !ok || got != key {
			t.Errorf("%s: UserKey(sub, %q) = %q, %v; want it as given, trimmed", name, key, got, ok)
		}
	}
	for name, key := range map[string]string{
		"empty":                       "",
		"only spaces":                 "  ",
		"256 characters":              long + "a",
		"a compact JWS":               "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln",
		"a JWT cut short":             "eyJhbGciOiJub25lIn0.",
		"a Bearer credential":         "Bearer abc123",
		"a Basic credential":          "basic YTpi",
		"non-ASCII":                   "ålice",
		"a control character":         "a\x00b",
		"a control character first":   "\x00alice",
		"a control character last":    "alice\x00",
		"U+001F, the last C0 control": "a\x1fb",
		"a line break":                "alice\nbob",
		"DEL":                         "a\x7fb",
		"a full-width letter U+FF41":  "ａlice",
	} {
		if got, ok := UserKey("sub", key); ok {
			t.Errorf("%s: UserKey(sub, %q) = %q, accepted; want it refused", name, key, got)
		}
	}
}

// Any other subject claim (email, preferred_username, upn, name) holds what the IdP put there, so
// its user key is only trimmed, never empty and without a control character: a non-ASCII, long or
// credential-shaped value is a real user's, whom revoke-user must be able to revoke (#594).
func TestAnotherSubjectClaimsUserKeyIsAnyValueWithoutAControlCharacter(t *testing.T) {
	for _, tc := range []struct{ claim, key string }{
		{"email", "jöhn@exämple.com"},
		{"name", "José Núñez"},
		{"name", "Ann Basic Lee"},
		{"email", "heyJoe.Smith.Jr@example.com"},
		{"email", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"},
		{"preferred_username", strings.Repeat("a", MaxSubject+1)},
	} {
		if got, ok := UserKey(tc.claim, " "+tc.key+" "); !ok || got != tc.key {
			t.Errorf("UserKey(%s, %q) = %q, %v; want it as given, trimmed", tc.claim, tc.key, got, ok)
		}
	}
	for _, key := range []string{"", "  ", "a\x00b", "alice\nbob", "a\x7fb"} {
		if got, ok := UserKey("email", key); ok {
			t.Errorf("UserKey(email, %q) = %q, accepted; want it refused", key, got)
		}
	}
}

// Sign-in stores a subject only as revoke-user can name it (#594): an ID token whose sub OIDC Core
// forbids, or whose subject has surrounding white space, is refused as Fatal, and the value is never
// shown. Another claim's value signs in however it is written.
func TestSignInStoresOnlyASubjectRevokeUserCanName(t *testing.T) {
	const canary = "LK7CANARY"
	for name, sub := range map[string]string{
		"256 characters":          strings.Repeat("a", MaxSubject) + canary,
		"a compact JWS":           "eyJhbGciOiJSUzI1NiJ9." + canary + ".c2ln",
		"non-ASCII":               "å" + canary,
		"surrounding white space": " " + canary,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{}, fakeidp.WithUser(fakeidp.User{Subject: sub}))
			_, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
			var ie *idp.Error
			if !errors.As(err, &ie) || ie.Class != idp.Fatal || strings.Contains(err.Error(), canary) {
				t.Fatalf("err = %v, want a Fatal IdP error that does not show the sub", err)
			}
		})
	}
	for _, email := range []string{"jöhn@exämple.com", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"} {
		e := newEnv(t, Config{SubjectClaim: "email"}, fakeidp.WithUser(fakeidp.User{Email: email}))
		if id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login); err != nil || id.Subject != email {
			t.Errorf("email %q: subject %q, err %v; want it signed in as given", email, id.Subject, err)
		}
	}
}
