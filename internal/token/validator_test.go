package token

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/resource"
)

type denyFunc func(grantID, subject string, issuedAt time.Time) (bool, error)

func (f denyFunc) Denied(g, s string, iat time.Time) (bool, error) { return f(g, s, iat) }

var allowAll = denyFunc(func(string, string, time.Time) (bool, error) { return false, nil })

func newValidator(t *testing.T, s *Sealer, deny DenyList) *Validator {
	t.Helper()
	v, err := NewValidator(s, deny, nil)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Inside a synctest bubble time.Now starts at 2000-01-01 00:00:00 UTC and time.Sleep moves it
// instantly, so the edges below are exact.
func TestExpiryAndIssuedAtHonourTheLeeway(t *testing.T) {
	const leeway = 30 * time.Second // fixed by ADR-0014; not derived from the constant under test
	cases := []struct {
		name string
		iat  time.Duration // relative to now at seal time
		wait time.Duration // sleep before validating
		want error
	}{
		{"fresh", 0, 0, nil},
		{"at exp", 0, time.Hour, nil},
		{"at the end of the leeway", 0, time.Hour + leeway, nil},
		{"one second past the leeway", 0, time.Hour + leeway + time.Second, resource.ErrExpired},
		{"iat in the future within the leeway", leeway, 0, nil},
		{"iat in the future beyond the leeway", leeway + time.Second, 0, resource.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSealer(t)
				iat := time.Now().Add(tc.iat)
				tok := mustSeal(t, s, Access, Claims{GrantID: "g", Subject: "u", IssuedAt: iat, ExpiresAt: time.Now().Add(time.Hour), ClientID: "c"})
				time.Sleep(tc.wait)
				id, err := newValidator(t, s, allowAll).Validate(context.Background(), tok)
				if !errors.Is(err, tc.want) {
					t.Fatalf("Validate = %v, want %v", err, tc.want)
				}
				if err == nil && (id.Subject != "u" || id.GrantID != "g") {
					t.Fatalf("subject %q, grant %q: want the token's (the grant leads On-Behalf-Of to the stored IdP tokens)", id.Subject, id.GrantID)
				}
			})
		})
	}
}

func TestEveryOtherFailureIsInvalid(t *testing.T) {
	s := newSealer(t)
	other := sealerFor(t, mustRing(t, keyDir(t, map[string]string{"k1": randomKey(t)})), resourceA)
	now := t0.Add(time.Minute)
	v, err := NewValidator(s, allowAll, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"garbage":              "nope",
		"code, not access":     mustSeal(t, s, Code, claims()),
		"refresh token":        func() string { tok, _ := NewRefreshToken(); return tok }(),
		"another key, same ID": mustSeal(t, other, Access, claims()),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), tok); !errors.Is(err, resource.ErrInvalid) {
				t.Fatalf("Validate = %v, want resource.ErrInvalid", err)
			}
		})
	}
}

func TestDenyListIsConsultedAndFailsClosed(t *testing.T) {
	s := newSealer(t)
	tok := mustSeal(t, s, Access, claims())
	now := func() time.Time { return t0.Add(time.Minute) }
	cases := map[string]struct {
		deny DenyList
		want error
	}{
		"not denied": {allowAll, nil},
		"revoked":    {denyFunc(func(string, string, time.Time) (bool, error) { return true, nil }), resource.ErrInvalid},
		"stale list": {denyFunc(func(string, string, time.Time) (bool, error) { return false, errors.New("stale") }), resource.ErrInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var gotGrant, gotSubject string
			var gotIAT time.Time
			spy := denyFunc(func(g, sub string, iat time.Time) (bool, error) {
				gotGrant, gotSubject, gotIAT = g, sub, iat
				return tc.deny.Denied(g, sub, iat)
			})
			v, err := NewValidator(s, spy, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Validate(context.Background(), tok); !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
			if c := claims(); gotGrant != c.GrantID || gotSubject != c.Subject || !gotIAT.Equal(c.IssuedAt) {
				t.Fatalf("deny list asked about (%q, %q, %v)", gotGrant, gotSubject, gotIAT)
			}
		})
	}
}

func TestNewValidatorNeedsASealerAndADenyList(t *testing.T) {
	if _, err := NewValidator(nil, allowAll, nil); err == nil {
		t.Error("nil sealer accepted")
	}
	if _, err := NewValidator(newSealer(t), nil, nil); err == nil {
		t.Error("nil deny list accepted")
	}
}
