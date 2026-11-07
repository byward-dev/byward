package apptoken

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/gate"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/resource"
)

const (
	tenant = "aaaaaaaa-1111-4111-8111-111111111111"
	sp     = "bbbbbbbb-2222-4222-8222-222222222222"
	caller = "cccccccc-3333-4333-8333-333333333333"
)

var t0 = time.Unix(1_800_000_000, 0)

// verifier returns its app, or err, for every token.
type verifier struct {
	app idp.App
	err error
}

func (v verifier) VerifyApp(context.Context, string) (idp.App, error) { return v.app, v.err }

// denyList cuts off subjects issued at or before their cut-off; err is a stale list.
type denyList struct {
	cutoffs map[string]time.Time
	err     error
}

func (d denyList) Denied(grantID, subject string, issuedAt time.Time) (bool, error) {
	if grantID != "" {
		return false, fmt.Errorf("an app has no grant, got %q", grantID)
	}
	c, ok := d.cutoffs[subject]
	return ok && !issuedAt.After(c), d.err
}

func goodApp() idp.App {
	return idp.App{Tenant: tenant, ObjectID: sp, ClientID: caller, Roles: []string{"MCP.Invoke"}, TokenID: "uti-1", IssuedAt: t0, Expiry: t0.Add(time.Hour)}
}

type fixture struct {
	v        *Validator
	outcomes []string
}

func newFixture(t *testing.T, ver verifier, deny denyList) *fixture {
	t.Helper()
	g, err := gate.NewApp(gate.AppRules{Roles: []string{"MCP.Invoke"}, ClientIDs: []string{caller}, Tenants: []string{tenant}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{}
	f.v, err = New(Config{Verifier: ver, Gate: g, Deny: deny, IdP: "entra", Count: func(o string) { f.outcomes = append(f.outcomes, o) }, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// An admitted app is a client principal keyed tid:oid, with its application ID and roles.
func TestAnAdmittedAppIsAClientPrincipal(t *testing.T) {
	f := newFixture(t, verifier{app: goodApp()}, denyList{})
	id, err := f.v.Validate(context.Background(), "jwt")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != tenant+":"+sp || id.ClientID != caller || id.PrincipalType != resource.PrincipalClient || len(id.Roles) != 1 || id.Roles[0] != "MCP.Invoke" ||
		id.Groups != nil || id.Email != "" || id.Name != "" {
		t.Fatalf("identity = %+v", id)
	}
	if fmt.Sprint(f.outcomes) != "[accepted]" {
		t.Fatalf("outcomes = %v", f.outcomes)
	}
}

// Every refusal: the status the client sees, the counted outcome, which is also the audit reason,
// and the caller named in the record only once its token verified.
func TestEveryRefusalIsCountedAndRecordedWithItsReason(t *testing.T) {
	app := goodApp()
	with := func(mod func(*idp.App)) verifier {
		a := goodApp()
		mod(&a)
		return verifier{app: a}
	}
	for name, tc := range map[string]struct {
		ver     verifier
		deny    denyList
		want    error
		outcome string
		named   bool
	}{
		"expired":                {ver: verifier{err: fmt.Errorf("wrapped: %w", idp.ErrAppTokenExpired)}, want: resource.ErrExpired, outcome: Expired},
		"a delegated token":      {ver: verifier{err: idp.ErrNotAppOnly}, want: resource.ErrInvalid, outcome: Delegated},
		"the keys unavailable":   {ver: verifier{err: fmt.Errorf("x: %w", idp.ErrKeysUnavailable)}, want: resource.ErrInvalid, outcome: KeysUnavailable},
		"a bad signature":        {ver: verifier{err: errors.New("idp: JWT signature")}, want: resource.ErrInvalid, outcome: Invalid},
		"no role":                {ver: with(func(a *idp.App) { a.Roles = nil }), want: resource.ErrForbidden, outcome: "denied_role", named: true},
		"another client":         {ver: with(func(a *idp.App) { a.ClientID = sp }), want: resource.ErrForbidden, outcome: "denied_client", named: true},
		"another tenant":         {ver: with(func(a *idp.App) { a.Tenant = sp }), want: resource.ErrForbidden, outcome: "denied_tenant", named: true},
		"revoked by revoke-user": {ver: verifier{app: app}, deny: denyList{cutoffs: map[string]time.Time{app.Key(): t0}}, want: resource.ErrInvalid, outcome: Revoked, named: true},
		"a stale deny list":      {ver: verifier{app: app}, deny: denyList{err: errors.New("stale")}, want: resource.ErrInvalid, outcome: DenyListStale, named: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.ver, tc.deny)
			_, err := f.v.Validate(context.Background(), "jwt")
			var rej *resource.Rejection
			if !errors.As(err, &rej) || !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want a rejection with %v", err, tc.want)
			}
			ev := rej.Event
			if ev.Name != audit.AppTokenRejected || ev.Outcome != audit.Failure || ev.Reason != tc.outcome || ev.IdP != "entra" {
				t.Fatalf("event = %+v, want app_token_rejected for %s", ev, tc.outcome)
			}
			wantKey, wantClient := "", ""
			if tc.named {
				wantKey, wantClient = tc.ver.app.Key(), tc.ver.app.ClientID
			}
			if ev.UserKey != wantKey || ev.ClientID != wantClient {
				t.Fatalf("event names %q for %q, want %q for %q", ev.UserKey, ev.ClientID, wantKey, wantClient)
			}
			if fmt.Sprint(f.outcomes) != "["+tc.outcome+"]" {
				t.Fatalf("outcomes = %v, want [%s]", f.outcomes, tc.outcome)
			}
		})
	}
}

// A revoke-user cut-off ends only tokens issued at or before it: the app's next token works.
func TestATokenIssuedAfterTheCutOffIsAccepted(t *testing.T) {
	app := goodApp()
	app.IssuedAt = t0.Add(time.Second)
	f := newFixture(t, verifier{app: app}, denyList{cutoffs: map[string]time.Time{app.Key(): t0}})
	if _, err := f.v.Validate(context.Background(), "jwt"); err != nil {
		t.Fatal(err)
	}
}

// The first use of each token is recorded, its later uses are not, and a token without an ID is
// recorded every time.
func TestATokensFirstUseIsAuditedOnce(t *testing.T) {
	ver := &switchable{app: goodApp()}
	g, _ := gate.NewApp(gate.AppRules{Roles: []string{"MCP.Invoke"}})
	v, _ := New(Config{Verifier: ver, Gate: g, Deny: denyList{}, IdP: "entra", Now: func() time.Time { return t0 }})
	audited := func() bool {
		id, err := v.Validate(context.Background(), "jwt")
		if err != nil {
			t.Fatal(err)
		}
		if id.Audit != nil && (id.Audit.Name != audit.AppTokenAccepted || id.Audit.UserKey != tenant+":"+sp || id.Audit.ClientID != caller || id.Audit.IdP != "entra") {
			t.Fatalf("audit = %+v", id.Audit)
		}
		return id.Audit != nil
	}
	if !audited() || audited() {
		t.Fatal("want the first use recorded and the second not")
	}
	ver.app.TokenID = "uti-2"
	if !audited() {
		t.Fatal("a new token's first use is not recorded")
	}
	ver.app.TokenID = ""
	for i := range 2 {
		if !audited() {
			t.Fatalf("use %d of a token without an ID is not recorded", i+1)
		}
	}
}

// A token is remembered until it expires, with the clock-skew leeway: a reuse just before is not
// recorded again, one after is (it would be a new first use of a token the IdP still honours).
func TestATokenIsRememberedUntilItExpiresWithTheLeeway(t *testing.T) {
	now := t0
	ver := &switchable{app: goodApp()}
	g, _ := gate.NewApp(gate.AppRules{Roles: []string{"MCP.Invoke"}})
	v, _ := New(Config{Verifier: ver, Gate: g, Deny: denyList{}, Now: func() time.Time { return now }})
	if !recorded(t, v) {
		t.Fatal("first use not recorded")
	}
	now = ver.app.Expiry.Add(idp.Leeway - time.Second)
	if recorded(t, v) {
		t.Fatal("a reuse within the leeway was recorded again")
	}
	now = ver.app.Expiry.Add(idp.Leeway)
	if !recorded(t, v) {
		t.Fatal("a reuse past expiry and leeway was not recorded")
	}
}

// fullValidator is a validator whose first-use set holds MaxTracked live tokens, all expiring at
// t0+1h, with the clock at *now; ver then presents a token that outlives them.
func fullValidator(t *testing.T, now *time.Time) (*Validator, *switchable) {
	t.Helper()
	ver := &switchable{app: goodApp()}
	g, _ := gate.NewApp(gate.AppRules{Roles: []string{"MCP.Invoke"}})
	v, _ := New(Config{Verifier: ver, Gate: g, Deny: denyList{}, Now: func() time.Time { return *now }})
	for i := range MaxTracked {
		ver.app.TokenID = fmt.Sprint("uti-", i)
		if id, _ := v.Validate(context.Background(), "jwt"); id.Audit == nil {
			t.Fatalf("token %d not recorded", i)
		}
	}
	ver.app.TokenID, ver.app.Expiry = "over-the-cap", t0.Add(2*time.Hour)
	return v, ver
}

// recorded validates one use, which must be admitted, and reports whether it was recorded.
func recorded(t *testing.T, v *Validator) bool {
	t.Helper()
	id, err := v.Validate(context.Background(), "jwt")
	if err != nil {
		t.Fatal(err)
	}
	return id.Audit != nil
}

// Past MaxTracked live tokens every use is recorded: more records, never fewer.
func TestPastTheTrackingCapEveryUseIsAudited(t *testing.T) {
	now := t0
	v, _ := fullValidator(t, &now)
	for i := range 3 {
		if !recorded(t, v) {
			t.Fatalf("use %d over the cap not recorded", i)
		}
	}
}

// A full set is swept at most once a second: a sweep just before the tracked tokens expire removes
// none, and just after they expire, under a second since that sweep, no sweep runs yet, so every
// use is still recorded;
// the next sweep removes them, and first uses are tracked again.
func TestAFullTrackingSetIsSweptAtMostOnceASecond(t *testing.T) {
	now := t0
	v, ver := fullValidator(t, &now)
	expiry := t0.Add(time.Hour).Add(idp.Leeway)
	now = expiry.Add(-500 * time.Millisecond)
	if !recorded(t, v) {
		t.Fatal("use over the cap not recorded")
	}
	now = expiry.Add(100 * time.Millisecond)
	for i := range 2 {
		if !recorded(t, v) {
			t.Fatalf("use %d before the next sweep not recorded", i)
		}
	}
	now = expiry.Add(2 * time.Second)
	ver.app.Expiry = now.Add(time.Hour)
	if !recorded(t, v) {
		t.Fatal("first use after the sweep not recorded")
	}
	if recorded(t, v) {
		t.Fatal("second use after the sweep recorded: expired tokens were not swept")
	}
}

type switchable struct{ app idp.App }

func (s *switchable) VerifyApp(context.Context, string) (idp.App, error) { return s.app, nil }

func TestAValidatorWithoutAVerifierGateOrDenyListRefusesToBuild(t *testing.T) {
	g, _ := gate.NewApp(gate.AppRules{Roles: []string{"r"}})
	for name, cfg := range map[string]Config{
		"no verifier":  {Gate: g, Deny: denyList{}},
		"no gate":      {Verifier: verifier{}, Deny: denyList{}},
		"no deny list": {Verifier: verifier{}, Gate: g},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
