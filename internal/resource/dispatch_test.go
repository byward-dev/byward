package resource

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
)

const testPrefix = "byw_"

// calls records which validator saw a token; each answers with its own name as the subject, or err.
type calls struct {
	name string
	got  *[]string
	err  error
}

func (c calls) Validate(_ context.Context, tok string) (Identity, error) {
	*c.got = append(*c.got, c.name)
	if c.err != nil {
		return Identity{}, c.err
	}
	return Identity{Subject: c.name}, nil
}

// The validator is chosen by the token's format alone (ADR-0022 §2): a refusal by the chosen one
// is final, the other never sees the token, and with app-only tokens off a JWT reaches nothing.
func TestTheValidatorIsChosenByFormatAndNeverFallsBack(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	for name, tc := range map[string]struct {
		tok       string
		appOn     bool
		sealedErr error
		appErr    error
		want      []string // validators called, in order
		wantErr   error
	}{
		"a proxy token":                         {tok: "byw_at_abc", appOn: true, want: []string{"sealed"}},
		"a refused proxy token is not a JWT":    {tok: "byw_at_abc", appOn: true, sealedErr: ErrInvalid, want: []string{"sealed"}, wantErr: ErrInvalid},
		"a proxy-prefixed JWT is a proxy token": {tok: "byw_" + jwt, appOn: true, sealedErr: ErrInvalid, want: []string{"sealed"}, wantErr: ErrInvalid},
		"a JWT":                                 {tok: jwt, appOn: true, want: []string{"app"}},
		"a refused JWT is not a proxy token":    {tok: jwt, appOn: true, appErr: ErrInvalid, want: []string{"app"}, wantErr: ErrInvalid},
		"a JWT with app-only tokens off":        {tok: jwt, wantErr: ErrInvalid},
		"two segments":                          {tok: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0", appOn: true, wantErr: ErrInvalid},
		"four segments":                         {tok: jwt + ".x", appOn: true, wantErr: ErrInvalid},
		"an empty segment":                      {tok: "eyJhbGciOiJSUzI1NiJ9..c2ln", appOn: true, wantErr: ErrInvalid},
		"padding is not base64url":              {tok: jwt + "=", appOn: true, wantErr: ErrInvalid},
		"anything else":                         {tok: "opaque", appOn: true, wantErr: ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			var got []string
			var app Validator
			if tc.appOn {
				app = calls{"app", &got, tc.appErr}
			}
			id, err := Dispatch(testPrefix, calls{"sealed", &got, tc.sealedErr}, app).Validate(context.Background(), tc.tok)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") || err != tc.wantErr {
				t.Fatalf("called %v, err %v; want %v, %v", got, err, tc.want, tc.wantErr)
			}
			if err == nil && id.Subject != tc.want[0] {
				t.Fatalf("identity from %s, want %s", id.Subject, tc.want[0])
			}
		})
	}
}

// Whatever the token, at most one validator sees it, and with app-only tokens off only the sealed
// one ever does.
func FuzzTheValidatorIsChosenByFormatAndNeverFallsBack(f *testing.F) {
	for _, s := range []string{"byw_at_x", "a.b.c", "byw_a.b.c", "", ".", "..", "a.b.c.d", "a.b=.c", "ey.ey.\x00"} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, tok string, appOn bool) {
		var got []string
		var app Validator
		if appOn {
			app = calls{"app", &got, ErrInvalid}
		}
		_, _ = Dispatch(testPrefix, calls{"sealed", &got, ErrInvalid}, app).Validate(context.Background(), tok)
		switch {
		case len(got) > 1:
			t.Fatalf("%q reached %v", tok, got)
		case len(got) == 1 && got[0] == "sealed" && !strings.HasPrefix(tok, testPrefix):
			t.Fatalf("%q without the prefix reached the sealed validator", tok)
		case len(got) == 1 && got[0] == "app" && (strings.HasPrefix(tok, testPrefix) || strings.Count(tok, ".") != 2):
			t.Fatalf("%q reached the app validator", tok)
		}
	})
}

type identityValidator struct {
	id  Identity
	err error
}

func (v identityValidator) Validate(context.Context, string) (Identity, error) { return v.id, v.err }

// A refusal's answer and audit record: a gate refusal of an app-only caller is 403
// insufficient_scope with a fixed description and no sign-in challenge (ADR-0014 §3 amendment);
// every other refusal keeps the 401 shapes. A *Rejection's own record replaces
// access_token_rejected.
func TestARefusalGetsItsStatusChallengeAndAuditRecord(t *testing.T) {
	forbidden := `Bearer error="insufficient_scope", error_description="` + descForbidden + `"`
	rejection := func(err error) error {
		return &Rejection{Err: err, Event: audit.Event{Name: audit.AppTokenRejected, Outcome: audit.Failure, Reason: "r"}}
	}
	for name, tc := range map[string]struct {
		err       error
		status    int
		challenge string
		code      string
		desc      string
		record    string
	}{
		"an app the gate refuses": {rejection(ErrForbidden), http.StatusForbidden, forbidden, "insufficient_scope", descForbidden, `"event":"app_token_rejected","outcome":"failure","reason":"r"`},
		"an expired app token":    {rejection(ErrExpired), http.StatusUnauthorized, challenge + `, error="invalid_token", error_description="` + descExpired + `"`, "invalid_token", descExpired, `"event":"app_token_rejected"`},
		"an invalid app token":    {rejection(ErrInvalid), http.StatusUnauthorized, challenge + `, error="invalid_token", error_description="` + descInvalid + `"`, "invalid_token", descInvalid, `"event":"app_token_rejected"`},
		"a bare forbidden":        {ErrForbidden, http.StatusForbidden, forbidden, "insufficient_scope", descForbidden, `"event":"access_token_rejected","outcome":"failure","reason":"forbidden"`},
	} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			rec := audit.New(slog.New(slog.NewJSONHandler(&out, nil)), nil, time.Now)
			r := httptest.NewRequest("POST", "/mcp", nil)
			r.Header.Set("Authorization", "Bearer a.b.c")
			w := serve(Guard(meta(), identityValidator{err: tc.err}, rec, reached), r)
			var body map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != tc.status || w.Header().Get("WWW-Authenticate") != tc.challenge || body["error"] != tc.code || body["error_description"] != tc.desc {
				t.Fatalf("%d %q %v", w.Code, w.Header().Get("WWW-Authenticate"), body)
			}
			if l := out.String(); !strings.Contains(l, tc.record) || strings.Count(l, `"event"`) != 1 {
				t.Fatalf("audit: %s, want one record with %s", l, tc.record)
			}
		})
	}
}

// An identity carrying a record (an app token's first use) has it written once, by the Guard, and
// the handler behind sees the identity without it.
func TestAnAdmittedIdentitysRecordIsWrittenAndNotPassedOn(t *testing.T) {
	var out strings.Builder
	rec := audit.New(slog.New(slog.NewJSONHandler(&out, nil)), nil, time.Now)
	id := Identity{Subject: "t:o", PrincipalType: PrincipalClient, Audit: &audit.Event{Name: audit.AppTokenAccepted, Outcome: audit.Success, UserKey: "t:o"}}
	var seen Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen, _ = IdentityFrom(r.Context()) })
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer a.b.c")
	serve(Guard(meta(), identityValidator{id: id}, rec, next), r)
	if strings.Count(out.String(), `"event":"app_token_accepted"`) != 1 || seen.Subject != "t:o" || seen.Audit != nil {
		t.Fatalf("audit %s, identity %+v", out.String(), seen)
	}
}
