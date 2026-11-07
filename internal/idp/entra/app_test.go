package entra

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const callerSecret = "caller-secret-value"

// appEnv is newEnv plus a headless caller registered at the fake, with roles on our app.
func appEnv(t *testing.T, roles []string, opts ...fakeidp.Option) (*env, fakeidp.Client) {
	t.Helper()
	caller := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{callerSecret}, ServicePrincipalID: fakeidp.NewGUID()}
	e := newEnv(t, Config{}, opts...)
	caller.AppRoles = map[string][]string{e.client.ID: roles}
	e.fake.Set(fakeidp.WithClient(caller))
	return e, caller
}

// The tokens the fake issues on client credentials, as Entra does: with a role assignment the app
// is returned with its roles; without one Entra still issues a token, with no roles, and the access
// gate is what refuses it (ADR-0022 Context); without the idtyp optional claim the token is not
// recognisably app-only and is refused.
func TestAnAppOnlyTokenFromClientCredentialsIsVerified(t *testing.T) {
	for name, tc := range map[string]struct {
		roles []string
		idtyp bool
		want  []string
		err   error
	}{
		"with a role":             {roles: []string{"MCP.Invoke"}, idtyp: true, want: []string{"MCP.Invoke"}},
		"without a role":          {idtyp: true},
		"without the idtyp claim": {roles: []string{"MCP.Invoke"}, err: idp.ErrNotAppOnly},
	} {
		t.Run(name, func(t *testing.T) {
			e, caller := appEnv(t, tc.roles, fakeidp.WithIDTypClaim(tc.idtyp))
			app, err := e.p.VerifyApp(context.Background(), e.fake.AppToken(t, caller.ID, callerSecret, e.client.ID))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := idp.App{Tenant: e.fake.TenantID(), ObjectID: caller.ServicePrincipalID, ClientID: caller.ID}
			if app.Tenant != want.Tenant || app.ObjectID != want.ObjectID || app.ClientID != want.ClientID || strings.Join(app.Roles, ",") != strings.Join(tc.want, ",") ||
				app.TokenID == "" || !app.Expiry.After(app.IssuedAt) || app.Key() != want.Tenant+":"+want.ObjectID {
				t.Fatalf("app = %+v, want %+v with roles %v", app, want, tc.want)
			}
		})
	}
}

// Every check of ADR-0022 §3, one broken per row; the good token passes.
func TestAnAppOnlyTokenFailingAnyCheckIsRefused(t *testing.T) {
	e, caller := appEnv(t, []string{"MCP.Invoke"})
	tid, sp := e.fake.TenantID(), caller.ServicePrincipalID
	good := map[string]any{"iss": issuerFor(tid), "aud": e.client.ID, "tid": tid, "oid": sp, "sub": sp, "azp": caller.ID, "ver": "2.0",
		"idtyp": "app", "roles": []string{"MCP.Invoke"}, "uti": "abc", "iat": now().Unix(), "nbf": now().Unix(), "exp": now().Add(time.Hour).Unix()}
	// with is good with the claims kv (pairs; a nil value removes the claim).
	with := func(kv ...any) map[string]any {
		c := maps.Clone(good)
		for i := 0; i < len(kv); i += 2 {
			if k := kv[i].(string); kv[i+1] == nil {
				delete(c, k)
			} else {
				c[k] = kv[i+1]
			}
		}
		return c
	}
	other := fakeidp.NewGUID()
	for name, tc := range map[string]struct {
		alg, typ string
		claims   map[string]any
		err      error // nil: refused as invalid; errIsOK: accepted
	}{
		"the good token":            {claims: good, err: errIsOK},
		"upper-case GUIDs":          {claims: with("oid", strings.ToUpper(sp), "azp", strings.ToUpper(caller.ID), "tid", strings.ToUpper(tid)), err: errIsOK},
		"aud as a one-entry array":  {claims: with("aud", []string{e.client.ID}), err: errIsOK},
		"exp within the leeway":     {claims: with("exp", now().Add(-idp.Leeway+time.Second).Unix()), err: errIsOK},
		"PS256":                     {alg: "PS256", claims: good},
		"typ at+jwt":                {typ: "at+jwt", claims: good},
		"no typ":                    {typ: "-", claims: good},
		"another tenant's issuer":   {claims: with("iss", issuerFor(other))},
		"another tenant":            {claims: with("tid", other)},
		"a v1 token":                {claims: with("ver", "1.0")},
		"another audience":          {claims: with("aud", other)},
		"two audiences":             {claims: with("aud", []string{e.client.ID, other})},
		"no audience":               {claims: with("aud", nil)},
		"expired":                   {claims: with("exp", now().Add(-idp.Leeway).Unix()), err: idp.ErrAppTokenExpired},
		"no exp":                    {claims: with("exp", nil)},
		"iat in the future":         {claims: with("iat", now().Add(time.Minute).Unix())},
		"no iat":                    {claims: with("iat", nil)},
		"not yet valid":             {claims: with("nbf", now().Add(time.Minute).Unix())},
		"a delegated token's idtyp": {claims: with("idtyp", "user"), err: idp.ErrNotAppOnly},
		"no idtyp":                  {claims: with("idtyp", nil), err: idp.ErrNotAppOnly},
		"scp present":               {claims: with("scp", "access_as_user"), err: idp.ErrNotAppOnly},
		"an empty scp":              {claims: with("scp", ""), err: idp.ErrNotAppOnly},
		"oid not a GUID":            {claims: with("oid", "app", "sub", "app")},
		"sub not the oid":           {claims: with("sub", other)},
		"azp not a GUID":            {claims: with("azp", "")},
		"roles not an array":        {claims: with("roles", "MCP.Invoke")},
		"roles holding a number":    {claims: with("roles", []any{"MCP.Invoke", 1})},
	} {
		t.Run(name, func(t *testing.T) {
			alg, typ := tc.alg, tc.typ
			if alg == "" {
				alg = "RS256"
			}
			switch typ {
			case "":
				typ = "JWT"
			case "-":
				typ = ""
			}
			app, err := e.p.VerifyApp(context.Background(), e.fake.MintWithHeader(alg, typ, tc.claims))
			switch {
			case tc.err == errIsOK:
				// GUIDs come back in lower case, as user keys are stored.
				if err != nil || app.ObjectID != sp || app.ClientID != caller.ID || app.Tenant != tid {
					t.Fatalf("app = %+v, %v; want %s:%s for %s", app, err, tid, sp, caller.ID)
				}
			case err == nil:
				t.Fatal("accepted")
			case tc.err != nil && !errors.Is(err, tc.err):
				t.Fatalf("err = %v, want %v", err, tc.err)
			case tc.err == nil && (errors.Is(err, idp.ErrAppTokenExpired) || errors.Is(err, idp.ErrNotAppOnly)):
				t.Fatalf("err = %v, want a plain refusal", err)
			}
		})
	}
}

// errIsOK marks a table row the verifier must accept.
var errIsOK = errors.New("accepted")

// A delegated token for our own access_as_user scope, as a signed-in user's MCP client would hold,
// is never an app-only token.
func TestAUsersAccessAsUserTokenIsNotAnAppOnlyToken(t *testing.T) {
	e, _ := appEnv(t, nil)
	_, toks, err := callback(t, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.VerifyApp(context.Background(), toks.AccessToken); !errors.Is(err, idp.ErrNotAppOnly) {
		t.Fatalf("err = %v, want ErrNotAppOnly", err)
	}
}

// An unreachable JWKS is reported as such, so the operator can tell an outage from bad tokens.
func TestAnUnreachableJWKSIsReportedAsKeysUnavailableNotAsABadToken(t *testing.T) {
	e, caller := appEnv(t, []string{"MCP.Invoke"})
	raw := e.fake.AppToken(t, caller.ID, callerSecret, e.client.ID)
	e.fake.Set(fakeidp.WithJWKSUnavailable(true))
	if _, err := e.p.VerifyApp(context.Background(), raw); !errors.Is(err, idp.ErrKeysUnavailable) {
		t.Fatalf("err = %v, want ErrKeysUnavailable", err)
	}
}
