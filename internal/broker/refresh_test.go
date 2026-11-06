package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/token"
)

// grace is the window the rotation tests use, the refresh-grace setting's default.
const grace = 30 * time.Second

// offline signs in with offline_access and returns the token response.
func (e *env) offline(t *testing.T) map[string]any {
	t.Helper()
	code := e.signIn(t, url.Values{"scope": {"mcp offline_access"}}).Query().Get("code")
	res, body := e.redeem(t, code, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("redeem: %d %v", res.StatusCode, body)
	}
	return body
}

// refresh posts grant_type=refresh_token for client (clientID if empty).
func (e *env) refresh(t *testing.T, rt, client string) (*http.Response, map[string]any) {
	t.Helper()
	if client == "" {
		client = clientID
	}
	res := e.do(t, "POST", "/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}}, nil)
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func (e *env) revokeToken(t *testing.T, tok, client string) *http.Response {
	t.Helper()
	return e.do(t, "POST", "/revoke", url.Values{"token": {tok}, "client_id": {client}}, nil)
}

// valid reports whether the access token passes the validator with the broker's deny list, synced
// at the test's current time (it fails closed when stale).
func (e *env) valid(t *testing.T, access string) bool {
	t.Helper()
	if err := e.b.Deny().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, err := token.NewValidator(e.sealer, e.b.Deny(), func() time.Time { return e.now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Validate(context.Background(), access)
	return err == nil
}

// validNow validates without syncing the deny list first, so only revocations this replica
// made itself (the immediate local add) can refuse the token. The list must still be fresh at
// the test's current time, or every token would be refused for the wrong reason.
func (e *env) validNow(t *testing.T, access string) bool {
	t.Helper()
	if _, err := e.b.Deny().Denied("", "", time.Time{}); err != nil {
		t.Fatalf("deny list is stale (%v): sync it before checking a local revocation", err)
	}
	v, err := token.NewValidator(e.sealer, e.b.Deny(), func() time.Time { return e.now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Validate(context.Background(), access)
	return err == nil
}

func (e *env) grantGone(t *testing.T, id string) bool {
	t.Helper()
	_, err := e.st.Store.Grant(context.Background(), id)
	return errors.Is(err, store.ErrNotFound)
}

func wantOAuthError(t *testing.T, res *http.Response, body map[string]any, status int, code string) {
	t.Helper()
	if res.StatusCode != status || body["error"] != code {
		t.Fatalf("got %d %v, want %d %s", res.StatusCode, body, status, code)
	}
}

func TestOfflineAccessIssuesARefreshTokenAndExtendsTheGrant(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	rt, _ := body["refresh_token"].(string)
	if !strings.HasPrefix(rt, token.RefreshPrefix) || !strings.Contains(body["scope"].(string), "offline_access") {
		t.Fatalf("token response %v: want a refresh token and offline_access", body)
	}
	g, err := e.st.Grant(context.Background(), firstGrant(e.st))
	if err != nil || !g.ExpiresAt.Equal(e.now.Add(GrantLifetime)) {
		t.Fatalf("grant %+v, %v: want it to live GrantLifetime after redemption", g, err)
	}
}

func TestWithoutOfflineAccessThereIsNoRefreshTokenAndTheGrantEndsWithTheAccessToken(t *testing.T) {
	e := newEnv(t)
	_, body := e.redeem(t, e.signIn(t, nil).Query().Get("code"), nil)
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("token response %v: no refresh token without offline_access", body)
	}
	if g, _ := e.st.Grant(context.Background(), firstGrant(e.st)); !g.ExpiresAt.Equal(e.now.Add(AccessLifetime)) {
		t.Fatalf("grant expires %v, want with the access token", g.ExpiresAt)
	}
}

func TestAbandonedLoginLeavesOnlyAShortLivedGrant(t *testing.T) {
	e := newEnv(t)
	e.signIn(t, url.Values{"scope": {"mcp offline_access"}}) // the code is never redeemed
	if g, _ := e.st.Grant(context.Background(), firstGrant(e.st)); !g.ExpiresAt.Equal(e.now.Add(LoginLifetime)) {
		t.Fatalf("unredeemed grant expires %v, want LoginLifetime after the callback", g.ExpiresAt)
	}
}

func TestRefreshRotatesAndKeepsWorking(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RefreshGrace = grace })
	rt := e.offline(t)["refresh_token"].(string)
	for i := range 3 {
		e.now = e.now.Add(time.Hour)
		res, body := e.refresh(t, rt, "")
		if res.StatusCode != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("refresh %d: %d %v", i, res.StatusCode, body)
		}
		next := body["refresh_token"].(string)
		if next == rt || !e.valid(t, body["access_token"].(string)) {
			t.Fatalf("refresh %d: want a new refresh token and a valid access token", i)
		}
		rt = next
	}
}

func TestRetryWithinGraceSucceedsAndReuseAfterGraceRevokes(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RefreshGrace = grace })
	body := e.offline(t)
	grant := firstGrant(e.st)
	rt1 := body["refresh_token"].(string)
	res, first := e.refresh(t, rt1, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", res.StatusCode, first)
	}
	// The response was lost; the client retries with the old token inside the window.
	e.now = e.now.Add(grace - time.Second)
	res, retried := e.refresh(t, rt1, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("retry within grace: %d %v", res.StatusCode, retried)
	}
	// Outside the window, the old token is a stolen copy: the grant goes.
	e.now = e.now.Add(2 * time.Second)
	if err := e.b.Deny().Sync(context.Background()); err != nil { // fresh before the reuse, so only it can deny
		t.Fatal(err)
	}
	res, reuse := e.refresh(t, rt1, "")
	wantOAuthError(t, res, reuse, http.StatusBadRequest, "invalid_grant")
	if !e.grantGone(t, grant) {
		t.Fatal("reuse after the grace window did not revoke the grant")
	}
	if e.validNow(t, retried["access_token"].(string)) {
		t.Fatal("access tokens of the revoked grant still validate on this replica")
	}
}

func TestRefreshIsBoundToItsClient(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	res, body := e.refresh(t, rt, otherClientID)
	wantOAuthError(t, res, body, http.StatusBadRequest, "invalid_grant")
	if e.grantGone(t, firstGrant(e.st)) {
		t.Fatal("another client presenting the token revoked the grant")
	}
	if res, _ := e.refresh(t, rt, ""); res.StatusCode != http.StatusOK {
		t.Fatal("the owner's token stopped working after another client tried it")
	}
}

func TestRefreshChecksItsInput(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	cases := []struct {
		name, rt, scope, resource string
		status                    int
		code, wantScope           string
	}{
		{"not one of ours", "garbage", "", "", http.StatusBadRequest, "invalid_grant", ""},
		{"unknown", token.RefreshPrefix + strings.Repeat("A", 43), "", "", http.StatusBadRequest, "invalid_grant", ""},
		{"wider scope", rt, "mcp admin", "", http.StatusBadRequest, "invalid_scope", ""},
		{"foreign resource", rt, "", "https://other.example/mcp", http.StatusBadRequest, "invalid_target", ""},
		{"narrower scope is allowed", rt, "mcp", "", http.StatusOK, "", "mcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tc.rt}, "client_id": {clientID}}
			if tc.scope != "" {
				f.Set("scope", tc.scope)
			}
			if tc.resource != "" {
				f.Set("resource", tc.resource)
			}
			res := e.do(t, "POST", "/token", f, nil)
			var body map[string]any
			_ = json.NewDecoder(res.Body).Decode(&body)
			if tc.status != http.StatusOK {
				wantOAuthError(t, res, body, tc.status, tc.code)
				return
			}
			if res.StatusCode != http.StatusOK || body["scope"] != tc.wantScope {
				t.Fatalf("got %d %v, want 200 with scope %q", res.StatusCode, body, tc.wantScope)
			}
		})
	}
}

func TestIdleExpiryOfRefreshTokens(t *testing.T) {
	t.Run("expires after RefreshIdleLifetime unused", func(t *testing.T) {
		e := newEnv(t)
		rt := e.offline(t)["refresh_token"].(string)
		e.now = e.now.Add(RefreshIdleLifetime)
		res, body := e.refresh(t, rt, "")
		wantOAuthError(t, res, body, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("use just inside the window starts a fresh one", func(t *testing.T) {
		e := newEnv(t)
		rt := e.offline(t)["refresh_token"].(string)
		e.now = e.now.Add(RefreshIdleLifetime - time.Second)
		res, body := e.refresh(t, rt, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("refresh inside the window: %d %v", res.StatusCode, body)
		}
		next := body["refresh_token"].(string)
		e.now = e.now.Add(RefreshIdleLifetime - time.Second) // a whole new window, used just in time
		if res, body := e.refresh(t, next, ""); res.StatusCode != http.StatusOK {
			t.Fatalf("the rotated token did not get a fresh window: %d %v", res.StatusCode, body)
		}
	})
	t.Run("never beyond the grant", func(t *testing.T) {
		e := newEnv(t)
		rt := e.offline(t)["refresh_token"].(string)
		g, _ := e.st.Store.Grant(context.Background(), firstGrant(e.st))
		g.ExpiresAt = e.now.Add(90 * time.Minute) // shorter than one idle window and than one access token after the refresh
		if err := e.st.UpdateGrant(context.Background(), g.ID, g.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(time.Hour)
		res, body := e.refresh(t, rt, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("refresh: %d %v", res.StatusCode, body)
		}
		next, _ := token.HashRefreshToken(body["refresh_token"].(string))
		got, err := e.st.Store.RefreshToken(context.Background(), next, e.now)
		if err != nil || !got.IdleExpiresAt.Equal(g.ExpiresAt) {
			t.Fatalf("rotated token %+v, %v: want its idle expiry capped at the grant's %v", got, err, g.ExpiresAt)
		}
		if exp := body["expires_in"].(float64); exp > (30 * time.Minute).Seconds() {
			t.Fatalf("expires_in %v: the access token outlives the grant, which ends in 30 min", exp)
		}
	})
	t.Run("an expired grant cannot refresh", func(t *testing.T) {
		e := newEnv(t)
		rt := e.offline(t)["refresh_token"].(string)
		g, _ := e.st.Store.Grant(context.Background(), firstGrant(e.st))
		if err := e.st.UpdateGrant(context.Background(), g.ID, e.now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(time.Minute) // the refresh token itself is still within its idle window
		res, body := e.refresh(t, rt, "")
		wantOAuthError(t, res, body, http.StatusBadRequest, "invalid_grant")
	})
}

func TestIdPEndingTheSessionRevokesTheGrant(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	e.fake.RevokeRefreshTokens()
	res, failed := e.refresh(t, body["refresh_token"].(string), "")
	wantOAuthError(t, res, failed, http.StatusBadRequest, "invalid_grant")
	if !e.grantGone(t, firstGrant(e.st)) || e.valid(t, body["access_token"].(string)) {
		t.Fatal("the IdP ended the session but the grant or its access token survived")
	}
}

func TestIdPOutageAnswers503AndKeepsTheRefreshToken(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	e.fake.Set(fakeidp.FailToken("refresh_token", &fakeidp.Failure{Status: http.StatusServiceUnavailable, Error: "temporarily_unavailable"}))
	res, body := e.refresh(t, rt, "")
	wantOAuthError(t, res, body, http.StatusServiceUnavailable, "temporarily_unavailable")
	if want := "refresh unavailable"; e.idpOps[len(e.idpOps)-1] != want {
		t.Fatalf("IdP observations = %v, want the last to be %q", e.idpOps, want)
	}
	e.fake.Set(fakeidp.FailToken("refresh_token", nil))
	if res, body := e.refresh(t, rt, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("after the outage the refresh token was spent: %d %v", res.StatusCode, body)
	}
}

func TestStoreOutageAnswers503WithRetryAfter(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	e.st.down.Store(true)
	res, failed := e.refresh(t, body["refresh_token"].(string), "")
	wantOAuthError(t, res, failed, http.StatusServiceUnavailable, "temporarily_unavailable")
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	if r := e.revokeToken(t, body["refresh_token"].(string), clientID); r.StatusCode != http.StatusServiceUnavailable || r.Header.Get("Retry-After") == "" {
		t.Fatalf("revoke during a store outage: %d, want 503 with Retry-After (never a false 200)", r.StatusCode)
	}
}

// refresherFunc replaces the IdP adapter's Refresh, for identities the fake IdP cannot produce.
type refresherFunc struct {
	IdP
	refresh func(context.Context, string) (*idp.Identity, idp.Tokens, error)
}

func (r refresherFunc) Refresh(ctx context.Context, rt string) (*idp.Identity, idp.Tokens, error) {
	return r.refresh(ctx, rt)
}

type gateFunc func(context.Context, idp.Identity) error

func (g gateFunc) Allow(ctx context.Context, id idp.Identity) error { return g(ctx, id) }

func TestRefreshRevokesWhenTheUserNoLongerChecksOut(t *testing.T) {
	cases := []struct {
		name    string
		refresh func(g store.Grant) (*idp.Identity, idp.Tokens, error)
		gate    error
	}{
		{"no ID token on refresh", func(store.Grant) (*idp.Identity, idp.Tokens, error) { return nil, idp.Tokens{AccessToken: "a"}, nil }, nil},
		{"another subject", func(g store.Grant) (*idp.Identity, idp.Tokens, error) {
			return &idp.Identity{Subject: g.Subject + "-other", Issuer: g.Issuer}, idp.Tokens{AccessToken: "a"}, nil
		}, nil},
		{"another issuer", func(g store.Grant) (*idp.Identity, idp.Tokens, error) {
			return &idp.Identity{Subject: g.Subject, Issuer: "https://elsewhere.example"}, idp.Tokens{AccessToken: "a"}, nil
		}, nil},
		{"the gate refuses now", func(g store.Grant) (*idp.Identity, idp.Tokens, error) {
			return &idp.Identity{Subject: g.Subject, Issuer: g.Issuer}, idp.Tokens{AccessToken: "a"}, nil
		}, denial{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e *env
			var gateErr error // nil while signing in; tc.gate once the refresh runs
			called := false
			e = newEnv(t, func(c *Config) {
				c.IdP = refresherFunc{IdP: c.IdP, refresh: func(context.Context, string) (*idp.Identity, idp.Tokens, error) {
					called = true
					g, _ := e.st.Store.Grant(context.Background(), firstGrant(e.st))
					return tc.refresh(g)
				}}
				c.Gate = gateFunc(func(context.Context, idp.Identity) error { return gateErr })
			})
			body := e.offline(t)
			gateErr = tc.gate
			res, failed := e.refresh(t, body["refresh_token"].(string), "")
			wantOAuthError(t, res, failed, http.StatusBadRequest, "invalid_grant")
			if !called {
				t.Fatal("the IdP was never asked: the grant failed for another reason")
			}
			if !e.grantGone(t, firstGrant(e.st)) {
				t.Fatal("grant survived")
			}
			e.oneAuditEvent(t, "grant_revoked", map[string]any{"outcome": "success", "client_id": clientID, "grant_id": firstGrant(e.st)})
			if denied := e.auditEvents(t, "access_denied"); (tc.gate != nil) != (len(denied) == 1) || len(denied) > 1 {
				t.Fatalf("access_denied records = %v, want one only when the gate refuses", denied)
			}
			if tc.gate != nil {
				e.oneAuditEvent(t, "access_denied", map[string]any{"outcome": "failure", "client_id": clientID,
					"grant_id": firstGrant(e.st), "user_key": "*", "idp": "entra", "reason": "role"})
			}
		})
	}
}

func TestIdPThatKeepsItsRefreshTokenStaysUsable(t *testing.T) {
	var e *env
	var seen []string
	e = newEnv(t, func(c *Config) {
		real := c.IdP
		c.IdP = refresherFunc{IdP: real, refresh: func(_ context.Context, rt string) (*idp.Identity, idp.Tokens, error) {
			seen = append(seen, rt)
			g, _ := e.st.Store.Grant(context.Background(), firstGrant(e.st))
			// Many IdPs answer a refresh without a new refresh token: the old one stays valid.
			return &idp.Identity{Subject: g.Subject, Issuer: g.Issuer}, idp.Tokens{AccessToken: "a", Expiry: e.now.Add(time.Hour)}, nil
		}}
	})
	rt := e.offline(t)["refresh_token"].(string)
	for i := range 2 {
		res, body := e.refresh(t, rt, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("refresh %d: %d %v", i, res.StatusCode, body)
		}
		rt = body["refresh_token"].(string)
	}
	if len(seen) != 2 || seen[0] == "" || seen[1] != seen[0] {
		t.Fatalf("IdP refresh tokens presented = %q, want the original one both times", seen)
	}
}

func TestUnusableStoredIdPTokensRevokeTheGrant(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	old, _ := token.HashRefreshToken(rt)
	next, nextHash := token.NewRefreshToken()
	g, _ := e.st.Store.Grant(context.Background(), firstGrant(e.st))
	if err := e.st.Store.RotateRefreshToken(context.Background(), store.RotateRequest{Old: old, Now: e.now, IdPTokens: []byte("not sealed"),
		Next: store.RefreshToken{Hash: nextHash, GrantID: g.ID, ClientID: clientID, CreatedAt: e.now, IdleExpiresAt: e.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	res, body := e.refresh(t, next, "")
	wantOAuthError(t, res, body, http.StatusBadRequest, "invalid_grant")
	if !e.grantGone(t, g.ID) {
		t.Fatal("a grant whose IdP tokens cannot be opened survived")
	}
}

func TestReuseReportedByTheStoreDeniesAtOnce(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	e.valid(t, body["access_token"].(string)) // a fresh list, before the reuse
	e.st.reuseOnRotate.Store(true)            // another replica won the race; nothing recorded yet
	res, failed := e.refresh(t, body["refresh_token"].(string), "")
	wantOAuthError(t, res, failed, http.StatusBadRequest, "invalid_grant")
	if e.validNow(t, body["access_token"].(string)) {
		t.Fatal("the grant's access token still validates on this replica after the store reported reuse")
	}
}

func TestRevokeEitherTokenEndsTheGrant(t *testing.T) {
	for _, which := range []string{"refresh_token", "access_token"} {
		t.Run(which, func(t *testing.T) {
			e := newEnv(t)
			body := e.offline(t)
			e.valid(t, body["access_token"].(string)) // a fresh list, before the revocation
			if res := e.revokeToken(t, body[which].(string), clientID); res.StatusCode != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("revoke: %d", res.StatusCode)
			}
			if !e.grantGone(t, firstGrant(e.st)) {
				t.Fatal("grant survived revocation")
			}
			if e.validNow(t, body["access_token"].(string)) {
				t.Fatal("the access token still validates on this replica before any sync")
			}
			res, failed := e.refresh(t, body["refresh_token"].(string), "")
			wantOAuthError(t, res, failed, http.StatusBadRequest, "invalid_grant")
		})
	}
}

func TestRevokeAnswers200ForWhatIsNotARevocableToken(t *testing.T) {
	e := newEnv(t)
	revoked := e.offline(t)["refresh_token"].(string)
	if res := e.revokeToken(t, revoked, clientID); res.StatusCode != http.StatusOK {
		t.Fatalf("first revoke: %d", res.StatusCode)
	}
	cases := []struct{ name, tok string }{
		{"garbage", "garbage"},
		{"unknown refresh token", token.RefreshPrefix + strings.Repeat("A", 43)},
		{"malformed access token", token.AccessPrefix + "AAAA"},
		{"already revoked", revoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if res := e.revokeToken(t, tc.tok, clientID); res.StatusCode != http.StatusOK {
				t.Fatalf("revoke: %d, want 200 (RFC 7009 §2.2)", res.StatusCode)
			}
		})
	}
}

func TestRevokeAnswers503WhenRevokingFails(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	e.st.revokeDown.Store(true) // the lookup works, the revocation does not
	res := e.revokeToken(t, rt, clientID)
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Fatalf("revoke with a failing store write: %d, want 503 with Retry-After (never a false 200)", res.StatusCode)
	}
	if e.grantGone(t, firstGrant(e.st)) {
		t.Fatal("grant gone although the revocation failed")
	}
}

func TestRevokeRefusesAnotherClientsToken(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	res := e.revokeToken(t, body["refresh_token"].(string), otherClientID)
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	wantOAuthError(t, res, out, http.StatusBadRequest, "invalid_grant")
	if e.grantGone(t, firstGrant(e.st)) {
		t.Fatal("another client revoked the grant")
	}
}

func TestRevokeRefusesAMissingTokenAnUnknownClientAndGET(t *testing.T) {
	e := newEnv(t)
	res := e.do(t, "POST", "/revoke", url.Values{"client_id": {clientID}}, nil)
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	wantOAuthError(t, res, body, http.StatusBadRequest, "invalid_request")
	if res := e.revokeToken(t, "x", "nope"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown client: %d, want 401", res.StatusCode)
	}
	if res := e.do(t, "GET", "/revoke", nil, nil); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /revoke: %d, want 405", res.StatusCode)
	}
}

func TestMetadataAdvertisesRefreshAndRevocation(t *testing.T) {
	e := newEnv(t)
	res := e.do(t, "GET", "/.well-known/oauth-authorization-server", nil, nil)
	var md map[string]any
	_ = json.NewDecoder(res.Body).Decode(&md)
	asStrings := func(v any) []string {
		var out []string
		for _, s := range v.([]any) {
			out = append(out, s.(string))
		}
		slices.Sort(out)
		return out
	}
	if !slices.Contains(asStrings(md["grant_types_supported"]), "refresh_token") || md["revocation_endpoint"] != issuer+"/revoke" ||
		!slices.Equal(asStrings(md["revocation_endpoint_auth_methods_supported"]), []string{"none", "private_key_jwt"}) {
		t.Fatalf("metadata %v", md)
	}
}

// Another replica learns of a revocation through the store: its deny list refuses the grant's
// access tokens after its next sync.
func TestRevocationReachesAnotherReplicaThroughTheStore(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	other, err := New(e.cfg) // same store, its own deny list
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Deny().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.revokeToken(t, body["refresh_token"].(string), clientID)
	v, _ := token.NewValidator(e.sealer, other.Deny(), func() time.Time { return e.now })
	if _, err := v.Validate(context.Background(), body["access_token"].(string)); err != nil {
		t.Fatalf("before its sync the other replica already refuses: %v", err)
	}
	if err := other.Deny().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(context.Background(), body["access_token"].(string)); !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf("after its sync the other replica accepts a revoked token: %v", err)
	}
}

func TestRefreshGraceIsBounded(t *testing.T) {
	e := newEnv(t)
	for _, d := range []time.Duration{-time.Second, MaxRefreshGrace + time.Second} {
		t.Run(d.String(), func(t *testing.T) {
			cfg := e.cfg
			cfg.RefreshGrace = d
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRefreshIsAuditedAsATokenIssueAndObservedAsAnIdPCall(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	if res, body := e.refresh(t, rt, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", res.StatusCode, body)
	}
	issued := e.auditEvents(t, "token_issued")
	if len(issued) != 2 {
		t.Fatalf("token_issued records = %d, want 2 (the code redemption and the refresh)", len(issued))
	}
	wantFields(t, "token_issued", issued[1], map[string]any{"outcome": "success", "client_id": clientID,
		"grant_id": firstGrant(e.st), "user_key": issued[0]["user_key"]})
	if want := "refresh success"; len(e.idpOps) == 0 || e.idpOps[len(e.idpOps)-1] != want {
		t.Fatalf("IdP observations = %v, want the last to be %q", e.idpOps, want)
	}
	if strings.Contains(e.audit.String(), rt) || strings.Contains(e.audit.String(), token.RefreshPrefix) {
		t.Fatal("a refresh token reached the audit stream")
	}
}

// Both ways a reuse is caught, by the broker (outside the grace window) and by the store (a race
// another replica won), are audited as a revocation.
func TestRefreshTokenReuseIsAuditedAsARevocation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reuse func(t *testing.T, e *env, rt string)
	}{
		{"seen by the broker", func(t *testing.T, e *env, rt string) { e.refresh(t, rt, ""); e.refresh(t, rt, "") }},
		{"reported by the store", func(t *testing.T, e *env, rt string) { e.st.reuseOnRotate.Store(true); e.refresh(t, rt, "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.reuse(t, e, e.offline(t)["refresh_token"].(string))
			revoked := e.oneAuditEvent(t, "grant_revoked", map[string]any{"outcome": "success", "client_id": clientID, "grant_id": firstGrant(e.st)})
			if !strings.Contains(fmt.Sprint(revoked["reason"]), "refresh token reused") {
				t.Errorf("grant_revoked.reason = %v, want it to say the refresh token was reused", revoked["reason"])
			}
		})
	}
}

func TestClientRevocationIsAudited(t *testing.T) {
	e := newEnv(t)
	body := e.offline(t)
	if res := e.revokeToken(t, body["refresh_token"].(string), clientID); res.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", res.StatusCode)
	}
	e.oneAuditEvent(t, "grant_revoked", map[string]any{"outcome": "success", "client_id": clientID, "grant_id": firstGrant(e.st),
		"reason": "the client revoked a token (RFC 7009)"})
	if res := e.revokeToken(t, body["refresh_token"].(string), clientID); res.StatusCode != http.StatusOK {
		t.Fatalf("second revoke: %d", res.StatusCode)
	}
	if n := len(e.auditEvents(t, "grant_revoked")); n != 1 {
		t.Fatalf("grant_revoked records = %d after revoking an already revoked token, want still 1", n)
	}
}

// A gate that cannot decide (not a Denial) is a server error on refresh, as at sign-in: the grant
// and our refresh token survive, and nothing is audited as a denial. The IdP's new tokens are
// dropped, so an IdP with single-use refresh tokens makes the next refresh a sign-in again.
func TestGateFailureOnRefreshKeepsTheGrant(t *testing.T) {
	for _, tc := range []struct {
		name      string
		singleUse bool
		next      int
	}{
		{"IdP refresh token reusable", false, http.StatusOK},
		{"IdP refresh token single use", true, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gateErr error
			e := newEnv(t, func(c *Config) {
				c.Gate = gateFunc(func(context.Context, idp.Identity) error { return gateErr })
			})
			e.fake.Set(fakeidp.WithSingleUseRefreshTokens(tc.singleUse))
			rt := e.offline(t)["refresh_token"].(string)
			gateErr = errors.New("directory lookup failed")
			res, body := e.refresh(t, rt, "")
			wantOAuthError(t, res, body, http.StatusInternalServerError, "server_error")
			if e.grantGone(t, firstGrant(e.st)) {
				t.Fatal("a gate failure revoked the grant")
			}
			if n := len(e.auditEvents(t, "access_denied")) + len(e.auditEvents(t, "grant_revoked")); n != 0 {
				t.Fatalf("a gate failure was audited as a denial or revocation (%d records)", n)
			}
			gateErr = nil
			res, body = e.refresh(t, rt, "")
			if res.StatusCode != tc.next {
				t.Fatalf("refresh after the gate recovered: %d %v, want %d", res.StatusCode, body, tc.next)
			}
			if tc.singleUse && (body["error"] != "invalid_grant" || !e.grantGone(t, firstGrant(e.st))) {
				t.Fatalf("with a spent IdP refresh token: %v, want invalid_grant and the grant revoked (sign in again)", body)
			}
		})
	}
}
