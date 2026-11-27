package broker

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/token"
)

// refusable is a broker whose CIMD client (the claude.ai document) can be refused at lookup in one
// of the two ways that end its grant, and let back in again.
type refusable struct {
	e      *env
	d      clientdocs.Doc
	refuse func()
	lift   func()
	reason string // the grant_revoked reason of this refusal
}

// The two refusals at lookup that end a CIMD client's grant: the operator denies its client ID
// (#338), or its metadata document is refused (draft -03 §6.1).
var refusals = map[string]func(t *testing.T) refusable{
	"client ID denied": func(t *testing.T) refusable {
		d := clientdocs.Load(t, "claude-ai")
		srv := clientdocs.Serve(t, d)
		e := newEnv(t, withCIMD(srv))
		before := e.b.cfg.Clients
		deny, err := registration.NewDenylist([]string{d.ClientID})
		if err != nil {
			t.Fatal(err)
		}
		denied := registration.Chain{e.reg, newCIMDFor(srv, deny)}
		return refusable{e: e, d: d, reason: "client on the operator's denylist; grant revoked",
			refuse: func() { e.b.cfg.Clients = denied },
			lift:   func() { e.b.cfg.Clients = before }}
	},
	"document refused": func(t *testing.T) refusable {
		e, d, mode := cimdEnv(t)
		return refusable{e: e, d: d, reason: "client metadata no longer valid",
			refuse: func() { mode.Store(modeRefused) },
			lift:   func() { mode.Store(modeOK) }}
	},
}

// signIn signs a user in with the CIMD client and offline_access, stopping at the code.
func (c refusable) signIn(t *testing.T) string {
	t.Helper()
	return c.e.signIn(t, url.Values{"client_id": {c.d.ClientID}, "redirect_uri": {c.d.Redirect}, "scope": {"mcp offline_access"}}).Query().Get("code")
}

// redeem redeems code as the CIMD client.
func (c refusable) redeem(t *testing.T, code string) (*http.Response, map[string]any) {
	t.Helper()
	return c.e.redeem(t, code, url.Values{"client_id": {c.d.ClientID}, "redirect_uri": {c.d.Redirect}})
}

// tokens redeems code as the CIMD client and fails unless it gets both tokens.
func (c refusable) tokens(t *testing.T, code string) map[string]any {
	t.Helper()
	res, tokens := c.redeem(t, code)
	if res.StatusCode != http.StatusOK || tokens["refresh_token"] == nil || tokens["access_token"] == nil {
		t.Fatalf("redeeming the code: %d %v, want 200 with both tokens", res.StatusCode, tokens)
	}
	return tokens
}

// revoke asks /revoke, as the CIMD client, to revoke tok.
func (c refusable) revoke(t *testing.T, tok any) (*http.Response, map[string]any) {
	t.Helper()
	s, ok := tok.(string)
	if !ok || s == "" {
		t.Fatalf("no token to revoke: %v", tok)
	}
	res := c.e.revokeToken(t, s, c.d.ClientID)
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

// wantInvalidClient fails unless what was answered 401 invalid_client with no token: the answer to a
// client refused at lookup.
func wantInvalidClient(t *testing.T, what string, res *http.Response, body map[string]any) {
	t.Helper()
	if res.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" || body["access_token"] != nil {
		t.Fatalf("%s: %d %v, want 401 invalid_client and no token", what, res.StatusCode, body)
	}
}

// onlyGrant is the ID of the one grant in the store.
func (c refusable) onlyGrant(t *testing.T) string {
	t.Helper()
	ids := c.e.st.GrantIDs()
	if len(ids) != 1 {
		t.Fatalf("grants %v, want exactly one", ids)
	}
	return ids[0]
}

// wantOneRevocation fails unless the audit stream has exactly one grant_revoked, for the CIMD
// client's grant, with the refusal's reason (c.reason), and that grant is gone from the store.
func (c refusable) wantOneRevocation(t *testing.T, grantID string) {
	t.Helper()
	revocations := c.e.auditEvents(t, "grant_revoked")
	if len(revocations) != 1 || revocations[0]["reason"] != c.reason || revocations[0]["client_id"] != c.d.ClientID || revocations[0]["grant_id"] != grantID {
		t.Fatalf("grant_revoked events %v, want one for grant %s of %s with the reason %q", revocations, grantID, c.d.ClientID, c.reason)
	}
	if !c.e.grantGone(t, grantID) {
		t.Fatalf("grant %s is still stored", grantID)
	}
}

// A sign-in under way when its client is refused at lookup gets no token, and /token revokes the
// grant behind its code (revoke-access.md, cimd.md), as a refresh by that client would; so does a
// code of its own that has expired or was already redeemed, and the refresh token it was redeemed
// for stops refreshing. An unspent code then never redeems, not even once the refusal is lifted:
// the grant it stands for is gone, so restoring the client cannot revive it.
func TestARefusedClientsCodeEndsItsGrantAndNeverRedeems(t *testing.T) {
	for name, newRefusable := range refusals {
		// before readies the code; it returns the tokens a spent code was redeemed for.
		for state, before := range map[string]func(t *testing.T, c refusable, code string) map[string]any{
			"an unspent code": func(*testing.T, refusable, string) map[string]any { return nil },
			"an expired code": func(_ *testing.T, c refusable, _ string) map[string]any {
				c.e.now = c.e.now.Add(CodeLifetime + time.Second)
				return nil
			},
			"a spent code": func(t *testing.T, c refusable, code string) map[string]any { return c.tokens(t, code) },
		} {
			t.Run(name+", "+state, func(t *testing.T) {
				c := newRefusable(t)
				code := c.signIn(t)
				grantID := c.onlyGrant(t)
				tokens := before(t, c, code)
				c.refuse()
				res, body := c.redeem(t, code)
				wantInvalidClient(t, "redeeming while refused", res, body)
				c.wantOneRevocation(t, grantID)
				c.lift()
				// Refresh the spent code's refresh token first: redeeming the spent code again below
				// would revoke a surviving grant as a reused code.
				if tokens != nil {
					if res, body := c.e.refresh(t, tokens["refresh_token"].(string), c.d.ClientID); res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
						t.Fatalf("refreshing the spent code's refresh token once the client is back: %d %v, want 400 invalid_grant", res.StatusCode, body)
					}
				}
				if res, body := c.redeem(t, code); res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" || body["access_token"] != nil {
					t.Fatalf("redeeming the same code once the client is back: %d %v, want 400 invalid_grant and no token", res.StatusCode, body)
				}
			})
		}
	}
}

// A client refused at lookup that asks /revoke to revoke its own refresh or access token, even an
// expired access token, is still answered 401 (RFC 7009 §2.1: it is not authenticated), but its
// grant ends as it asked and as its next refresh would end it: with the refusal's reason, an
// unexpired access token stops working and the refresh token does not refresh once the refusal is
// lifted.
func TestARefusedClientRevokingItsOwnTokenEndsItsGrant(t *testing.T) {
	for name, newRefusable := range refusals {
		for _, tc := range []struct {
			name, field string        // the subtest name; the token's field in the token response
			after       time.Duration // how long after the redemption it is revoked
		}{
			{"its refresh token", "refresh_token", 0},
			{"its access token", "access_token", 0},
			{"its expired access token", "access_token", AccessLifetime + token.Leeway + time.Second},
		} {
			t.Run(name+", "+tc.name, func(t *testing.T) {
				c := newRefusable(t)
				tokens := c.tokens(t, c.signIn(t))
				grantID := c.onlyGrant(t)
				c.e.now = c.e.now.Add(tc.after)
				c.refuse()
				res, body := c.revoke(t, tokens[tc.field])
				wantInvalidClient(t, "/revoke while refused", res, body)
				c.wantOneRevocation(t, grantID)
				if tc.after < AccessLifetime && c.e.valid(t, tokens["access_token"].(string)) {
					t.Fatal("the access token still passes after the revocation")
				}
				c.lift()
				if res, body := c.e.refresh(t, tokens["refresh_token"].(string), c.d.ClientID); res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
					t.Fatalf("refresh once the client is back: %d %v, want 400 invalid_grant", res.StatusCode, body)
				}
			})
		}
	}
}

// A refused client that refreshes another client's refresh token, redeems that client's code, or
// asks /revoke to revoke either of that client's tokens, revokes nothing: the refusal ends only the
// refused client's own grants, and the owner (the static client) still redeems its code and
// refreshes.
func TestARefusedClientCannotEndAnotherClientsGrant(t *testing.T) {
	type owned struct {
		code   string
		tokens map[string]any
	}
	for name, newRefusable := range refusals {
		for attempt, present := range map[string]func(t *testing.T, c refusable, o owned) (*http.Response, map[string]any){
			"refreshing the owner's refresh token": func(t *testing.T, c refusable, o owned) (*http.Response, map[string]any) {
				return c.e.refresh(t, o.tokens["refresh_token"].(string), c.d.ClientID)
			},
			"redeeming the owner's code": func(t *testing.T, c refusable, o owned) (*http.Response, map[string]any) {
				return c.redeem(t, o.code)
			},
			"revoking the owner's refresh token": func(t *testing.T, c refusable, o owned) (*http.Response, map[string]any) {
				return c.revoke(t, o.tokens["refresh_token"])
			},
			"revoking the owner's access token": func(t *testing.T, c refusable, o owned) (*http.Response, map[string]any) {
				return c.revoke(t, o.tokens["access_token"])
			},
		} {
			t.Run(name+", "+attempt, func(t *testing.T) {
				c := newRefusable(t)
				o := owned{code: c.e.signIn(t, nil).Query().Get("code")}
				var res *http.Response
				res, o.tokens = c.e.redeem(t, c.e.signIn(t, nil).Query().Get("code"), nil)
				if res.StatusCode != http.StatusOK || o.tokens["refresh_token"] == nil || o.tokens["access_token"] == nil {
					t.Fatalf("the owner's sign-in: %d %v, want 200 with both tokens", res.StatusCode, o.tokens)
				}
				c.refuse()
				res, body := present(t, c, o)
				wantInvalidClient(t, "the refused client "+attempt, res, body)
				if revocations := c.e.auditEvents(t, "grant_revoked"); len(revocations) != 0 {
					t.Fatalf("grant_revoked events %v, want none", revocations)
				}
				if res, body := c.e.redeem(t, o.code, nil); res.StatusCode != http.StatusOK {
					t.Fatalf("the owner redeeming its code: %d %v, want 200", res.StatusCode, body)
				}
				if res, body := c.e.refresh(t, o.tokens["refresh_token"].(string), ""); res.StatusCode != http.StatusOK {
					t.Fatalf("the owner's refresh: %d %v, want 200", res.StatusCode, body)
				}
			})
		}
	}
}
