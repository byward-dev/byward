package broker

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
)

// signedInClient is an MCP client signed in with offline_access: its client ID and redirect URI,
// the token response, and how to put the operator's denylist in front of it.
type signedInClient struct {
	e                  *env
	clientID, redirect string
	tokens             map[string]any
	deny               func(t *testing.T, entries ...string)
}

// A client the operator denies after it signed in loses its grant at its next refresh (#338): the
// refresh is refused, the grant is revoked and audited, and its access token stops working. A
// denied CIMD client ID is refused at lookup, so it gets 401; a client denied by its redirect host
// is still found, so it gets invalid_grant. A denylist that names another client changes nothing.
func TestADeniedClientLosesItsGrantAtRefresh(t *testing.T) {
	for name, tc := range map[string]struct {
		signIn  func(t *testing.T) signedInClient
		entry   func(clientID, redirect string) string
		status  int
		errCode string
	}{
		"DCR client, its redirect host":  {signIn: dcrSignedIn, entry: redirectHost, status: http.StatusBadRequest, errCode: "invalid_grant"},
		"DCR client, another host":       {signIn: dcrSignedIn, entry: func(string, string) string { return "other.example" }, status: http.StatusOK},
		"CIMD client, its client ID":     {signIn: cimdSignedIn, entry: func(id, _ string) string { return id }, status: http.StatusUnauthorized, errCode: "invalid_client"},
		"CIMD client, its redirect host": {signIn: cimdSignedIn, entry: redirectHost, status: http.StatusBadRequest, errCode: "invalid_grant"},
		"CIMD client, another client ID": {signIn: cimdSignedIn, entry: func(string, string) string { return "https://other.example/client.json" }, status: http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			c := tc.signIn(t)
			c.deny(t, tc.entry(c.clientID, c.redirect))
			res, body := c.e.refresh(t, c.tokens["refresh_token"].(string), c.clientID)
			if res.StatusCode != tc.status || tc.errCode != "" && body["error"] != tc.errCode {
				t.Fatalf("refresh after the denial: %d %v, want %d %s", res.StatusCode, body, tc.status, tc.errCode)
			}
			denied := tc.errCode != ""
			revocations := c.e.auditEvents(t, "grant_revoked")
			switch {
			case !denied && len(revocations) != 0:
				t.Fatalf("grant_revoked events %v, want none for a client the denylist does not name", revocations)
			case denied && len(revocations) != 1:
				t.Fatalf("grant_revoked events %v, want exactly one", revocations)
			case denied:
				ev := revocations[0]
				if ev["reason"] != "client on the operator's denylist; grant revoked" {
					t.Errorf("reason %q, want the documented denylist reason", ev["reason"])
				}
				if ev["client_id"] != c.clientID {
					t.Errorf("client_id %q, want %q", ev["client_id"], c.clientID)
				}
				if ev["grant_id"] == nil || ev["grant_id"] == "" {
					t.Errorf("grant_id missing: %v", ev)
				}
			}
			if got := c.e.valid(t, c.tokens["access_token"].(string)); got == denied {
				t.Fatalf("the access token issued before the denial passes: %v, want %v", got, !denied)
			}
		})
	}
}

// A denied client that presents another client's refresh token is refused as any other client
// would be, and revokes nothing: the token's own client keeps its grant (RFC 6749 §6).
func TestADeniedClientCannotRevokeAnotherClientsGrant(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	owner := dcrSignIn(t, e, "https://app.example/cb")
	denied := dcrSignIn(t, e, "https://evil.example/cb")
	owner.deny(t, "evil.example")
	rt := owner.tokens["refresh_token"].(string)
	if res, body := e.refresh(t, rt, denied.clientID); res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("the denied client presenting another client's refresh token: %d %v, want 400 invalid_grant", res.StatusCode, body)
	}
	if revocations := e.auditEvents(t, "grant_revoked"); len(revocations) != 0 {
		t.Fatalf("grant_revoked events %v, want none", revocations)
	}
	if res, body := e.refresh(t, rt, owner.clientID); res.StatusCode != http.StatusOK {
		t.Fatalf("the owner's refresh: %d %v, want 200", res.StatusCode, body)
	}
}

// redirectHost is the host of the client's redirect URI, as a denylist entry.
func redirectHost(_, redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		panic(err)
	}
	return u.Hostname()
}

// dcrSignedIn registers a DCR client in a new broker and signs a user in with it.
func dcrSignedIn(t *testing.T) signedInClient {
	t.Helper()
	return dcrSignIn(t, newEnv(t, withDCR(nil)), "https://app.example/cb")
}

// dcrSignIn registers a DCR client with the refresh_token grant and one redirect URI in e, and signs
// a user in with it.
func dcrSignIn(t *testing.T, e *env, redirect string) signedInClient {
	t.Helper()
	_, reg := e.register(t, `{"client_name":"App","redirect_uris":["`+redirect+`"],"grant_types":["authorization_code","refresh_token"]}`)
	id := reg["client_id"].(string)
	as := url.Values{"client_id": {id}, "redirect_uri": {redirect}, "scope": {"mcp offline_access"}}
	res, body := e.redeem(t, e.signIn(t, as).Query().Get("code"), url.Values{"client_id": {id}, "redirect_uri": {redirect}})
	if res.StatusCode != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("redeem: %d %v", res.StatusCode, body)
	}
	return signedInClient{e: e, clientID: id, redirect: redirect, tokens: body, deny: func(_ *testing.T, entries ...string) {
		e.b.cfg.Clients = registration.Chain{e.reg, newDCRFor(e.st, e.cfg.Now, entries...)}
	}}
}

// cimdSignedIn signs a user in with the claude.ai CIMD document and offline_access.
func cimdSignedIn(t *testing.T) signedInClient {
	t.Helper()
	d := clientdocs.Load(t, "claude-ai")
	srv := clientdocs.Serve(t, d)
	e := newEnv(t, withCIMD(srv))
	back := e.signIn(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
	res, body := e.redeem(t, back.Query().Get("code"), url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
	if res.StatusCode != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("redeem: %d %v", res.StatusCode, body)
	}
	return signedInClient{e: e, clientID: d.ClientID, redirect: d.Redirect, tokens: body, deny: func(t *testing.T, entries ...string) {
		deny, err := registration.NewDenylist(entries)
		if err != nil {
			t.Fatal(err)
		}
		e.b.cfg.Clients = registration.Chain{e.reg, newCIMDFor(srv, deny)}
	}}
}
