package broker

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/token"
)

// signedInApp is an app signed in with offline_access: its client ID and redirect URI, the token
// response, and how to put the operator's denylist in front of it.
type signedInApp struct {
	e                  *env
	clientID, redirect string
	tokens             map[string]any
	deny               func(t *testing.T, entries ...string)
}

// A client the operator denies after it signed in loses its grant at its next refresh (#338): the
// refresh is refused, the grant is revoked and audited, and its access token stops working. A
// denied CIMD client ID is refused at lookup, so it gets 401; a client denied by its redirect host
// is still found, so it gets invalid_grant. A denylist that names another app changes nothing.
func TestADeniedClientLosesItsGrantAtRefresh(t *testing.T) {
	apps := map[string]func(t *testing.T) signedInApp{
		"DCR":  dcrSignedIn,
		"CIMD": cimdSignedIn,
	}
	for name, tc := range map[string]struct {
		app     string
		entry   func(clientID, redirect string) string
		status  int
		errCode string
	}{
		"DCR client, its redirect host":  {app: "DCR", entry: redirectHost, status: http.StatusBadRequest, errCode: "invalid_grant"},
		"DCR client, another host":       {app: "DCR", entry: func(string, string) string { return "other.example" }, status: http.StatusOK},
		"CIMD client, its client ID":     {app: "CIMD", entry: func(id, _ string) string { return id }, status: http.StatusUnauthorized, errCode: "invalid_client"},
		"CIMD client, its redirect host": {app: "CIMD", entry: redirectHost, status: http.StatusBadRequest, errCode: "invalid_grant"},
		"CIMD client, another client ID": {app: "CIMD", entry: func(string, string) string { return "https://other.example/client.json" }, status: http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			a := apps[tc.app](t)
			a.deny(t, tc.entry(a.clientID, a.redirect))
			res, body := a.e.refresh(t, a.tokens["refresh_token"].(string), a.clientID)
			if res.StatusCode != tc.status || tc.errCode != "" && body["error"] != tc.errCode {
				t.Fatalf("refresh after the denial: %d %v, want %d %s", res.StatusCode, body, tc.status, tc.errCode)
			}
			denied := tc.errCode != ""
			revocations := a.e.auditEvents(t, "grant_revoked")
			if denied != (len(revocations) == 1) || len(revocations) > 1 ||
				denied && (revocations[0]["reason"] != reasonClientDenied || revocations[0]["client_id"] != a.clientID || revocations[0]["grant_id"] == "") {
				t.Fatalf("grant_revoked events %v, want one for %s only when denied (%v)", revocations, a.clientID, denied)
			}
			if a.e.valid(t, a.tokens["access_token"].(string)) == denied {
				t.Fatalf("the access token issued before the denial passes: %v, want %v", !denied, !denied)
			}
		})
	}
}

// An access token of a denied CIMD client ID is refused at its next request, before any refresh;
// one of a DCR client denied by its redirect host keeps working until it expires, at most an hour,
// since the validator does not look the client up (#338).
func TestAnAccessTokenOfADeniedClientID(t *testing.T) {
	for name, tc := range map[string]struct {
		signIn func(t *testing.T) signedInApp
		entry  func(clientID, redirect string) string
		passes bool
	}{
		"CIMD client ID":      {signIn: cimdSignedIn, entry: func(id, _ string) string { return id }},
		"DCR redirect host":   {signIn: dcrSignedIn, entry: redirectHost, passes: true},
		"another CIMD client": {signIn: cimdSignedIn, entry: func(string, string) string { return "https://other.example/client.json" }, passes: true},
	} {
		t.Run(name, func(t *testing.T) {
			a := tc.signIn(t)
			deny, err := registration.NewDenylist([]string{tc.entry(a.clientID, a.redirect)})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.e.b.Deny().Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			v, err := token.NewValidator(a.e.sealer, a.e.b.Deny(), deny, func() time.Time { return a.e.now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Validate(context.Background(), a.tokens["access_token"].(string)); (err == nil) != tc.passes {
				t.Fatalf("validate: %v, want passes %v", err, tc.passes)
			}
		})
	}
}

// redirectHost is the host of the app's redirect URI, as a denylist entry.
func redirectHost(_, redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		panic(err)
	}
	return u.Hostname()
}

// dcrSignedIn registers a DCR app with the refresh_token grant and signs a user in with it.
func dcrSignedIn(t *testing.T) signedInApp {
	t.Helper()
	e := newEnv(t, withDCR(nil))
	const redirect = "https://app.example/cb"
	_, reg := e.register(t, `{"client_name":"App","redirect_uris":["`+redirect+`"],"grant_types":["authorization_code","refresh_token"]}`)
	id := reg["client_id"].(string)
	as := url.Values{"client_id": {id}, "redirect_uri": {redirect}, "scope": {"mcp offline_access"}}
	res, body := e.redeem(t, e.signIn(t, as).Query().Get("code"), url.Values{"client_id": {id}, "redirect_uri": {redirect}})
	if res.StatusCode != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("redeem: %d %v", res.StatusCode, body)
	}
	return signedInApp{e: e, clientID: id, redirect: redirect, tokens: body, deny: func(_ *testing.T, entries ...string) {
		e.b.cfg.Clients = registration.Chain{e.reg, newDCRFor(e.st, e.cfg.Now, entries...)}
	}}
}

// cimdSignedIn signs a user in with the claude.ai CIMD document and offline_access.
func cimdSignedIn(t *testing.T) signedInApp {
	t.Helper()
	d := clientdocs.Load(t, "claude-ai")
	srv := clientdocs.Serve(t, d)
	e := newEnv(t, withCIMD(srv))
	back := e.signIn(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
	res, body := e.redeem(t, back.Query().Get("code"), url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
	if res.StatusCode != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("redeem: %d %v", res.StatusCode, body)
	}
	return signedInApp{e: e, clientID: d.ClientID, redirect: d.Redirect, tokens: body, deny: func(t *testing.T, entries ...string) {
		deny, err := registration.NewDenylist(entries)
		if err != nil {
			t.Fatal(err)
		}
		e.b.cfg.Clients = registration.Chain{e.reg, newCIMDFor(srv, deny)}
	}}
}
