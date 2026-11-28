package broker

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
)

// A misuse detected on a request that then ends still revokes its grant in the store (#693). The
// store fails a call under an ended context, as the SQL stores do (memstore.SQLContext), and the
// request ends, as its client going away or the proxy's shutdown, right after the store call that
// detects the misuse. The grant is gone from the store, so every replica refuses it and its refresh
// tokens stop, not only this replica's deny list, and the revocation is audited with its reason and
// never logged as a failed one.
func TestAMisuseDetectedOnARequestThatThenEndsRevokesItsGrantInTheStore(t *testing.T) {
	const badCB = "https://bad.example/cb"
	redeemForm := func(code string, override url.Values) url.Values {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {clientCB}, "client_id": {clientID}, "code_verifier": {verifier}}
		for k, v := range override {
			f[k] = v
		}
		return f
	}
	refreshForm := func(rt, client string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}}
	}
	offlineCode := func(t *testing.T, e *env, extra url.Values) string {
		q := url.Values{"scope": {"mcp offline_access"}}
		for k, v := range extra {
			q[k] = v
		}
		return e.signIn(t, q).Query().Get("code")
	}
	// deniedDCR registers a DCR client returning to bad.example, signs it in, and returns its ID, its
	// code, and the call that puts bad.example on the operator's denylist.
	deniedDCR := func(t *testing.T, e *env) (id, code string, deny func()) {
		id = registerDCR(t, e, badCB)
		code = offlineCode(t, e, url.Values{"client_id": {id}, "redirect_uri": {badCB}})
		return id, code, func() { e.b.cfg.Clients = registration.Chain{e.reg, newDCRFor(e.st, e.cfg.Now, "bad.example")} }
	}
	for name, tc := range map[string]struct {
		opts   []func(*Config)
		reason string
		after  string // the store call that detects the misuse; the request ends once it returns
		// prepare readies the misuse and returns the request's path and form.
		prepare func(t *testing.T, e *env) (path string, form url.Values)
	}{
		"a reused code": {reason: "authorization code reused; grant revoked", after: "ConsumeCode",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				code := offlineCode(t, e, nil)
				if res, body := e.redeem(t, code, nil); res.StatusCode != 200 {
					t.Fatalf("first redemption: %d %v", res.StatusCode, body)
				}
				return "/token", redeemForm(code, nil)
			}},
		"a code with the wrong verifier": {reason: "authorization code redeemed with the wrong binding; grant revoked", after: "ConsumeCode",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				return "/token", redeemForm(offlineCode(t, e, nil), url.Values{"code_verifier": {strings.Repeat("x", len(verifier))}})
			}},
		"a code of a client denied since": {opts: []func(*Config){withDCR(nil)}, reason: reasonClientDenied, after: "ConsumeCode",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				id, code, deny := deniedDCR(t, e)
				deny()
				return "/token", redeemForm(code, url.Values{"client_id": {id}, "redirect_uri": {badCB}})
			}},
		"a refresh by a client denied since": {opts: []func(*Config){withDCR(nil)}, reason: reasonClientDenied, after: "RefreshToken",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				id, code, deny := deniedDCR(t, e)
				res, body := e.redeem(t, code, url.Values{"client_id": {id}, "redirect_uri": {badCB}})
				if res.StatusCode != 200 {
					t.Fatalf("redemption: %d %v", res.StatusCode, body)
				}
				deny()
				return "/token", refreshForm(body["refresh_token"].(string), id)
			}},
		"a refresh token reused past the grace": {reason: reasonRefreshReused, after: "RefreshToken",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				old := e.offline(t)["refresh_token"].(string)
				if res, body := e.refresh(t, old, ""); res.StatusCode != 200 {
					t.Fatalf("rotation: %d %v", res.StatusCode, body)
				}
				e.now = e.now.Add(MaxRefreshGrace + time.Second)
				return "/token", refreshForm(old, clientID)
			}},
		"a revocation the client asked for": {reason: "the client revoked a token (RFC 7009)", after: "RefreshToken",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				return "/revoke", url.Values{"token": {e.offline(t)["refresh_token"].(string)}, "client_id": {clientID}}
			}},
	} {
		for _, end := range lifecycle.ContextEndings {
			t.Run(name+"/"+end.Ending.String(), func(t *testing.T) {
				e := newEnv(t, tc.opts...)
				path, form := tc.prepare(t, e)
				grantID := lastGrant(e.st)
				e.st.SQLContext()
				ctx, stop := end.Start(t.Context())
				t.Cleanup(stop)
				e.st.AfterCall(tc.after, stop)
				e.serveIn(ctx, formRequest(path, strings.NewReader(form.Encode())))
				if ctx.Err() == nil {
					t.Fatalf("the request never ended: %s was not called", tc.after)
				}
				if !e.grantGone(t, grantID) {
					t.Errorf("grant %s is still in the store", grantID)
				}
				if revs := e.auditEvents(t, "grant_revoked"); len(revs) != 1 || revs[0]["reason"] != tc.reason || revs[0]["grant_id"] != grantID {
					t.Errorf("grant_revoked events %v; want one for grant %s with the reason %q", revs, grantID, tc.reason)
				}
				if failed := e.logRecords(t, "revoking a grant failed"); len(failed) != 0 {
					t.Errorf("logged a failed revocation: %v", failed)
				}
			})
		}
	}
}
