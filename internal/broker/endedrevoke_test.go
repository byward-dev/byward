package broker

import (
	"context"
	"fmt"
	"net/http"
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
	offlineCode := func(t *testing.T, e *env, extra url.Values) string {
		q := url.Values{"scope": {"mcp offline_access"}}
		for k, v := range extra {
			q[k] = v
		}
		return e.signIn(t, q).Query().Get("code")
	}
	// deniedDCR registers a DCR client returning to bad.example and signs it in, stopping at its code
	// (dcrSignInTo redeems it), and returns its ID, its code, and the call that puts bad.example on
	// the operator's denylist.
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
		"a code of a client denied since it signed in": {opts: []func(*Config){withDCR(nil)}, reason: reasonClientDenied, after: "ConsumeCode",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				id, code, deny := deniedDCR(t, e)
				deny()
				return "/token", redeemForm(code, url.Values{"client_id": {id}, "redirect_uri": {badCB}})
			}},
		"a refresh by a client denied since it signed in": {opts: []func(*Config){withDCR(nil)}, reason: reasonClientDenied, after: "RefreshToken",
			prepare: func(t *testing.T, e *env) (string, url.Values) {
				c := dcrSignInTo(t, e, badCB)
				c.deny(t, "bad.example")
				return "/token", refreshForm(c.tokens["refresh_token"].(string), c.clientID)
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
				e.st.AfterCall(tc.after, func(context.Context) { stop() })
				e.st.AfterCall("RevokeGrant", func(call context.Context) {
					if ctx.Err() == nil {
						t.Error("the grant was revoked before the request ended: the cell tests nothing")
					}
					wantBounded(t, call)
				})
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

// A DCR client whose code redemption ends once its tokens are issued, as its client going away or
// the proxy's shutdown, still has its use recorded: recordUse runs detached, so the client is not
// collected as never used, and its registration slides when due (ADR-0008 §3, #693). An
// availability guarantee: a lost use makes the client register again.
func TestADCRClientWhoseRedemptionEndsIsStillMarkedUsed(t *testing.T) {
	const cb = "https://app.example/cb"
	for _, end := range lifecycle.ContextEndings {
		t.Run(end.Ending.String(), func(t *testing.T) {
			e := newEnv(t, withDCR(nil))
			id := registerDCR(t, e, cb)
			code := e.signIn(t, url.Values{"client_id": {id}, "redirect_uri": {cb}, "scope": {"mcp offline_access"}}).Query().Get("code")
			e.st.SQLContext()
			ctx, stop := end.Start(t.Context())
			t.Cleanup(stop)
			e.st.AfterCall("Grant", func(context.Context) { stop() }) // the grant's identity claims: the last store call before recordUse
			e.st.AfterCall("UseClient", func(call context.Context) { wantBounded(t, call) })
			f := redeemForm(code, url.Values{"client_id": {id}, "redirect_uri": {cb}})
			e.serveIn(ctx, formRequest("/token", strings.NewReader(f.Encode())))
			if ctx.Err() == nil {
				t.Fatal("the request never ended: Grant was not called")
			}
			if c, err := e.st.Store.Client(context.Background(), id); err != nil || c.UsedAt.IsZero() {
				t.Errorf("the client after a redemption whose request ended: %+v, %v; want it marked used", c, err)
			}
		})
	}
}

// A detached call outlives its request's end, keeps the request's values (its log reference), and
// still ends within 5 s, so a stuck store cannot hold a revocation open past the shutdown grace.
func TestADetachedCallOutlivesItsRequestAndEndsWithinFiveSeconds(t *testing.T) {
	type key struct{}
	parent, end := context.WithCancel(context.WithValue(context.Background(), key{}, "ref"))
	before := time.Now()
	ctx, cancel := detached(parent)
	defer cancel()
	end()
	if ctx.Err() != nil {
		t.Fatalf("the detached context ended with its request: %v", ctx.Err())
	}
	if ctx.Value(key{}) != "ref" {
		t.Error("the detached context lost the request's values")
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(before.Add(5*time.Second)) || deadline.After(time.Now().Add(5*time.Second)) {
		t.Errorf("deadline %v (set: %v), want 5 s after the call", deadline, ok)
	}
}

// A DCR client that revokes its token at /revoke as it closes, or as the proxy shuts down, still ends
// its grant: its own lookup is a store read, and it runs detached with the revocation (#693). The
// answer then follows the ending (shutdown.AnswerIfEnded), after the revocation.
func TestADCRClientsRevocationOnARequestThatEndedStillEndsItsGrant(t *testing.T) {
	for _, end := range lifecycle.ContextEndings {
		t.Run(end.Ending.String(), func(t *testing.T) {
			e := newEnv(t, withDCR(nil))
			c := dcrSignInTo(t, e, "https://app.example/cb")
			grantID := lastGrant(e.st)
			e.st.SQLContext()
			e.st.AfterCall("RevokeGrant", func(call context.Context) { wantBounded(t, call) })
			e.st.AfterCall("Client", func(call context.Context) { wantBounded(t, call) }) // the DCR client's own lookup
			f := url.Values{"token": {c.tokens["refresh_token"].(string)}, "client_id": {c.clientID}}
			w := e.serveIn(endedCtx(end), formRequest("/revoke", strings.NewReader(f.Encode())))
			end.Answered(t, w)
			if !e.grantGone(t, grantID) {
				t.Errorf("grant %s is still in the store", grantID)
			}
			if revs := e.auditEvents(t, "grant_revoked"); len(revs) != 1 || revs[0]["grant_id"] != grantID {
				t.Errorf("grant_revoked events %v; want one for grant %s", revs, grantID)
			}
		})
	}
}

// wantBoundedIfLive is wantBounded for a store call whose context has not ended: one that can still
// run after its request ended. A call still on the ended request's context fails anyway.
func wantBoundedIfLive(t *testing.T, call context.Context) {
	t.Helper()
	if call.Err() == nil {
		wantBounded(t, call)
	}
}

// wantBounded fails t unless call, a store call's context, has a deadline at most 5 s away: a
// revocation detached from its request is still bounded, so a stuck store cannot hold it past the
// shutdown grace.
func wantBounded(t *testing.T, call context.Context) {
	t.Helper()
	if deadline, ok := call.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
		t.Errorf("a revocation's store call has deadline %v (set: %v), want one at most 5 s away", deadline, ok)
	}
}

// replayChecked is a client whose authentication spends its assertion in the store, as a
// private_key_jwt client's does (registration.StoreJTICache): it fails on an ended context, as
// that store call does on a SQL store.
type replayChecked struct{ registration.Client }

func (c replayChecked) Authenticate(ctx context.Context, f url.Values, h http.Header, endpoint string, now time.Time) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %v", registration.ErrReplayCheckUnavailable, ctx.Err())
	}
	return c.Client.Authenticate(ctx, f, h, endpoint, now)
}

// replayCheckedClients resolves every client as replayChecked, and records the deadline its lookup
// ran with in lookup, if set.
type replayCheckedClients struct {
	registration.Registry
	lookup *time.Time
}

func (r replayCheckedClients) Client(ctx context.Context, id string) (registration.Client, error) {
	if d, ok := ctx.Deadline(); ok && r.lookup != nil {
		*r.lookup = d
	}
	c, err := r.Registry.Client(ctx, id)
	if err != nil {
		return nil, err
	}
	return replayChecked{c}, nil
}

// A client whose authentication is a store call (a private_key_jwt assertion's replay check) still
// ends its grant at /revoke when its request has ended: the authentication runs detached, and the
// revocation then gets a bound of its own, so a slow lookup cannot spend its time (#693).
func TestARevocationWhoseClientAuthenticationIsAStoreCallStillEndsItsGrant(t *testing.T) {
	for _, end := range lifecycle.ContextEndings {
		t.Run(end.Ending.String(), func(t *testing.T) {
			e := newEnv(t)
			rt := e.offline(t)["refresh_token"].(string)
			grantID := lastGrant(e.st)
			var lookup time.Time
			e.b.cfg.Clients = replayCheckedClients{e.b.cfg.Clients, &lookup}
			e.st.SQLContext()
			e.st.AfterCall("RevokeGrant", func(call context.Context) {
				wantBounded(t, call)
				if d, _ := call.Deadline(); !d.After(lookup) {
					t.Errorf("the revocation's deadline %v is not after the lookup's %v: they share one bound", d, lookup)
				}
			})
			f := url.Values{"token": {rt}, "client_id": {clientID}}
			end.Answered(t, e.serveIn(endedCtx(end), formRequest("/revoke", strings.NewReader(f.Encode()))))
			if !e.grantGone(t, grantID) {
				t.Errorf("grant %s is still in the store", grantID)
			}
		})
	}
}
