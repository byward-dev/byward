package broker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// brokerCell is what one lifecycle cell of the broker pins.
type brokerCell struct {
	status int
	body   string   // in the answer
	warns  []string // every WARN or ERROR line, by message
	audit  []string // every audit event, as "event outcome"
}

// serveIn serves r to the broker in-process with ctx, as the server would: through the logging
// middleware, so error pages carry their reference.
func (e *env) serveIn(ctx context.Context, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(w, r.WithContext(ctx))
	return w
}

// formRequest is a POST of a form to path, from a browser on our origin, as answer sends one.
func formRequest(path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, issuer+path, body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", issuer)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// pinned fails t unless w and the broker's logs since mark are want.
func (e *env) pinned(t *testing.T, w *httptest.ResponseRecorder, logMark, auditMark int, want brokerCell) {
	t.Helper()
	if w.Code != want.status || !strings.Contains(w.Body.String(), want.body) {
		t.Errorf("answered %d %q; want %d with %q", w.Code, w.Body, want.status, want.body)
	}
	var warns []string
	for _, rec := range logsink.Records[map[string]any](t, e.logs.String()[logMark:]) {
		if rec["level"] == "WARN" || rec["level"] == "ERROR" {
			warns = append(warns, rec["msg"].(string))
		}
	}
	var events []string
	for _, rec := range logsink.Records[map[string]any](t, e.audit.String()[auditMark:]) {
		events = append(events, fmt.Sprint(rec["event"], " ", rec["outcome"]))
	}
	if !slices.Equal(warns, want.warns) || !slices.Equal(events, want.audit) {
		t.Errorf("logged %q and audited %q; want %q and %q", warns, events, want.warns, want.audit)
	}
}

// endedAnswer fails t unless w answers a request that ended as end does (499 recorded, or 503 and
// close at shutdown), with nothing logged as a failure or audited since the marks (#527).
func (e *env) endedAnswer(t *testing.T, end lifecycle.Ended, w *httptest.ResponseRecorder, logMark, auditMark int) {
	t.Helper()
	end.Answered(t, w)
	e.pinned(t, w, logMark, auditMark, brokerCell{status: end.Status, body: end.Body})
}

// marks are where the cell's own logs and audit events begin.
func (e *env) marks() (int, int) { return len(e.logs.String()), len(e.audit.String()) }

// cutIn serves r, its body a lifecycle.CutBody, until the broker has read the body's first byte,
// then ends the request as end does and fails the rest of the read, as the server's connection
// does. It returns what the broker answered.
func (e *env) cutIn(t *testing.T, end lifecycle.Ended, r *http.Request, body *lifecycle.CutBody) *httptest.ResponseRecorder {
	t.Helper()
	ctx, stop := end.Start(context.Background())
	defer stop() // ends the request on a failure path too, so its serve goroutine returns
	got := make(chan *httptest.ResponseRecorder, 1)
	go func() { got <- e.serveIn(ctx, r) }()
	select {
	case <-body.Started():
	case <-time.After(5 * time.Second):
		body.Stop()
		t.Fatal("the broker never read the request body")
	}
	stop()
	body.Cut()
	select {
	case w := <-got:
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("the broker never answered")
		return nil
	}
}

// endedCtx is a request context that ended as e does.
func endedCtx(e lifecycle.Ended) context.Context {
	ctx, stop := e.Start(context.Background())
	stop()
	return ctx
}

// The broker's lifecycle matrix (#672): its requests' endings, crossed with the states its work
// can be in: before its body read or client lookup, reading its body, and waiting on a client
// lookup (the CIMD fetch, or a client's keys) or the IdP. A request that ended is answered by how it
// ended, with nothing logged as a failure or audited; a callback past its spent login finishes, so
// a shutdown keeps its sign-in and a browser that went away gets nothing. The CIMD fetch's own cells
// are in TestTheCIMDFetchLifecycleMatrix (internal/registration).
//
// The same class, outside these cells (#672 known residuals): /authorize's and /consent's IdP
// discovery before a replica has cached it (AuthCodeURL) answers an ended request 502 and logs the
// sign-in as failed; the throttled /authorize's lookup answers it 429, harmlessly; the admin consent
// redirect has no wait (it logs one INFO line and shows a page).
func TestTheBrokerLifecycleMatrix(t *testing.T) {
	const (
		whole       = "the broker writes whole answers: no interim response, stream, trailer or upgrade"
		noOutbound  = "nothing goes outbound before the broker reads a body or looks a client up"
		noPreBound  = "the broker sets no bound on its work before a body read or lookup"
		storeCalls  = "a request that ended with its body read runs to completion; its store calls under the ended context are #693, which memstore cannot show (a callback's calls after its spent login are detached, so only its spendLogin is)"
		readBound   = "the server's ReadTimeout bounds a stalled body, not the broker"
		inFlightOut = "nothing goes outbound while the broker reads a body"
	)
	at := func(e lifecycle.Ending, s lifecycle.State) lifecycle.Cell { return lifecycle.Cell{Ending: e, State: s} }
	m := map[lifecycle.Cell]lifecycle.Case{}
	for _, e := range lifecycle.Endings {
		for _, s := range []lifecycle.State{lifecycle.After1xx, lifecycle.Streaming, lifecycle.TrailerPending, lifecycle.UpgradeRequested} {
			m[at(e, s)] = lifecycle.Unreachable(whole)
		}
	}
	m[at(lifecycle.Completes, lifecycle.NotStarted)] = lifecycle.Unreachable("a request that completes got past its body read or lookup")
	m[at(lifecycle.ClientGone, lifecycle.NotStarted)] = lifecycle.NotRun(storeCalls)
	m[at(lifecycle.Shutdown, lifecycle.NotStarted)] = lifecycle.NotRun(storeCalls)
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.Unreachable(noOutbound)
	m[at(lifecycle.Timeout, lifecycle.NotStarted)] = lifecycle.Unreachable(noPreBound)
	m[at(lifecycle.Completes, lifecycle.BodyInFlight)] = lifecycle.NotRun("TestTokenAndRevokeReadAFormOfUpTo64KiB and the registration tests pin a body read whole")
	m[at(lifecycle.UpstreamGone, lifecycle.BodyInFlight)] = lifecycle.Unreachable(inFlightOut)
	m[at(lifecycle.Timeout, lifecycle.BodyInFlight)] = lifecycle.Unreachable(readBound)
	m[at(lifecycle.Completes, lifecycle.AwaitingHeaders)] = lifecycle.NotRun("TestRealCIMDClientsSignInAndRedeem pins a lookup the fetch answers")
	m[at(lifecycle.UpstreamGone, lifecycle.AwaitingHeaders)] = lifecycle.NotRun("TestTransientMetadataFailuresAreServiceUnavailable and TestATransientFailureAtTheConsentAnswerIsServiceUnavailable pin a failed fetch's 503")
	m[at(lifecycle.Timeout, lifecycle.AwaitingHeaders)] = lifecycle.NotRun("a fetch that times out is a transient failure, answered as upstream gone; TestTheCIMDFetchLifecycleMatrix pins the timeout")

	for _, end := range lifecycle.ContextEndings {
		m[at(end.Ending, lifecycle.BodyInFlight)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("/register", func(t *testing.T) {
				e := newEnv(t, withDCR(nil))
				lm, am := e.marks()
				body := lifecycle.NewCutBody(`{"redirect_uris":["https://app.example/cb"]}`)
				r := httptest.NewRequest(http.MethodPost, issuer+"/register", body)
				r.Header.Set("Content-Type", "application/json")
				e.endedAnswer(t, end, e.cutIn(t, end, r, body), lm, am)
			})
			for _, path := range []string{"/token", "/revoke"} {
				t.Run(path, func(t *testing.T) {
					e := newEnv(t)
					lm, am := e.marks()
					body := lifecycle.NewCutBody(url.Values{"client_id": {clientID}, "token": {"x"}, "grant_type": {"refresh_token"}}.Encode())
					e.endedAnswer(t, end, e.cutIn(t, end, formRequest(path, body), body), lm, am)
				})
			}
			t.Run("/consent", func(t *testing.T) {
				e := newEnv(t)
				p := e.showConsent(t, nil)
				e.now = e.now.Add(ConsentDelay)
				lm, am := e.marks()
				body := lifecycle.NewCutBody(url.Values{"flow": {p.flow}, "action": {"allow"}}.Encode())
				r := formRequest("/consent", body)
				r.AddCookie(p.binding)
				e.endedAnswer(t, end, e.cutIn(t, end, r, body), lm, am)
			})
		})

		m[at(end.Ending, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
			t.Run("/authorize", func(t *testing.T) {
				e, d, mode := cimdEnv(t)
				mode.Store(modeWaits)
				lm, am := e.marks()
				q := authorizeQuery(url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
				r := httptest.NewRequest(http.MethodGet, issuer+"/authorize?"+q.Encode(), nil)
				e.endedAnswer(t, end, e.serveIn(endedCtx(end), r), lm, am)
			})
			t.Run("/consent", func(t *testing.T) {
				e, d, mode := cimdEnv(t)
				p := e.showConsent(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
				e.now = e.now.Add(ConsentDelay)
				mode.Store(modeWaits)
				lm, am := e.marks()
				r := formRequest("/consent", strings.NewReader(url.Values{"flow": {p.flow}, "action": {"allow"}}.Encode()))
				r.AddCookie(p.binding)
				e.endedAnswer(t, end, e.serveIn(endedCtx(end), r), lm, am)
			})
			t.Run("/token, a code", func(t *testing.T) {
				e, d, mode := cimdEnv(t)
				mode.Store(modeWaits)
				lm, am := e.marks()
				f := url.Values{"grant_type": {"authorization_code"}, "code": {"any"}, "client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "code_verifier": {verifier}}
				e.endedAnswer(t, end, e.serveIn(endedCtx(end), formRequest("/token", strings.NewReader(f.Encode()))), lm, am)
			})
			for name, tc := range map[string]struct {
				mode int32
				path string
			}{
				"/token, a refresh":         {modeWaits, "/token"},
				"/token, the client's keys": {modeKeysWait, "/token"},
				"/token, the IdP's refresh": {modeOK, "/token"}, // the client resolves: the refresh waits on the IdP
				"/revoke":                   {modeWaits, "/revoke"},
			} {
				t.Run(name, func(t *testing.T) {
					e, d, mode, tokens := offlineCIMD(t)
					mode.Store(tc.mode)
					lm, am := e.marks()
					ops := len(e.idpOps)
					f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "token": {tokens["refresh_token"].(string)}, "client_id": {d.ClientID}}
					e.endedAnswer(t, end, e.serveIn(endedCtx(end), formRequest(tc.path, strings.NewReader(f.Encode()))), lm, am)
					if tc.mode == modeOK && !slices.Contains(e.idpOps[ops:], OpRefresh+" unavailable") {
						t.Errorf("IdP calls %q; want the refresh to have reached the IdP", e.idpOps[ops:])
					}
				})
			}
			// The callback has spent its login before it redeems the IdP's code, so it finishes, its
			// request ended or not: a shutdown's browser gets its sign-in; a browser that went away
			// gets nothing, and no grant is made.
			t.Run("/callback, the IdP's code exchange", func(t *testing.T) {
				e, d, _ := cimdEnv(t)
				cookie, cb := e.startLogin(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
				lm, am := e.marks()
				r := httptest.NewRequest(http.MethodGet, issuer+"/callback/entra?"+cb.RawQuery, nil)
				r.AddCookie(cookie)
				e.callbackFinished(t, end, e.serveIn(endedCtx(end), r), lm, am)
			})
			// The IdP refuses the code exchange: a browser that went away is still sent nothing, and
			// no failure is logged or audited for it; a shutdown's browser, still there, is told the
			// sign-in failed, as any live one is.
			t.Run("/callback, a failed code exchange", func(t *testing.T) {
				e, d, _ := cimdEnv(t)
				cookie, cb := e.startLogin(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
				f := fakeidp.CodeExpired
				e.fake.Set(fakeidp.FailToken(fakeidp.GrantAuthorizationCode, &f))
				lm, am := e.marks()
				r := httptest.NewRequest(http.MethodGet, issuer+"/callback/entra?"+cb.RawQuery, nil)
				r.AddCookie(cookie)
				w := e.serveIn(endedCtx(end), r)
				if end.Ending == lifecycle.ClientGone {
					e.endedAnswer(t, end, w, lm, am)
					return
				}
				e.pinned(t, w, lm, am, brokerCell{status: http.StatusBadGateway, body: "Sign-in failed", warns: []string{"IdP sign-in failed"}, audit: []string{"login failure"}})
			})
			// After the IdP's code is spent, the callback looks the client up to grant offline_access,
			// on its own context: a request that ends meanwhile neither fails the lookup nor loses the
			// refresh.
			t.Run("/callback, the client lookup", func(t *testing.T) {
				d := clientdocs.Load(t, "claude-ai")
				lookups := &enteredLookups{entered: make(chan struct{}), release: make(chan struct{})}
				var released sync.Once
				release := func() { released.Do(func() { close(lookups.release) }) }
				defer release() // a failing run lets a lookup that enters late go on, too
				cimd := withCIMD(clientdocs.Serve(t, d))
				e := newEnv(t, func(c *Config) { cimd(c); lookups.inner = c.Clients; c.Clients = lookups })
				cookie, cb := e.startLogin(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
				lookups.armed.Store(true)
				lm, am := e.marks()
				r := httptest.NewRequest(http.MethodGet, issuer+"/callback/entra?"+cb.RawQuery, nil)
				r.AddCookie(cookie)
				ctx, stop := end.Start(context.Background())
				defer stop()
				got := make(chan *httptest.ResponseRecorder, 1)
				go func() { got <- e.serveIn(ctx, r) }()
				select {
				case <-lookups.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("the callback never looked the client up")
				}
				stop()
				release()
				var w *httptest.ResponseRecorder
				select {
				case w = <-got:
				case <-time.After(5 * time.Second):
					t.Fatal("the callback never answered")
				}
				if err := lookups.ctxErr.Load(); err != nil {
					t.Errorf("the lookup's context ended (%v); want it to outlive the request", *err)
				}
				if dl := lookups.deadline.Load(); dl == nil || time.Until(*dl) > CallbackTimeout {
					t.Errorf("the lookup's deadline %v; want one within CallbackTimeout, so the detached callback is bounded", dl)
				}
				e.callbackFinished(t, end, w, lm, am)
			})
		})
	}
	lifecycle.Run(t, m)
}

// enteredLookups resolves clients through inner until armed; then a CIMD lookup says it has
// entered, waits for release, and resolves through inner, keeping its context's error.
type enteredLookups struct {
	inner    registration.Registry
	armed    atomic.Bool
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
	ctxErr   atomic.Pointer[error]
	deadline atomic.Pointer[time.Time]
}

func (l *enteredLookups) Client(ctx context.Context, id string) (registration.Client, error) {
	if !l.armed.Load() || !registration.IsCIMDURL(id) {
		return l.inner.Client(ctx, id)
	}
	l.once.Do(func() { close(l.entered) })
	<-l.release
	if err := ctx.Err(); err != nil {
		l.ctxErr.Store(&err)
	}
	if dl, ok := ctx.Deadline(); ok {
		l.deadline.Store(&dl)
	}
	return l.inner.Client(ctx, id)
}

// callbackFinished fails t unless a callback whose request ended as end does finished as it should:
// at shutdown, the browser's sign-in (a code, a grant that can refresh, the login audited); for a
// browser that went away, nothing sent and no grant; neither logged as a failure.
func (e *env) callbackFinished(t *testing.T, end lifecycle.Ended, w *httptest.ResponseRecorder, logMark, auditMark int) {
	t.Helper()
	if end.Ending == lifecycle.ClientGone {
		e.endedAnswer(t, end, w, logMark, auditMark)
		if g := firstGrant(e.st); g != "" {
			t.Errorf("grant %s made for a browser that went away", g)
		}
		return
	}
	e.pinned(t, w, logMark, auditMark, brokerCell{status: http.StatusFound, audit: []string{"login success"}})
	back, _ := url.Parse(w.Header().Get("Location"))
	if back.Query().Get("code") == "" {
		t.Fatalf("redirected to %q; want a code", back)
	}
	g, err := e.st.Grant(context.Background(), firstGrant(e.st))
	if err != nil || !slices.Contains(g.Scopes, "offline_access") {
		t.Errorf("grant %+v, %v; want one that can refresh", g, err)
	}
}

// A refused client is refused whether or not its request has ended: only a lookup that waited
// (ErrUnavailable) is answered by how its request ended, so each refusal that ends a grant
// (refusals: the denylist, a refused document) still revokes the grant behind what it presents: a
// code or a refresh token at /token, or a token at /revoke (draft -03 §6.1; #338; #672). The store
// fails a call under the ended context, as a SQL store does, so the revocation and the lookup it
// needs must run detached (#693).
func TestARefusedClientWhoseRequestEndedStillLosesItsGrant(t *testing.T) {
	// Each surface readies what the client presents and returns its path and form.
	surfaces := map[string]func(t *testing.T, c refusable) (string, url.Values){
		"a code": func(t *testing.T, c refusable) (string, url.Values) {
			return "/token", redeemForm(c.signIn(t), url.Values{"client_id": {c.d.ClientID}, "redirect_uri": {c.d.Redirect}})
		},
		"a refresh token": func(t *testing.T, c refusable) (string, url.Values) {
			return "/token", refreshForm(c.tokens(t, c.signIn(t))["refresh_token"].(string), c.d.ClientID)
		},
		"a token at /revoke": func(t *testing.T, c refusable) (string, url.Values) {
			return "/revoke", url.Values{"token": {c.tokens(t, c.signIn(t))["refresh_token"].(string)}, "client_id": {c.d.ClientID}}
		},
	}
	for name, refusal := range refusals {
		for surface, ready := range surfaces {
			for _, end := range lifecycle.ContextEndings {
				t.Run(name+"/"+surface+"/"+end.Ending.String(), func(t *testing.T) {
					c := refusal(t)
					path, f := ready(t, c)
					grantID := c.onlyGrant(t)
					c.refuse()
					c.e.st.SQLContext()
					for _, m := range []string{"Grant", "RefreshToken", "RevokeGrant"} { // the revocation and the lookup before it
						c.e.st.AfterCall(m, func(call context.Context) { wantBounded(t, call) })
					}
					c.e.serveIn(endedCtx(end), formRequest(path, strings.NewReader(f.Encode())))
					c.wantOneRevocation(t, grantID)
				})
			}
		}
	}
}
