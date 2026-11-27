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
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// brokerCell is what one lifecycle cell of the broker pins today.
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

const (
	bodyReadBug = "a request whose client goes away, or the proxy shuts down, while the broker reads its body is answered 400 as unreadable (register.go, token.go, revoke.go, consent.go), audited as a failed request, not answered by how it ended (shutdown.AnswerIfEnded: 499, or 503 and close); the broker never calls AnswerIfEnded"
	waitBug     = "a client lookup whose request ended while it waited on the CIMD fetch (or a client's keys) is ErrUnavailable like a failed fetch: the broker answers 503 with WARN \"client metadata unavailable\" (and audits token_rejected at /token and /revoke), not by how it ended; /callback logs WARN and goes on, issuing a grant that cannot refresh; and a callback whose request ended during the IdP's code exchange fails the sign-in as the IdP's error, 502 with WARN \"IdP sign-in failed\""
)

// The broker's lifecycle matrix (#672): its requests' endings, crossed with the states its work
// can be in: before its body read or client lookup, reading its body, and waiting on a client
// lookup (the CIMD fetch, or a client's keys). Its cells are today's answers to requests that
// ended (KnownResidual): the broker fix flips them to Pinned. The CIMD fetch's own cells are in
// TestTheCIMDFetchLifecycleMatrix (internal/registration).
func TestTheBrokerLifecycleMatrix(t *testing.T) {
	const (
		whole       = "the broker writes whole answers: no interim response, stream, trailer or upgrade"
		noOutbound  = "nothing goes outbound before the broker reads a body or looks a client up"
		noPreBound  = "the broker sets no bound on its work before a body read or lookup"
		storeCalls  = "a request that ended with its body read runs to completion; its store calls under the ended context are #693, which memstore cannot show"
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
		m[at(end.Ending, lifecycle.BodyInFlight)] = lifecycle.KnownResidual("#672", bodyReadBug, func(t *testing.T) {
			t.Run("/register", func(t *testing.T) {
				e := newEnv(t, withDCR(nil))
				lm, am := e.marks()
				body := lifecycle.NewCutBody(`{"redirect_uris":["https://app.example/cb"]}`)
				r := httptest.NewRequest(http.MethodPost, issuer+"/register", body)
				r.Header.Set("Content-Type", "application/json")
				e.pinned(t, e.cutIn(t, end, r, body), lm, am, brokerCell{status: http.StatusBadRequest, body: "could not be read",
					audit: []string{"client_registered failure"}})
			})
			for _, path := range []string{"/token", "/revoke"} {
				t.Run(path, func(t *testing.T) {
					e := newEnv(t)
					lm, am := e.marks()
					body := lifecycle.NewCutBody(url.Values{"client_id": {clientID}, "token": {"x"}, "grant_type": {"refresh_token"}}.Encode())
					e.pinned(t, e.cutIn(t, end, formRequest(path, body), body), lm, am, brokerCell{status: http.StatusBadRequest, body: "invalid_request",
						audit: []string{"token_rejected failure"}})
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
				e.pinned(t, e.cutIn(t, end, r, body), lm, am, brokerCell{status: http.StatusBadRequest, body: "could not be read"})
			})
		})

		m[at(end.Ending, lifecycle.AwaitingHeaders)] = lifecycle.KnownResidual("#672", waitBug, func(t *testing.T) {
			unavailablePage := brokerCell{status: http.StatusServiceUnavailable, body: "Try again", warns: []string{metadataUnavailable}}
			unavailableToken := func(what string) brokerCell {
				return brokerCell{status: http.StatusServiceUnavailable, body: what, warns: []string{metadataUnavailable},
					audit: []string{"token_rejected failure"}}
			}
			t.Run("/authorize", func(t *testing.T) {
				e, d, mode := cimdEnv(t)
				mode.Store(modeWaits)
				lm, am := e.marks()
				q := authorizeQuery(url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
				r := httptest.NewRequest(http.MethodGet, issuer+"/authorize?"+q.Encode(), nil)
				e.pinned(t, e.serveIn(endedCtx(end), r), lm, am, unavailablePage)
			})
			t.Run("/consent", func(t *testing.T) {
				e, d, mode := cimdEnv(t)
				p := e.showConsent(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
				e.now = e.now.Add(ConsentDelay)
				mode.Store(modeWaits)
				lm, am := e.marks()
				r := formRequest("/consent", strings.NewReader(url.Values{"flow": {p.flow}, "action": {"allow"}}.Encode()))
				r.AddCookie(p.binding)
				e.pinned(t, e.serveIn(endedCtx(end), r), lm, am, unavailablePage)
			})
			t.Run("/token, a code", func(t *testing.T) {
				e, d, mode := cimdEnv(t)
				mode.Store(modeWaits)
				lm, am := e.marks()
				f := url.Values{"grant_type": {"authorization_code"}, "code": {"any"}, "client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "code_verifier": {verifier}}
				e.pinned(t, e.serveIn(endedCtx(end), formRequest("/token", strings.NewReader(f.Encode()))), lm, am,
					unavailableToken("the client's metadata could not be fetched"))
			})
			for name, tc := range map[string]struct {
				mode int32
				path string
				what string
			}{
				"/token, a refresh":         {modeWaits, "/token", "the client's metadata could not be fetched"},
				"/token, the client's keys": {modeKeysWait, "/token", "the client's keys could not be fetched"},
				"/revoke":                   {modeWaits, "/revoke", "the client's metadata could not be fetched"},
			} {
				t.Run(name, func(t *testing.T) {
					e, d, mode, tokens := offlineCIMD(t)
					mode.Store(tc.mode)
					lm, am := e.marks()
					f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "token": {tokens["refresh_token"].(string)}, "client_id": {d.ClientID}}
					e.pinned(t, e.serveIn(endedCtx(end), formRequest(tc.path, strings.NewReader(f.Encode()))), lm, am, unavailableToken(tc.what))
				})
			}
			// Before the lookup, the callback redeems the IdP's code: a request that ended there fails
			// the sign-in as the IdP's error.
			t.Run("/callback, the IdP's code exchange", func(t *testing.T) {
				e, d, _ := cimdEnv(t)
				cookie, cb := e.startLogin(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
				lm, am := e.marks()
				r := httptest.NewRequest(http.MethodGet, issuer+"/callback/entra?"+cb.RawQuery, nil)
				r.AddCookie(cookie)
				e.pinned(t, e.serveIn(endedCtx(end), r), lm, am, brokerCell{status: http.StatusBadGateway, body: "Signing in failed",
					warns: []string{"IdP sign-in failed"}, audit: []string{"login failure"}})
			})
			// After the IdP's code is spent, the callback looks the client up to grant offline_access:
			// today a request that ends there logs the failed lookup and goes on, with a grant that
			// cannot refresh.
			t.Run("/callback, the client lookup", func(t *testing.T) {
				d := clientdocs.Load(t, "claude-ai")
				lookups := &enteredLookups{entered: make(chan struct{})}
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
				var w *httptest.ResponseRecorder
				select {
				case w = <-got:
				case <-time.After(5 * time.Second):
					t.Fatal("the callback never answered")
				}
				e.pinned(t, w, lm, am, brokerCell{status: http.StatusFound,
					warns: []string{"looking up the client failed, so this grant cannot refresh"}, audit: []string{"login success"}})
			})
		})
	}
	lifecycle.Run(t, m)
}

// enteredLookups resolves clients through inner until armed; then a CIMD lookup says it has
// entered and waits for its request to end, as CIMDRegistry.Client does.
type enteredLookups struct {
	inner   registration.Registry
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
}

func (l *enteredLookups) Client(ctx context.Context, id string) (registration.Client, error) {
	if !l.armed.Load() || !registration.IsCIMDURL(id) {
		return l.inner.Client(ctx, id)
	}
	l.once.Do(func() { close(l.entered) })
	<-ctx.Done()
	return nil, fmt.Errorf("%w: %v", registration.ErrUnavailable, ctx.Err())
}
