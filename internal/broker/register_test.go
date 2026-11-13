package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/memstore"
)

// outcomes records what the broker counted for /register.
type outcomes struct {
	mu   sync.Mutex
	seen []string
}

func (o *outcomes) observe(outcome string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, outcome)
}

func (o *outcomes) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.seen)
}

// withDCR registers clients dynamically into the broker's store and resolves them after the static
// clients; deny, when set, is the operator's denylist; counted records the metric.
func withDCR(counted *outcomes, deny ...string) func(*Config) {
	return func(c *Config) {
		dcr := newDCRFor(c.Store, c.Now, deny...)
		c.Clients, c.Registrar = registration.Chain{c.Clients, dcr}, dcr
		if counted != nil {
			c.ObserveRegistration = counted.observe
		}
	}
}

// newDCRFor is a DCR registry over st offering the test scopes; deny is the operator's denylist.
func newDCRFor(st store.Clients, now func() time.Time, deny ...string) *registration.DCRRegistry {
	d, err := registration.NewDenylist(deny)
	if err != nil {
		panic(err)
	}
	return registration.NewDCRRegistry(registration.DCRConfig{Store: st, JTI: registration.NewStoreJTICache(memory.New(), now), Now: now,
		Scopes: []string{"mcp", "offline_access"}, Deny: d})
}

// register posts body to /register as JSON.
func (e *env) register(t *testing.T, body string) (*http.Response, map[string]any) {
	t.Helper()
	r, _ := http.NewRequest("POST", e.srv.URL+"/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	res := e.send(t, r)
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return res, m
}

// The registrations real clients send are accepted; the client then signs a user in through the
// consent page (never vouched for), redeems the code, refreshes, and its registration is marked
// used so it is not collected as never used.
func TestRealClientsRegisterSignInAndRefresh(t *testing.T) {
	for _, name := range clientdocs.Registrations {
		t.Run(name, func(t *testing.T) {
			fx := clientdocs.LoadRegistration(t, name)
			counted := &outcomes{}
			e := newEnv(t, withDCR(counted))
			res, reg := e.register(t, string(fx.Body))
			id, _ := reg["client_id"].(string)
			if res.StatusCode != http.StatusCreated || res.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(id, registration.DCRIDPrefix) {
				t.Fatalf("register: %d %v", res.StatusCode, reg)
			}
			e.oneAuditEvent(t, "client_registered", map[string]any{"outcome": "success", "reason": "dcr", "client_id": id, "remote_ip": "*"})
			if got := counted.list(); !slices.Equal(got, []string{RegistrationOK}) {
				t.Fatalf("counted %v, want [%s]", got, RegistrationOK)
			}

			as := url.Values{"client_id": {id}, "redirect_uri": {fx.Redirect}, "scope": {"mcp offline_access"}}
			if p := e.showConsent(t, as); !strings.Contains(p.body, "Not verified") {
				t.Fatalf("the consent page for a registered client does not say it is not verified: %s", p.body)
			}
			code := e.signIn(t, as).Query().Get("code")
			tok, body := e.redeem(t, code, url.Values{"client_id": {id}, "redirect_uri": {fx.Redirect}})
			if tok.StatusCode != http.StatusOK || body["refresh_token"] == nil {
				t.Fatalf("redeem: %d %v", tok.StatusCode, body)
			}
			c, err := e.st.Client(context.Background(), id)
			if err != nil || !c.UsedAt.Equal(e.now) {
				t.Fatalf("registration after redemption: %+v %v, want UsedAt %v", c, err, e.now)
			}
			e.now = e.now.Add(registration.DCRRenewal)
			if res, body := e.refresh(t, body["refresh_token"].(string), id); res.StatusCode != http.StatusOK {
				t.Fatalf("refresh: %d %v", res.StatusCode, body)
			}
			if c, _ := e.st.Client(context.Background(), id); !c.ExpiresAt.Equal(e.now.Add(registration.DCRLifetime)) {
				t.Fatalf("registration after a refresh a day later expires %v, want %v (renewed)", c.ExpiresAt, e.now.Add(registration.DCRLifetime))
			}
		})
	}
}

// Every refusal is answered in RFC 7591 §3.2.2 JSON, audited and counted, not only successes: an
// open /register is the classic abuse path. A full or failing store is temporary (503 with
// Retry-After), never a refusal of the metadata.
func TestRegistrationRefusalsAreAnsweredAuditedAndCounted(t *testing.T) {
	good := `{"client_name":"App","redirect_uris":["https://app.example/cb"]}`
	for name, tc := range map[string]struct {
		body, contentType string
		opt               func(*Config)
		status            int
		code, outcome     string
		retryAfter        string
		desc              string // how error_description starts, when the reason matters to the client
	}{
		"no acceptable redirect": {body: `{"client_name":"App","redirect_uris":["myapp://cb"]}`, status: 400, code: "invalid_redirect_uri", outcome: RegistrationBadRedirect,
			desc: "no redirect URI passes the redirect policy"},
		"a body over 64 KiB": {body: `{"client_name":"` + strings.Repeat("x", 64<<10) + `","redirect_uris":["https://app.example/cb"]}`, status: 400,
			code: "invalid_client_metadata", outcome: RegistrationBadMetadata, desc: "the request body could not be read"},
		"bad metadata":     {body: `{"redirect_uris":["https://app.example/cb"]}`, status: 400, code: "invalid_client_metadata", outcome: RegistrationBadMetadata, desc: "client_name:"},
		"not sent as JSON": {body: good, contentType: "text/plain", status: 400, code: "invalid_client_metadata", outcome: RegistrationBadMetadata},
		"at the cap":       {body: good, opt: withStore(failingStore(store.ErrFull, "CreateClient")), status: 503, code: "temporarily_unavailable", outcome: RegistrationFull, retryAfter: "60"},
		"store down":       {body: good, opt: withStore(failingStore(errors.New("disk I/O error"), "CreateClient")), status: 503, code: "temporarily_unavailable", outcome: RegistrationUnavailable, retryAfter: "60"},
		"rate-limited": {body: good, opt: func(c *Config) { c.Limiter = stubLimiter{endpoints: map[string]bool{"register": true}} },
			status: 429, code: "temporarily_unavailable", outcome: RegistrationRateLimited, retryAfter: "2"},
	} {
		t.Run(name, func(t *testing.T) {
			counted := &outcomes{}
			opts := []func(*Config){withDCR(counted)}
			if tc.opt != nil {
				opts = append(opts, tc.opt)
			}
			e := newEnv(t, opts...)
			ct := tc.contentType
			if ct == "" {
				ct = "application/json"
			}
			r, _ := http.NewRequest("POST", e.srv.URL+"/register", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", ct)
			res := e.send(t, r)
			var body map[string]string
			_ = json.NewDecoder(res.Body).Decode(&body)
			if res.StatusCode != tc.status || body["error"] != tc.code || !strings.Contains(body["error_description"], "reference ") ||
				res.Header.Get("Retry-After") != tc.retryAfter || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("%d %v, Retry-After %q; want %d %s, Retry-After %q", res.StatusCode, body, res.Header.Get("Retry-After"), tc.status, tc.code, tc.retryAfter)
			}
			if !strings.HasPrefix(body["error_description"], tc.desc) {
				t.Fatalf("error_description %q, want it to start with %q", body["error_description"], tc.desc)
			}
			e.oneAuditEvent(t, "client_registered", map[string]any{"outcome": "failure", "reason": tc.outcome, "remote_ip": "*"})
			if got := counted.list(); !slices.Equal(got, []string{tc.outcome}) {
				t.Fatalf("counted %v, want [%s]", got, tc.outcome)
			}
		})
	}
}

// withStore wires the DCR registry to st (registrations only; the broker keeps its own store).
func withStore(st store.Clients) func(*Config) {
	return func(c *Config) {
		c.Registrar = newDCRFor(st, c.Now)
	}
}

// RFC 7591 §3.2.2 lets the server substitute values: Cursor's cursor:// callback is dropped, the
// registration succeeds, and the operator log says so at info with the client ID, never as an error.
func TestDroppedRedirectsAreLoggedAtInfoWithTheClientID(t *testing.T) {
	for name, tc := range map[string]struct{ body, logged, never string }{
		"cursor":                {body: string(clientdocs.LoadRegistration(t, "cursor").Body), logged: "cursor://anysphere.cursor-mcp/oauth/callback"},
		"with a query":          {body: `{"client_name":"App","redirect_uris":["myapp://cb?secret=s3cr3t","https://app.example/cb"]}`, logged: "myapp://cb", never: "s3cr3t"},
		"with user information": {body: `{"client_name":"App","redirect_uris":["http://u:s3cr3t@evil.example/cb","https://app.example/cb"]}`, logged: "http://evil.example/cb", never: "s3cr3t"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withDCR(nil))
			res, reg := e.register(t, tc.body)
			if res.StatusCode != http.StatusCreated {
				t.Fatalf("register: %d %v", res.StatusCode, reg)
			}
			var line map[string]any
			for _, l := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
				if strings.Contains(l, "dropped redirect URIs") {
					_ = json.Unmarshal([]byte(l), &line)
				}
			}
			reason, _ := line["reason"].(string)
			if line["level"] != "INFO" || line["client_id"] != reg["client_id"] || !strings.Contains(reason, tc.logged) {
				t.Fatalf("dropped-URI log line %v; logs:\n%s", line, e.logs.String())
			}
			// Queries never reach the operator log (ADR-0009 §8), not even in a dropped redirect URI.
			if logs := e.logs.String(); strings.Contains(logs, `"level":"ERROR"`) || (tc.never != "" && strings.Contains(logs, tc.never)) {
				t.Fatalf("a dropped redirect was logged as an error or with its query:\n%s", logs)
			}
		})
	}
}

func TestRegistrationEndpointIsAdvertisedAndServedOnlyWhenOn(t *testing.T) {
	for name, tc := range map[string]struct {
		opts         []func(*Config)
		wantEndpoint any
		wantStatus   int // for a POST that is not JSON
	}{
		"on":  {opts: []func(*Config){withDCR(nil)}, wantEndpoint: issuer + "/register", wantStatus: http.StatusBadRequest},
		"off": {wantEndpoint: nil, wantStatus: http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, tc.opts...)
			res := e.do(t, "GET", "/.well-known/oauth-authorization-server", nil, nil)
			var m map[string]any
			if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
				t.Fatal(err)
			}
			if m["registration_endpoint"] != tc.wantEndpoint {
				t.Fatalf("registration_endpoint = %v, want %v", m["registration_endpoint"], tc.wantEndpoint)
			}
			if reg := e.do(t, "POST", "/register", url.Values{}, nil); reg.StatusCode != tc.wantStatus {
				t.Fatalf("POST /register: %d, want %d", reg.StatusCode, tc.wantStatus)
			}
		})
	}
}

// Browser-based clients (MCP Inspector) register from another origin: the preflight is answered;
// other methods are not allowed.
func TestRegisterAnswersThePreflightAndOnlyPOST(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	pre, _ := http.NewRequest("OPTIONS", e.srv.URL+"/register", nil)
	pre.Header.Set("Origin", "http://localhost:6274")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	res := e.send(t, pre)
	if res.StatusCode != http.StatusNoContent || !strings.Contains(res.Header.Get("Access-Control-Allow-Methods"), "POST") || res.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("preflight: %d %v", res.StatusCode, res.Header)
	}
	if get := e.do(t, "GET", "/register", nil, nil); get.StatusCode != http.StatusMethodNotAllowed || get.Header.Get("Allow") != "POST, OPTIONS" {
		t.Fatalf("GET /register: %d, Allow %q", get.StatusCode, get.Header.Get("Allow"))
	}
}

// A host the operator denies after a client registered stops that client at /authorize and at
// /token: the denylist is checked on every use, not only at registration.
func TestADeniedRedirectHostStopsARegisteredClient(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	_, reg := e.register(t, `{"client_name":"App","redirect_uris":["https://app.example/cb"]}`)
	id := reg["client_id"].(string)
	as := url.Values{"client_id": {id}, "redirect_uri": {"https://app.example/cb"}}
	code := e.signIn(t, as).Query().Get("code")

	e.b.cfg.Clients = registration.Chain{e.reg, newDCRFor(e.st, e.cfg.Now, "app.example")}
	res := e.do(t, "GET", "/authorize?"+authorizeQuery(as).Encode(), nil, nil)
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" || !strings.Contains(string(page), "denylist") {
		t.Fatalf("authorize with a denied redirect host: %d, Location %q: %s", res.StatusCode, res.Header.Get("Location"), page)
	}
	if tok, body := e.redeem(t, code, as); tok.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("redeeming a code for a denied redirect host: %d %v, want 400 invalid_grant", tok.StatusCode, body)
	}
}

// A renewal that fails is logged and never fails the token request: the code and the refresh
// token are still honoured, and the registration simply renews at a later use.
func TestAFailedRenewalNeverFailsTheTokenRequest(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		st := c.Store.(*memstore.Store)
		st.Fail(errors.New("disk I/O error"), "UseClient") // registration renewals fail
		dcr := newDCRFor(st, c.Now)
		c.Clients, c.Registrar = registration.Chain{c.Clients, dcr}, dcr
	})
	_, reg := e.register(t, `{"client_name":"App","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code","refresh_token"]}`)
	id := reg["client_id"].(string)
	as := url.Values{"client_id": {id}, "redirect_uri": {"https://app.example/cb"}, "scope": {"mcp offline_access"}}
	tok, body := e.redeem(t, e.signIn(t, as).Query().Get("code"), as)
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("redeem: %d %v", tok.StatusCode, body)
	}
	if res, b := e.refresh(t, body["refresh_token"].(string), id); res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", res.StatusCode, b)
	}
	if n := strings.Count(e.logs.String(), "renewing a client registration failed"); n != 2 || !strings.Contains(e.logs.String(), `"client_id":"`+id+`"`) {
		t.Fatalf("%d renewal warnings, want 2 with the client ID:\n%s", n, e.logs.String())
	}
}

// A Content-Type parameter (charset) is accepted: it is still JSON.
func TestARegistrationWithACharsetIsAccepted(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	r, _ := http.NewRequest("POST", e.srv.URL+"/register", strings.NewReader(`{"client_name":"App","redirect_uris":["https://app.example/cb"]}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	if res := e.send(t, r); res.StatusCode != http.StatusCreated {
		t.Fatalf("register with a charset: %d, want 201", res.StatusCode)
	}
}

// error_description is capped at 200 characters, even when the reason quotes a long redirect URI.
func TestALongRefusalReasonIsCut(t *testing.T) {
	e := newEnv(t, withDCR(nil, "app.example"))
	long := "https://app.example/" + strings.Repeat("p", 300)
	res, body := e.register(t, `{"client_name":"App","redirect_uris":["`+long+`"]}`)
	desc, _ := body["error_description"].(string)
	reason, _, _ := strings.Cut(desc, " (reference ")
	if res.StatusCode != http.StatusBadRequest || len(reason) != 200 || !strings.HasPrefix(reason, "https://app.example/") {
		t.Fatalf("%d, reason of %d characters: %q", res.StatusCode, len(reason), reason)
	}
}
