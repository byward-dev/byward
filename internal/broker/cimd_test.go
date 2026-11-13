package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
)

// withCIMD resolves CIMD clients from documents served by srv, after the static clients.
func withCIMD(srv *clientdocs.Server, trusted ...string) func(*Config) {
	return func(c *Config) {
		guard := ssrfguard.New(ssrfguard.Config{RootCAs: srv.RootCAs, Dial: srv.Dial})
		c.Clients = registration.Chain{c.Clients, registration.NewCIMDRegistry(registration.CIMDConfig{Fetch: guard,
			KeysClient: guard.HTTPClient(), TrustedHosts: trusted, JTI: registration.NewStoreJTICache(memory.New()), Now: time.Now})}
		c.CIMD = true
	}
}

// Each real client's published document signs a user in and redeems the code with PKCE and no
// client secret, returning to a redirect URI the document registered.
func TestRealCIMDClientsSignInAndRedeem(t *testing.T) {
	for _, name := range clientdocs.Names {
		t.Run(name, func(t *testing.T) {
			d := clientdocs.Load(t, name)
			redirect := d.Redirect
			srv := clientdocs.Serve(t, d)
			e := newEnv(t, withCIMD(srv))
			back := e.signIn(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {redirect}})
			if got := back.Scheme + "://" + back.Host + back.Path; got != redirect {
				t.Fatalf("returned to %s, want %s", got, redirect)
			}
			res, body := e.redeem(t, back.Query().Get("code"), url.Values{"client_id": {d.ClientID}, "redirect_uri": {redirect}})
			if res.StatusCode != http.StatusOK || body["access_token"] == nil {
				t.Fatalf("token: %d %v", res.StatusCode, body)
			}
			if n := srv.Hits(d.ClientID); n != 1 {
				t.Fatalf("document fetched %d times, want once (cached between /authorize and /token)", n)
			}
		})
	}
}

func TestCIMDClientCannotUseAnUnregisteredRedirect(t *testing.T) {
	d := clientdocs.Load(t, "claude-ai")
	srv := clientdocs.Serve(t, d)
	e := newEnv(t, withCIMD(srv))
	q := authorizeQuery(url.Values{"client_id": {d.ClientID}, "redirect_uri": {"https://evil.example/cb"}})
	res := e.do(t, "GET", "/authorize?"+q.Encode(), nil, nil)
	body, _ := io.ReadAll(res.Body)
	// The document was fetched and its redirect URIs applied: not a failed lookup, which is also a 400.
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" || !strings.Contains(string(body), "does not allow") || srv.Hits(d.ClientID) != 1 {
		t.Fatalf("status %d, Location %q, fetches %d: %s", res.StatusCode, res.Header.Get("Location"), srv.Hits(d.ClientID), body)
	}
}

func TestMetadataAdvertisesCIMDOnlyWhenOn(t *testing.T) {
	for name, on := range map[string]bool{"advertised when on": true, "not advertised when off": false} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.CIMD = on })
			res := e.do(t, "GET", "/.well-known/oauth-authorization-server", nil, nil)
			var m map[string]any
			if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
				t.Fatal(err)
			}
			if m["client_id_metadata_document_supported"] != on {
				t.Fatalf("client_id_metadata_document_supported = %v, want %v", m["client_id_metadata_document_supported"], on)
			}
		})
	}
}

// A transient failure is never a redirect and never invalid_client (draft -03 §6.1).
func TestTransientMetadataFailuresAreServiceUnavailable(t *testing.T) {
	const id = "https://app.example/client.json"
	mode := new(atomic.Int32)
	mode.Store(modeUnavailable)
	e := newEnv(t, func(c *Config) { c.Clients = switchable{c.Clients, mode} })
	q := authorizeQuery(url.Values{"client_id": {id}, "redirect_uri": {"https://app.example/cb"}})
	res := e.do(t, "GET", "/authorize?"+q.Encode(), nil, nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Location") != "" || !strings.Contains(string(body), "Try again") {
		t.Fatalf("authorize: %d, Location %q, %s", res.StatusCode, res.Header.Get("Location"), body)
	}
	if logs := e.logs.String(); !strings.Contains(logs, metadataUnavailable) || strings.Contains(logs, metadataRefused) {
		t.Fatalf("/authorize should log a temporary failure, not a refusal: %s", logs)
	}
	before := len(e.logs.String())
	tok, tb := e.redeem(t, "any", url.Values{"client_id": {id}})
	if tok.StatusCode != http.StatusServiceUnavailable || tb["error"] != "temporarily_unavailable" || tok.Header.Get("Retry-After") != "60" {
		t.Fatalf("token: %d %v, Retry-After %q", tok.StatusCode, tb, tok.Header.Get("Retry-After"))
	}
	if logs := e.logs.String()[before:]; !strings.Contains(logs, metadataUnavailable) || strings.Contains(logs, metadataRefused) {
		t.Fatalf("/token should log a temporary failure, not a refusal: %s", logs)
	}
}

const appDoc = "https://app.example.com/oauth/client.json"

func appDocument() clientdocs.Doc {
	body, _ := json.Marshal(map[string]any{"client_id": appDoc, "client_name": "Example App",
		"redirect_uris": []string{"https://auth.example.com/cb", "https://evil.example/cb", "http://127.0.0.1/cb"}})
	return clientdocs.Doc{ClientID: appDoc, Body: body, Header: http.Header{"Cache-Control": {"max-age=300"}}}
}

// The consent page names the host that published the app's document and warns when the app
// returns outside that host's registrable domain (ADR-0010 §4, amended 2026-11-06).
func TestCIMDConsentNamesThePublisherAndWarnsWhenTheAppReturnsElsewhere(t *testing.T) {
	const otherSite, loopbackWarning = "This app returns to", "Only allow this if you just started"
	for name, tc := range map[string]struct {
		redirect string
		warning  string // the exact other-site warning, or "" for none
		loopback bool
	}{
		"same registrable domain":      {redirect: "https://auth.example.com/cb"},
		"another site":                 {redirect: "https://evil.example/cb", warning: "This app returns to evil.example, which is not part of app.example.com."},
		"loopback has its own warning": {redirect: "http://127.0.0.1:41000/cb", loopback: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withCIMD(clientdocs.Serve(t, appDocument())))
			text := visibleText(e.showConsent(t, url.Values{"client_id": {appDoc}, "redirect_uri": {tc.redirect}}).body)
			if !strings.Contains(text, "Published by app.example.com") || !strings.Contains(text, "Identified by its web address") {
				t.Fatalf("page: %s", text)
			}
			if tc.warning == "" && strings.Contains(text, otherSite) || tc.warning != "" && !strings.Contains(text, tc.warning) {
				t.Fatalf("want other-site warning %q: %s", tc.warning, text)
			}
			if strings.Contains(text, loopbackWarning) != tc.loopback {
				t.Fatalf("loopback warning shown: %v, want %v: %s", !tc.loopback, tc.loopback, text)
			}
		})
	}
}

func TestATrustedCIMDHostIsLabelledTrustedAndStaticClientsHaveNoPublisher(t *testing.T) {
	d := clientdocs.Load(t, "claude-ai")
	e := newEnv(t, withCIMD(clientdocs.Serve(t, d), "claude.ai"))
	text := visibleText(e.showConsent(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}}).body)
	if !strings.Contains(text, "Trusted by your operator") || !strings.Contains(text, "Published by claude.ai") || strings.Contains(text, "This app returns to") {
		t.Fatalf("trusted CIMD page: %s", text)
	}
	if text := visibleText(e.showConsent(t, nil).body); strings.Contains(text, "Published by") {
		t.Fatalf("static client page names a publisher: %s", text)
	}
}

func TestOtherSiteComparesRegistrableDomains(t *testing.T) {
	for _, c := range []struct {
		cimd, redirect string
		other          bool
	}{
		{"claude.ai", "https://claude.ai/api/mcp/auth_callback", false},
		{"app.example.com", "https://auth.example.com/cb", false},
		{"App.Example.com", "https://auth.EXAMPLE.com/cb", false},
		{"claude.ai", "https://evil.example/cb", true},
		{"claude.ai", "https://claude.ai.evil.example/cb", true},
		{"alice.github.io", "https://bob.github.io/cb", true}, // github.io is a public suffix
		{"github.io", "https://gitlab.io/cb", true},           // public suffixes themselves: compared exactly
		{"github.io", "https://github.io/cb", false},
		{"example.co.uk", "https://other.co.uk/cb", true},
		{"203.0.113.7", "https://203.0.113.7/cb", false}, // no registrable domain: compared exactly
		{"203.0.113.7", "https://203.0.113.8/cb", true},
		{"198.51.3.4", "https://203.0.3.4/cb", true}, // the default suffix rule would make both "3.4"
		{"2001:db8::1", "https://[2001:db8::1]/cb", false},
		{"claude.ai", "://bad", true},
	} {
		if got := otherSite(c.cimd, c.redirect); got != c.other {
			t.Errorf("otherSite(%q, %q) = %v, want %v", c.cimd, c.redirect, got, c.other)
		}
	}
}

func TestThePublisherIsShownReadably(t *testing.T) {
	for in, want := range map[string]string{
		"claude.ai":             "claude.ai",
		"xn--bcher-kva.example": "bücher.example (xn--bcher-kva.example)",
	} {
		if got := showHost(in); got != want {
			t.Errorf("showHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// A look-alike publisher shows its Unicode spelling beside the xn-- name the browser uses.
func TestAPunycodePublisherIsShownBesideItsUnicodeSpelling(t *testing.T) {
	const id = "https://xn--bcher-kva.example/client.json"
	body, _ := json.Marshal(map[string]any{"client_id": id, "client_name": "Bücher", "redirect_uris": []string{"https://xn--bcher-kva.example/cb"}})
	e := newEnv(t, withCIMD(clientdocs.Serve(t, clientdocs.Doc{ClientID: id, Body: body})))
	text := visibleText(e.showConsent(t, url.Values{"client_id": {id}, "redirect_uri": {"https://xn--bcher-kva.example/cb"}}).body)
	if !strings.Contains(text, "Published by bücher.example (xn--bcher-kva.example)") || strings.Contains(text, "This app returns to") {
		t.Fatalf("page: %s", text)
	}
}

// Metadata modes for switchable.
const (
	modeOK              int32 = iota
	modeUnavailable           // a transient fetch failure
	modeRefused               // a terminal one: the document now mismatches
	modeNoRefresh             // the document no longer lists the refresh_token grant
	modeUnknown               // any client unknown without a refused document (CIMD off, allowlist, removed static client)
	modeKeysUnavailable       // the client resolves, but its jwks_uri cannot be fetched for now
	modeKeysRefused           // the client resolves, but the keys at its jwks_uri are unusable
	modeBadAssertion          // the client resolves, but its assertion is wrong
	modeReplayCheckDown       // the client resolves, but the store cannot check its assertion for replay
)

// switchable resolves clients through inner, or fails or changes them as its mode says: modeUnknown
// for every client, the other modes for CIMD client IDs only.
type switchable struct {
	inner registration.Registry
	mode  *atomic.Int32
}

func (s switchable) Client(ctx context.Context, id string) (registration.Client, error) {
	if s.mode.Load() == modeUnknown {
		return nil, registration.ErrUnknownClient
	}
	if !registration.IsCIMDURL(id) {
		return s.inner.Client(ctx, id)
	}
	switch s.mode.Load() {
	case modeUnavailable:
		return nil, fmt.Errorf("%w: refetch timed out", registration.ErrUnavailable)
	case modeRefused:
		return nil, fmt.Errorf("%w: client_id does not match the document URL", registration.ErrMetadataRefused)
	}
	c, err := s.inner.Client(ctx, id)
	if err == nil && s.mode.Load() == modeNoRefresh {
		return noRefresh{c}, nil
	}
	if err == nil && s.mode.Load() == modeKeysUnavailable {
		return keysDown{c}, nil
	}
	if err == nil && s.mode.Load() == modeKeysRefused {
		return keysBad{c}, nil
	}
	if err == nil && s.mode.Load() == modeBadAssertion {
		return badAssertion{c}, nil
	}
	if err == nil && s.mode.Load() == modeReplayCheckDown {
		return replayCheckDown{c}, nil
	}
	return c, err
}

type noRefresh struct{ registration.Client }

func (noRefresh) AllowsRefresh() bool { return false }

type badAssertion struct{ registration.Client }

func (badAssertion) Authenticate(context.Context, url.Values, http.Header, string, time.Time) error {
	return fmt.Errorf("%w: bad signature", registration.ErrInvalidClient)
}

type replayCheckDown struct{ registration.Client }

func (replayCheckDown) Authenticate(context.Context, url.Values, http.Header, string, time.Time) error {
	return fmt.Errorf("%w: store down", registration.ErrReplayCheckUnavailable)
}

type keysBad struct{ registration.Client }

func (keysBad) Authenticate(context.Context, url.Values, http.Header, string, time.Time) error {
	return fmt.Errorf("%w: jwks_uri answered 404", registration.ErrKeysRefused)
}

type keysDown struct{ registration.Client }

func (keysDown) Authenticate(context.Context, url.Values, http.Header, string, time.Time) error {
	return fmt.Errorf("%w: client assertion keys: jwks_uri answered 503", registration.ErrUnavailable)
}

// The consent answer looks the client up again; a transient failure then is a 503, not a 500.
func TestATransientFailureAtTheConsentAnswerIsServiceUnavailable(t *testing.T) {
	var mode atomic.Int32
	cimd := withCIMD(clientdocs.Serve(t, appDocument()))
	e := newEnv(t, func(c *Config) { cimd(c); c.Clients = switchable{c.Clients, &mode} })
	p := e.showConsent(t, url.Values{"client_id": {appDoc}, "redirect_uri": {"https://auth.example.com/cb"}})
	e.now = e.now.Add(ConsentDelay)
	before := len(e.logs.String())
	mode.Store(modeUnavailable)
	res := e.answer(t, p, "allow", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "Try again") || res.Header.Get("Location") != "" {
		t.Fatalf("consent answer: %d, Location %q, %s", res.StatusCode, res.Header.Get("Location"), body)
	}
	if logs := e.logs.String()[before:]; !strings.Contains(logs, metadataUnavailable) || strings.Contains(logs, metadataRefused) {
		t.Fatalf("the consent answer should log a temporary failure, not a refusal: %s", logs)
	}
}

// Only CIMD refusals are logged, with their reason; an unknown static client ID is ordinary noise.
// Both lookups end in ErrUnknownClient: only the shape of the client ID differs.
func TestOnlyCIMDRefusalsAreLoggedWithTheirReason(t *testing.T) {
	for name, tc := range map[string]struct {
		clientID string
		logged   string // "" means nothing is logged
	}{
		"unknown static client":       {clientID: "nobody"},
		"CIMD document that is a 404": {clientID: "https://app.example.com/oauth/missing.json", logged: "answered HTTP status 404"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withCIMD(clientdocs.Serve(t, appDocument()))) // app.example.com serves only appDoc
			res := e.do(t, "GET", "/authorize?"+authorizeQuery(url.Values{"client_id": {tc.clientID}}).Encode(), nil, nil)
			logs := e.logs.String()
			if res.StatusCode != http.StatusBadRequest || strings.Contains(logs, metadataRefused) != (tc.logged != "") || !strings.Contains(logs, tc.logged) {
				t.Fatalf("status %d, want the log to say %q: %s", res.StatusCode, tc.logged, logs)
			}
		})
	}
}

// offlineCIMD signs a user in with the claude.ai document and offline_access and returns the
// redeemed token response; mode switches the client's metadata afterwards.
func offlineCIMD(t *testing.T) (e *env, d clientdocs.Doc, mode *atomic.Int32, tokens map[string]any) {
	t.Helper()
	d = clientdocs.Load(t, "claude-ai")
	mode = new(atomic.Int32)
	cimd := withCIMD(clientdocs.Serve(t, d))
	e = newEnv(t, func(c *Config) { cimd(c); c.Clients = switchable{c.Clients, mode} })
	back := e.signIn(t, url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}, "scope": {"mcp offline_access"}})
	res, body := e.redeem(t, back.Query().Get("code"), url.Values{"client_id": {d.ClientID}, "redirect_uri": {d.Redirect}})
	if res.StatusCode != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("redeem: %d %v", res.StatusCode, body)
	}
	return e, d, mode, body
}

// Draft -03 §6.1: a terminal metadata failure revokes the grant behind the presented refresh token,
// so restoring the document cannot revive it; a transient failure never does.
func TestARefusedCIMDClientLosesItsGrantButATransientFailureDoesNot(t *testing.T) {
	for name, tc := range map[string]struct {
		mode          int32
		status        int // of the refresh while the metadata fails
		revoked       bool
		afterRecovery int // of the same refresh once the metadata is back
	}{
		"transient failure": {mode: modeUnavailable, status: http.StatusServiceUnavailable, afterRecovery: http.StatusOK},
		"terminal failure":  {mode: modeRefused, status: http.StatusUnauthorized, revoked: true, afterRecovery: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			e, d, mode, tokens := offlineCIMD(t)
			rt := tokens["refresh_token"].(string)
			mode.Store(tc.mode)
			if res, body := e.refresh(t, rt, d.ClientID); res.StatusCode != tc.status {
				t.Fatalf("refresh while failing: %d %v, want %d", res.StatusCode, body, tc.status)
			}
			revocations := e.auditEvents(t, "grant_revoked")
			if (len(revocations) == 1) != tc.revoked || (tc.revoked && revocations[0]["reason"] != "client metadata no longer valid") {
				t.Fatalf("grant_revoked events %v, want revoked %v", revocations, tc.revoked)
			}
			mode.Store(modeOK)
			if res, body := e.refresh(t, rt, d.ClientID); res.StatusCode != tc.afterRecovery {
				t.Fatalf("refresh after the metadata is back: %d %v, want %d", res.StatusCode, body, tc.afterRecovery)
			}
		})
	}
}

// Only a refused metadata document revokes. A client that is unknown for any other reason (CIMD
// switched off, its host taken off the allowlist, a static client removed from config) keeps its
// grant, even when it presents its own token, and refreshes again once it is back.
func TestAnUnknownClientThatIsNotARefusedDocumentRevokesNothing(t *testing.T) {
	for name, signIn := range map[string]func(t *testing.T) (*env, *atomic.Int32, string, string){
		"CIMD client": func(t *testing.T) (*env, *atomic.Int32, string, string) {
			e, d, mode, tokens := offlineCIMD(t)
			return e, mode, d.ClientID, tokens["refresh_token"].(string)
		},
		"static client": func(t *testing.T) (*env, *atomic.Int32, string, string) {
			mode := new(atomic.Int32)
			e := newEnv(t, func(c *Config) { c.Clients = switchable{c.Clients, mode} })
			return e, mode, clientID, e.offline(t)["refresh_token"].(string)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, mode, id, rt := signIn(t)
			mode.Store(modeUnknown)
			if res, _ := e.refresh(t, rt, id); res.StatusCode != http.StatusUnauthorized || len(e.auditEvents(t, "grant_revoked")) != 0 {
				t.Fatalf("status %d, revocations %v", res.StatusCode, e.auditEvents(t, "grant_revoked"))
			}
			mode.Store(modeOK)
			if res, body := e.refresh(t, rt, id); res.StatusCode != http.StatusOK {
				t.Fatalf("refresh once the client is back: %d %v", res.StatusCode, body)
			}
		})
	}
}

// A CIMD client whose document does not list refresh_token gets no refresh token, is told so on the
// consent page, and is refused at refresh if its document drops the grant later (draft -03 §6).
func TestRefreshNeedsTheRefreshTokenGrant(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"client_id": appDoc, "client_name": "Example App", "grant_types": []string{"authorization_code"},
		"redirect_uris": []string{"https://auth.example.com/cb"}})
	e := newEnv(t, withCIMD(clientdocs.Serve(t, clientdocs.Doc{ClientID: appDoc, Body: body})))
	q := url.Values{"client_id": {appDoc}, "redirect_uri": {"https://auth.example.com/cb"}, "scope": {"mcp offline_access"}}
	if text := visibleText(e.showConsent(t, q).body); !strings.Contains(text, "up to 1 hour") {
		t.Fatalf("consent lifetime: %s", text)
	}
	back := e.signIn(t, q)
	if res, tok := e.redeem(t, back.Query().Get("code"), url.Values{"client_id": {appDoc}, "redirect_uri": {"https://auth.example.com/cb"}}); res.StatusCode != http.StatusOK || tok["refresh_token"] != nil || tok["scope"] != "mcp" {
		t.Fatalf("redeem: %d %v, want an access token only, scope mcp (offline_access not granted)", res.StatusCode, tok)
	}

	e2, d, mode, tokens := offlineCIMD(t)
	mode.Store(modeNoRefresh)
	if res, b := e2.refresh(t, tokens["refresh_token"].(string), d.ClientID); res.StatusCode != http.StatusBadRequest || b["error"] != "unauthorized_client" {
		t.Fatalf("refresh without the grant: %d %v", res.StatusCode, b)
	}
}

// A refused CIMD client ID cannot revoke a grant it does not own: another client's refresh token
// presented under it is left alone.
func TestARefusedCIMDClientCannotRevokeAnotherClientsGrant(t *testing.T) {
	mode := new(atomic.Int32)
	mode.Store(modeRefused)
	e := newEnv(t, func(c *Config) { c.Clients = switchable{c.Clients, mode} })
	rt := e.offline(t)["refresh_token"].(string) // the static client's
	if res, _ := e.refresh(t, rt, appDoc); res.StatusCode != http.StatusUnauthorized || len(e.auditEvents(t, "grant_revoked")) != 0 {
		t.Fatalf("status %d, revocations %v", res.StatusCode, e.auditEvents(t, "grant_revoked"))
	}
	if res, body := e.refresh(t, rt, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("the static client's own refresh: %d %v", res.StatusCode, body)
	}
}

// A jwks_uri that cannot be fetched for now is a 503 at /token, like the document itself (draft
// -03 §6.1), logged as a temporary failure; one whose keys are unusable is invalid_client, logged as
// a refusal. Neither revokes the grant.
func TestClientKeyFailuresAreClassifiedAndLogged(t *testing.T) {
	for name, tc := range map[string]struct {
		mode   int32
		status int
		code   string
		logged string
	}{
		"keys unavailable for now": {mode: modeKeysUnavailable, status: http.StatusServiceUnavailable, code: "temporarily_unavailable", logged: metadataUnavailable},
		"keys refused":             {mode: modeKeysRefused, status: http.StatusUnauthorized, code: "invalid_client", logged: metadataRefused},
		"a wrong assertion":        {mode: modeBadAssertion, status: http.StatusUnauthorized, code: "invalid_client"},
	} {
		t.Run(name, func(t *testing.T) {
			e, d, mode, tokens := offlineCIMD(t)
			mode.Store(tc.mode)
			before := len(e.logs.String())
			res, body := e.refresh(t, tokens["refresh_token"].(string), d.ClientID)
			logs := e.logs.String()[before:]
			metadataLogged := strings.Contains(logs, metadataRefused) || strings.Contains(logs, metadataUnavailable)
			if res.StatusCode != tc.status || body["error"] != tc.code || !strings.Contains(logs, tc.logged) || metadataLogged != (tc.logged != "") ||
				len(e.auditEvents(t, "grant_revoked")) != 0 {
				t.Fatalf("status %d %v, logs %s", res.StatusCode, body, logs)
			}
			if want := map[bool]string{true: "60"}[tc.status == http.StatusServiceUnavailable]; res.Header.Get("Retry-After") != want {
				t.Fatalf("Retry-After %q on a %d", res.Header.Get("Retry-After"), res.StatusCode)
			}
		})
	}
}

// A replay check the store cannot answer is a store outage, not a refused client: /token answers 503
// with the store's Retry-After and logs it (ADR-0007 §7); the grant survives and works once the store
// is back.
func TestAReplayCheckTheStoreCannotAnswerIsAStoreOutage(t *testing.T) {
	e, d, mode, tokens := offlineCIMD(t)
	rt := tokens["refresh_token"].(string)
	mode.Store(modeReplayCheckDown)
	before := len(e.logs.String())
	res, body := e.refresh(t, rt, d.ClientID)
	if res.StatusCode != http.StatusServiceUnavailable || body["error"] != "temporarily_unavailable" || res.Header.Get("Retry-After") != "5" ||
		!strings.Contains(e.logs.String()[before:], "client assertion replay check failed") {
		t.Fatalf("status %d %v, Retry-After %q (want 503, temporarily_unavailable, 5 and the log line), logs %s", res.StatusCode, body, res.Header.Get("Retry-After"), e.logs.String()[before:])
	}
	if n := len(e.auditEvents(t, "grant_revoked")); n != 0 {
		t.Fatalf("grant_revoked events = %d, want 0: a store outage revokes nothing", n)
	}
	mode.Store(modeOK)
	if res, body := e.refresh(t, rt, d.ClientID); res.StatusCode != http.StatusOK {
		t.Fatalf("once the store is back: %d %v", res.StatusCode, body)
	}
}
