package broker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/registration"
)

// wrapped is a registry whose clients come from inner, each wrapped by wrap: a DCR client whose
// keys at its jwks_uri fail, without fetching any.
type wrapped struct {
	inner registration.Registry
	wrap  func(registration.Client) registration.Client
}

func (w wrapped) Client(ctx context.Context, id string) (registration.Client, error) {
	c, err := w.inner.Client(ctx, id)
	if err != nil {
		return nil, err
	}
	return w.wrap(c), nil
}

// registerDCR registers a DCR client with one redirect URI in e and returns its client ID.
func registerDCR(t *testing.T, e *env, redirects ...string) string {
	t.Helper()
	res, reg := e.register(t, `{"client_name":"App","redirect_uris":["`+strings.Join(redirects, `","`)+`"],"grant_types":["authorization_code","refresh_token"]}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", res.StatusCode, reg)
	}
	return reg["client_id"].(string)
}

// A DCR client's registration that the store cannot read is a store outage, logged at error and
// answered as one: /token says the proxy's store is unavailable with its Retry-After, never that
// the client's metadata could not be fetched, and /authorize shows the 503 page.
func TestADCRLookupStoreFailureIsLoggedAndAnsweredAsAStoreOutage(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	id := registerDCR(t, e, "https://app.example/cb")
	e.st.Fail(errStoreDown, "Client")

	res, body := e.refresh(t, "byw_rt_"+strings.Repeat("A", 43), id)
	if res.StatusCode != http.StatusServiceUnavailable || body["error"] != "temporarily_unavailable" ||
		!strings.Contains(body["error_description"].(string), "store is unavailable") || res.Header.Get("Retry-After") != retryAfter {
		t.Fatalf("/token: %d %v Retry-After %q, want 503, the store outage answer and Retry-After %s", res.StatusCode, body, res.Header.Get("Retry-After"), retryAfter)
	}
	if logs := e.logs.String(); !strings.Contains(logs, `"level":"ERROR","msg":"loading a client registration failed"`) || strings.Contains(logs, metadataUnavailable) {
		t.Fatalf("/token logs:\n%s\nwant one store failure line, no client metadata line", logs)
	}

	before := len(e.logs.String())
	q := authorizeQuery(url.Values{"client_id": {id}, "redirect_uri": {"https://app.example/cb"}})
	if res := e.do(t, "GET", "/authorize?"+q.Encode(), nil, nil); res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/authorize: %d, want 503", res.StatusCode)
	}
	if logs := e.logs.String()[before:]; !strings.Contains(logs, `"level":"ERROR","msg":"loading a client registration failed"`) {
		t.Fatalf("/authorize logs:\n%s\nwant the store failure line", logs)
	}
}

// A DCR client's keys at its jwks_uri fail the same way a CIMD client's do, and the operator sees
// why in the log, as for CIMD: refused keys (401) and keys that could not be fetched (503).
func TestADCRClientsKeyFailureIsLogged(t *testing.T) {
	for name, tc := range map[string]struct {
		wrap   func(registration.Client) registration.Client
		status int
		msg    string
	}{
		"keys refused":     {wrap: func(c registration.Client) registration.Client { return keysBad{c} }, status: http.StatusUnauthorized, msg: metadataRefused},
		"keys unavailable": {wrap: func(c registration.Client) registration.Client { return keysDown{c} }, status: http.StatusServiceUnavailable, msg: metadataUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withDCR(nil))
			id := registerDCR(t, e, "https://app.example/cb")
			e.b.cfg.Clients = wrapped{e.b.cfg.Clients, tc.wrap}
			if res, body := e.refresh(t, "byw_rt_"+strings.Repeat("A", 43), id); res.StatusCode != tc.status {
				t.Fatalf("/token: %d %v, want %d", res.StatusCode, body, tc.status)
			}
			if logs := e.logs.String(); !strings.Contains(logs, `"msg":"`+tc.msg+`"`) || !strings.Contains(logs, "jwks_uri answered") {
				t.Fatalf("logs:\n%s\nwant %q with the cause", logs, tc.msg)
			}
		})
	}
}

// An expired DCR registration is ordinary noise, like an unknown client ID: the client gets
// invalid_client and the operator log stays quiet.
func TestAnExpiredDCRRegistrationIsNotLogged(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	id := registerDCR(t, e, "https://app.example/cb")
	e.now = e.now.Add(registration.DCRLifetime)
	if res, body := e.refresh(t, "byw_rt_"+strings.Repeat("A", 43), id); res.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("/token: %d %v, want 401 invalid_client", res.StatusCode, body)
	}
	if logs := e.logs.String(); strings.Contains(logs, metadataRefused) || strings.Contains(logs, metadataUnavailable) || strings.Contains(logs, "client registration") {
		t.Fatalf("logs:\n%s\nwant nothing about the expired client", logs)
	}
}
