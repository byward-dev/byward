package broker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/token"
)

// clientsChangedBy is a registry that returns inner's clients, each changed by change. It hides
// any method the change does not keep, such as Denied.
type clientsChangedBy struct {
	inner  registration.Registry
	change func(registration.Client) registration.Client
}

func (w clientsChangedBy) Client(ctx context.Context, id string) (registration.Client, error) {
	c, err := w.inner.Client(ctx, id)
	if err != nil {
		return nil, err
	}
	return w.change(c), nil
}

// anyRefreshToken is a well-formed refresh token the store does not hold: these tests fail before
// the token is looked up.
var anyRefreshToken = token.RefreshPrefix + strings.Repeat("A", 43)

// storeFailureLogged fails t unless the log holds want ERROR records, and no others, for a client
// registration the store could not read.
func storeFailureLogged(t *testing.T, e *env, want int) {
	t.Helper()
	var n int
	for _, rec := range e.logRecords(t, "loading a client registration failed") {
		if rec["level"] != "ERROR" {
			t.Errorf("store failure logged at %v, want ERROR", rec["level"])
		}
		n++
	}
	if n != want {
		t.Fatalf("%d store failure records, want %d:\n%s", n, want, e.logs.String())
	}
}

// A DCR client's registration that the store cannot read is a store outage, logged at error and
// answered as one: /token says the proxy's store is unavailable with its Retry-After, never that
// the client's metadata could not be fetched, and /authorize shows the 503 page.
func TestADCRLookupStoreFailureIsLoggedAndAnsweredAsAStoreOutage(t *testing.T) {
	e := newEnv(t, withDCR(nil))
	id := registerDCR(t, e, "https://app.example/cb")
	e.st.Fail(errStoreDown, "Client")

	res, body := e.refresh(t, anyRefreshToken, id)
	if res.StatusCode != http.StatusServiceUnavailable || body["error"] != "temporarily_unavailable" ||
		!strings.Contains(body["error_description"].(string), "store is unavailable") || res.Header.Get("Retry-After") != retryAfter {
		t.Fatalf("/token: %d %v Retry-After %q, want 503, the store outage answer and Retry-After %s", res.StatusCode, body, res.Header.Get("Retry-After"), retryAfter)
	}
	storeFailureLogged(t, e, 1)
	if recs := e.logRecords(t, metadataUnavailable); len(recs) != 0 {
		t.Fatalf("/token logged %v, want no client metadata line", recs)
	}

	q := authorizeQuery(url.Values{"client_id": {id}, "redirect_uri": {"https://app.example/cb"}})
	if res := e.do(t, "GET", "/authorize?"+q.Encode(), nil, nil); res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/authorize: %d, want 503", res.StatusCode)
	}
	storeFailureLogged(t, e, 2) // and one more for /authorize
}

// A DCR client's keys at its jwks_uri fail the same way a CIMD client's do, and the operator sees
// why in the log, as for CIMD: refused keys (401) and keys that could not be fetched (503). An
// expired registration is ordinary noise, like an unknown client ID: invalid_client, nothing logged.
func TestADCRClientsFailureIsAnsweredAndLoggedAsForCIMD(t *testing.T) {
	quiet := []string{metadataRefused, metadataUnavailable, "loading a client registration failed"}
	for name, tc := range map[string]struct {
		setup  func(*env)
		status int
		code   string
		logged string // the one line of quiet logged with the jwks_uri cause; "" for none
	}{
		"keys refused": {
			setup:  func(e *env) { e.b.cfg.Clients = clientsChangedBy{e.b.cfg.Clients, func(c registration.Client) registration.Client { return keysBad{c} }} },
			status: http.StatusUnauthorized, code: "invalid_client", logged: metadataRefused,
		},
		"keys unavailable": {
			setup:  func(e *env) { e.b.cfg.Clients = clientsChangedBy{e.b.cfg.Clients, func(c registration.Client) registration.Client { return keysDown{c} }} },
			status: http.StatusServiceUnavailable, code: "temporarily_unavailable", logged: metadataUnavailable,
		},
		"registration expired": {
			setup:  func(e *env) { e.now = e.now.Add(registration.DCRLifetime) },
			status: http.StatusUnauthorized, code: "invalid_client",
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withDCR(nil))
			id := registerDCR(t, e, "https://app.example/cb")
			tc.setup(e)
			if res, body := e.refresh(t, anyRefreshToken, id); res.StatusCode != tc.status || body["error"] != tc.code {
				t.Fatalf("/token: %d %v, want %d %s", res.StatusCode, body, tc.status, tc.code)
			}
			for _, msg := range quiet {
				recs := e.logRecords(t, msg)
				if msg != tc.logged {
					if len(recs) != 0 {
						t.Errorf("logged %v, want no %q line", recs, msg)
					}
					continue
				}
				if len(recs) != 1 || recs[0]["client_id"] != id || !strings.Contains(recs[0]["error"].(string), "jwks_uri answered") {
					t.Errorf("logged %v, want one %q line naming %s with the jwks_uri cause", recs, msg, id)
				}
			}
		})
	}
}
