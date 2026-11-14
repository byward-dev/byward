package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// signInFailing has the IdP fail the code redemption with f and runs a sign-in to its error page.
func signInFailing(t *testing.T, e *env, f fakeidp.Failure) {
	t.Helper()
	e.fake.Set(fakeidp.FailToken(fakeidp.GrantAuthorizationCode, &f))
	ck, cb := e.startLogin(t, nil)
	if res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{ck}); res.StatusCode != http.StatusBadGateway {
		t.Fatalf("callback answered %d, want the IdP failure page (502)", res.StatusCode)
	}
}

// refreshFailing signs in, has the IdP fail the refresh with f, and refreshes.
func refreshFailing(t *testing.T, e *env, f fakeidp.Failure) {
	t.Helper()
	rt := e.offline(t)["refresh_token"].(string)
	e.fake.Set(fakeidp.FailToken(fakeidp.GrantRefreshToken, &f))
	if res, body := e.refresh(t, rt, ""); res.StatusCode == http.StatusOK {
		t.Fatalf("the refresh succeeded despite the IdP failure: %v", body)
	}
}

// failingCallback is the IdP with its code redemption answering err: for alert reasons the fake IdP
// cannot produce at the callback.
type failingCallback struct {
	IdP
	err error
}

func (f failingCallback) Callback(context.Context, url.Values, idp.Login) (idp.Identity, idp.Tokens, error) {
	return idp.Identity{}, idp.Tokens{}, f.err
}

// callbackFailingWith restarts the broker with its IdP's code redemption answering err, then signs
// in to the error page.
func callbackFailingWith(err error) func(*testing.T, *env, fakeidp.Failure) {
	return func(t *testing.T, e *env, _ fakeidp.Failure) {
		t.Helper()
		cfg := e.cfg
		cfg.IdP = failingCallback{IdP: cfg.IdP, err: err}
		e.start(t, cfg)
		ck, cb := e.startLogin(t, nil)
		if res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{ck}); res.StatusCode != http.StatusBadGateway {
			t.Fatalf("callback answered %d, want the IdP failure page (502)", res.StatusCode)
		}
	}
}

// refreshFailingWith signs in, restarts the broker with its IdP's refresh answering err (for
// errors the fake IdP cannot produce at a refresh), and refreshes.
func refreshFailingWith(err error) func(*testing.T, *env, fakeidp.Failure) {
	return func(t *testing.T, e *env, _ fakeidp.Failure) {
		t.Helper()
		rt := e.offline(t)["refresh_token"].(string)
		cfg := e.cfg
		cfg.IdP = refresherFunc{IdP: cfg.IdP, refresh: func(context.Context, string) (*idp.Identity, idp.Tokens, error) {
			return nil, idp.Tokens{}, err
		}}
		e.start(t, cfg)
		if res, body := e.refresh(t, rt, ""); res.StatusCode == http.StatusOK {
			t.Fatalf("the refresh succeeded despite the IdP failure: %v", body)
		}
	}
}

// forgedCallback sends the callback a browser could forge: f's error and code as the IdP's own, in
// the query.
func forgedCallback(t *testing.T, e *env, f fakeidp.Failure) {
	t.Helper()
	ck, cb := e.startLogin(t, nil)
	q := cb.Query()
	q.Del("code")
	q.Set("error", f.Error)
	q.Set("error_description", fmt.Sprintf("AADSTS%d: forged.", f.Code))
	if res := e.do(t, "GET", "/callback/entra?"+q.Encode(), nil, []*http.Cookie{ck}); res.StatusCode != http.StatusBadGateway {
		t.Fatalf("callback answered %d, want the IdP failure page (502)", res.StatusCode)
	}
}

// #204: an IdP error that only the operator can fix (here Entra rejecting the proxy's client
// secret at its token endpoint) is counted and logged as an alert that names the fix, for a sign-in
// and for a refresh. An outage the IdP recovers from on its own is not, nor is an error in the
// callback query, which anyone can forge.
func TestIdPErrorsThatNeedTheOperatorRaiseAnAlert(t *testing.T) {
	cases := []struct {
		name    string
		drive   func(*testing.T, *env, fakeidp.Failure)
		failure fakeidp.Failure
		want    string // "operation reason", or "" for no alert
		fix     string // the whole reason on the alert line and on the failure's own line
	}{
		// AADSTS7000215 has no operator hint of its own, so the alert's default fix stands in.
		{"sign-in, client secret rejected", signInFailing, fakeidp.InvalidClientSecret, "callback credential_rejected", idp.AlertCredentialRejected.Hint()},
		// Entra's own hint wins over the default, on the sign-in failure line too.
		{"sign-in, client secret expired", signInFailing, fakeidp.ExpiredClientSecret, "callback credential_rejected", "AADSTS7000222: the client secret has expired; create a new one (or switch to a certificate)."},
		{"sign-in, IdP unavailable", signInFailing, fakeidp.TemporarilyUnavailable, "", ""},
		// Auth0 refuses a wrong secret with access_denied 401 (#315): the IdP failure page, not "the
		// user declined", since the alert says the credential was refused.
		{"sign-in, Auth0 wrong secret", callbackFailingWith(&idp.Error{Class: idp.Fatal, OAuth: "access_denied", Status: 401, Alert: idp.AlertCredentialRejected}),
			fakeidp.Failure{}, "callback credential_rejected", idp.AlertCredentialRejected.Hint()},
		{"refresh, Auth0 wrong secret", refreshFailingWith(&idp.Error{Class: idp.Fatal, OAuth: "access_denied", Status: 401, Alert: idp.AlertCredentialRejected}),
			fakeidp.Failure{}, "refresh credential_rejected", idp.AlertCredentialRejected.Hint()},
		{"refresh, client secret rejected", refreshFailing, fakeidp.InvalidClientSecret, "refresh credential_rejected", idp.AlertCredentialRejected.Hint()},
		// Entra's own hint wins over the default.
		{"refresh, client secret expired", refreshFailing, fakeidp.ExpiredClientSecret, "refresh credential_rejected", "AADSTS7000222: the client secret has expired; create a new one (or switch to a certificate)."},
		{"refresh, IdP unavailable", refreshFailing, fakeidp.TemporarilyUnavailable, "", ""},
		// The other reasons pass through as they are, each with its own fix.
		{"sign-in, IdP protocol violation", callbackFailingWith(&idp.Error{Class: idp.Fatal, Alert: idp.AlertProtocol}), fakeidp.Failure{},
			"callback protocol", idp.AlertProtocol.Hint()},
		{"sign-in, credential unusable", callbackFailingWith(&idp.Error{Class: idp.Unavailable, Alert: idp.AlertCredentialUnusable}), fakeidp.Failure{},
			"callback credential_unusable", idp.AlertCredentialUnusable.Hint()},
		{"forged callback, invalid_client", forgedCallback, fakeidp.InvalidClientSecret, "", ""},
		{"forged callback, unauthorized_client", forgedCallback, fakeidp.UnknownClient, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.drive(t, e, c.failure)
			logs := e.logs.String()
			// With no fix to name, a failure line (sign-in or refresh) leaves the reason out rather than log it empty.
			if strings.Contains(logs, `"reason":""`) {
				t.Errorf("a log line has an empty reason:\n%s", logs)
			}
			if c.want == "" {
				if len(e.alerts) != 0 || strings.Contains(logs, `"alert":`) {
					t.Fatalf("no alert wanted, got %v:\n%s", e.alerts, logs)
				}
				return
			}
			if fmt.Sprint(e.alerts) != fmt.Sprint([]string{c.want}) {
				t.Fatalf("alerts = %v, want [%s]", e.alerts, c.want)
			}
			op, reason, _ := strings.Cut(c.want, " ")
			lines := regexp.MustCompile(`(?m)^.*"msg":"IdP alert: the operator must act".*$`).FindAllString(logs, -1)
			if len(lines) != 1 {
				t.Fatalf("want one alert line, got %d:\n%s", len(lines), logs)
			}
			line := lines[0]
			for _, want := range []string{`"level":"ERROR"`, `"idp":"entra"`, `"operation":"` + op + `"`, `"alert":"` + reason + `"`} {
				if !strings.Contains(line, want) {
					t.Errorf("the alert line lacks %s:\n%s", want, logs)
				}
			}
			if !strings.Contains(line, `"reason":"`+c.fix+`"`) {
				t.Errorf("the alert line's reason is not %q:\n%s", c.fix, logs)
			}
			// The failure's own line names the same fix (#315: it was empty when only the alert had one).
			msg := map[string]string{"callback": "IdP sign-in failed", "refresh": "IdP refresh (unavailable|failed)"}[op]
			if failed := regexp.MustCompile(`(?m)^.*"msg":"` + msg + `".*$`).FindString(logs); !strings.Contains(failed, `"reason":"`+c.fix+`"`) {
				t.Errorf("the %q line's reason is not %q:\n%s", msg, c.fix, logs)
			}
		})
	}
}

// #204: every IdP call the broker observes is one of IdPOperations, so its alert series is exported
// at 0 from the start.
func TestEveryBrokerIdPCallIsExportedFromTheStart(t *testing.T) {
	e := newEnv(t)
	e.offline(t) // authorize and callback
	refreshFailing(t, e, fakeidp.InvalidClientSecret)
	seen := map[string]bool{}
	for _, o := range e.idpOps {
		op, _, _ := strings.Cut(o, " ")
		seen[op] = true
		if !slices.Contains(IdPOperations, op) {
			t.Errorf("the broker observed the IdP call %q, which IdPOperations does not list", op)
		}
	}
	for _, op := range IdPOperations {
		if !seen[op] {
			t.Errorf("IdPOperations lists %q, which no sign-in or refresh observed", op)
		}
	}
}

// #342: a refresh error of no known kind (not an *idp.Error, such as a bug in an adapter) is the
// proxy's own failure: a 500 server_error that keeps the grant, logged at error level with the
// request and the error but no fix to name, and no alert.
func TestARefreshErrorOfNoKnownKindIsAServerErrorLoggedWithoutAFix(t *testing.T) {
	e := newEnv(t)
	rt := e.offline(t)["refresh_token"].(string)
	working, cfg := e.cfg, e.cfg
	cfg.IdP = refresherFunc{IdP: cfg.IdP, refresh: func(context.Context, string) (*idp.Identity, idp.Tokens, error) {
		return nil, idp.Tokens{}, errors.New("plain failure")
	}}
	e.start(t, cfg)
	res, body := e.refresh(t, rt, "")
	if res.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("refresh = %d %v, want 500 server_error", res.StatusCode, body)
	}
	logs := e.logs.String()
	line := regexp.MustCompile(`(?m)^.*"msg":"IdP refresh failed".*$`).FindString(logs)
	for _, want := range []string{`"level":"ERROR"`, `"request_id":"`, `"error":"plain failure"`} {
		if !strings.Contains(line, want) {
			t.Errorf("the refresh failure line lacks %s:\n%s", want, logs)
		}
	}
	if line == "" || strings.Contains(line, `"reason":`) {
		t.Errorf("want one failure line with no reason:\n%s", logs)
	}
	if len(e.alerts) != 0 || strings.Contains(logs, `"alert":`) {
		t.Errorf("an error of no known kind raised an alert %v:\n%s", e.alerts, logs)
	}
	// The grant is kept: the same refresh token works once the IdP answers again.
	e.start(t, working)
	if res, body := e.refresh(t, rt, ""); res.StatusCode != http.StatusOK {
		t.Errorf("after the failure, refresh = %d %v, want the grant kept", res.StatusCode, body)
	}
}
