package broker

import (
	"fmt"
	"net/http"
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

// forgedCallback sends the callback a browser could forge: the IdP's own error, invalid_client with
// Entra's code for a rejected secret, in the query.
func forgedCallback(t *testing.T, e *env, _ fakeidp.Failure) {
	t.Helper()
	ck, cb := e.startLogin(t, nil)
	q := cb.Query()
	q.Del("code")
	q.Set("error", "invalid_client")
	q.Set("error_description", "AADSTS7000215: Invalid client secret provided.")
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
		fix     string // the alert line's whole reason
	}{
		// AADSTS7000215 has no operator hint of its own, so the alert's default fix stands in.
		{"sign-in, client secret rejected", signInFailing, fakeidp.InvalidClientSecret, "callback credential_rejected", idp.AlertCredentialRejected.Hint()},
		{"sign-in, IdP unavailable", signInFailing, fakeidp.TemporarilyUnavailable, "", ""},
		{"refresh, client secret rejected", refreshFailing, fakeidp.InvalidClientSecret, "refresh credential_rejected", idp.AlertCredentialRejected.Hint()},
		// Entra's own hint wins over the default.
		{"refresh, client secret expired", refreshFailing, fakeidp.ExpiredClientSecret, "refresh credential_rejected", "AADSTS7000222: the client secret has expired; create a new one (or switch to a certificate)."},
		{"refresh, IdP unavailable", refreshFailing, fakeidp.TemporarilyUnavailable, "", ""},
		{"forged callback error", forgedCallback, fakeidp.Failure{}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.drive(t, e, c.failure)
			logs := e.logs.String()
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
