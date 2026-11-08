package broker

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

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
	}{
		{"sign-in, client secret rejected", signInFailing, fakeidp.InvalidClientSecret, "callback credential_rejected"},
		{"sign-in, IdP unavailable", signInFailing, fakeidp.TemporarilyUnavailable, ""},
		{"refresh, client secret rejected", refreshFailing, fakeidp.InvalidClientSecret, "refresh credential_rejected"},
		{"refresh, IdP unavailable", refreshFailing, fakeidp.TemporarilyUnavailable, ""},
		{"forged callback error", forgedCallback, fakeidp.Failure{}, ""},
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
			line := regexp.MustCompile(`(?m)^.*"msg":"IdP alert: the operator must act".*$`).FindString(logs)
			for _, want := range []string{`"level":"ERROR"`, `"idp":"entra"`, `"operation":"` + op + `"`, `"alert":"` + reason + `"`} {
				if !strings.Contains(line, want) {
					t.Errorf("the alert line lacks %s:\n%s", want, logs)
				}
			}
			// AADSTS7000215 has no operator hint of its own, so the alert's fix stands in.
			if !strings.Contains(line, `"reason":"the IdP refused the proxy's client credential`) {
				t.Errorf("the alert line does not name the fix:\n%s", logs)
			}
		})
	}
}
