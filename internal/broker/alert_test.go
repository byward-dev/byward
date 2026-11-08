package broker

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// #204: an IdP error that only the operator can fix (here Entra rejecting the proxy's client
// secret) is counted and logged as an alert, for a sign-in and for a refresh; an outage the IdP
// recovers from on its own is not.
func TestIdPErrorsThatNeedTheOperatorRaiseAnAlert(t *testing.T) {
	cases := []struct {
		name    string
		grant   string
		failure fakeidp.Failure
		want    string // "operation reason", or "" for no alert
	}{
		{"sign-in, client secret rejected", fakeidp.GrantAuthorizationCode, fakeidp.InvalidClientSecret, "callback credential_rejected"},
		{"sign-in, IdP unavailable", fakeidp.GrantAuthorizationCode, fakeidp.TemporarilyUnavailable, ""},
		{"refresh, client secret rejected", "refresh_token", fakeidp.InvalidClientSecret, "refresh credential_rejected"},
		{"refresh, IdP unavailable", "refresh_token", fakeidp.TemporarilyUnavailable, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.grant == "refresh_token" {
				rt := e.offline(t)["refresh_token"].(string)
				e.fake.Set(fakeidp.FailToken(c.grant, &c.failure))
				if res, body := e.refresh(t, rt, ""); res.StatusCode == http.StatusOK {
					t.Fatalf("the refresh succeeded despite the IdP failure: %v", body)
				}
			} else {
				e.fake.Set(fakeidp.FailToken(c.grant, &c.failure))
				ck, cb := e.startLogin(t, nil)
				if res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{ck}); res.StatusCode != http.StatusBadGateway {
					t.Fatalf("callback answered %d, want the IdP failure page (502)", res.StatusCode)
				}
			}
			logs := e.logs.String()
			if c.want == "" {
				if len(e.alerts) != 0 || strings.Contains(logs, `"alert":`) {
					t.Fatalf("an outage raised an alert: %v\n%s", e.alerts, logs)
				}
				return
			}
			if fmt.Sprint(e.alerts) != fmt.Sprint([]string{c.want}) {
				t.Fatalf("alerts = %v, want [%s]", e.alerts, c.want)
			}
			op, reason, _ := strings.Cut(c.want, " ")
			for _, want := range []string{`"level":"ERROR","msg":"IdP alert: the operator must act"`, `"idp":"entra"`,
				`"operation":"` + op + `"`, `"alert":"` + reason + `"`} {
				if !strings.Contains(logs, want) {
					t.Errorf("the alert log lacks %s:\n%s", want, logs)
				}
			}
		})
	}
}
