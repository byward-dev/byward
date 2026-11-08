package server

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/downstream"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/metrics"
)

// #204: an On-Behalf-Of error that needs the operator is counted and logged once per IdP exchange:
// the requests waiting on one shared exchange do not multiply it, and it is not lost when the only
// request has gone before the exchange fails.
func TestAnOnBehalfOfAlertIsCountedAndLoggedOncePerExchange(t *testing.T) {
	for _, c := range []struct {
		name    string
		waiters int
		leave   bool // the waiters' contexts end before the exchange fails
		fail    *idp.Error
		reason  string // the alert line's reason
	}{
		{"three waiting requests", 3, false,
			&idp.Error{Class: idp.Unavailable, Alert: idp.AlertCredentialRejected, OperatorHint: "AADSTS7000222: renew the secret"}, "AADSTS7000222: renew the secret"},
		{"the only request has gone", 1, true, &idp.Error{Class: idp.Fatal, Alert: idp.AlertProtocol}, idp.AlertProtocol.Hint()},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := &syncBuffer{}
				m := metrics.New()
				release := make(chan struct{})
				exchange := alertingExchange(func(context.Context, string, string, []string) (downstream.Token, error) {
					<-release
					return downstream.Token{}, c.fail
				}, "entra", logging.New(logs, "json"), Observability{Metrics: m})
				cache := downstream.New(exchange, []string{graphUserRead}, 0, time.Now)
				ctx, cancel := context.WithCancel(context.Background())
				var wg sync.WaitGroup
				for range c.waiters {
					wg.Go(func() {
						_, _, _ = cache.Token(ctx, downstream.User{TenantID: "tid", ObjectID: "oid", Assertion: "a", AssertionExpiresAt: time.Now().Add(time.Hour)})
					})
				}
				synctest.Wait() // one request in the exchange, the rest waiting on it
				if c.leave {
					cancel()
					wg.Wait()
				}
				close(release)
				wg.Wait()
				synctest.Wait() // the exchange finishes even after its waiters have gone
				cancel()
				rec := httptest.NewRecorder()
				m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
				if want := `byward_idp_alerts_total{idp="entra",operation="on_behalf_of",reason="` + string(c.fail.Alert) + `"} 1`; !strings.Contains(rec.Body.String(), want) {
					t.Errorf("metrics lack %s:\n%s", want, rec.Body.String())
				}
				lines := regexp.MustCompile(`(?m)^.*"msg":"IdP alert: the operator must act".*$`).FindAllString(logs.String(), -1)
				if len(lines) != 1 {
					t.Fatalf("want one alert line, got %d:\n%s", len(lines), logs)
				}
				for _, want := range []string{`"level":"ERROR"`, `"idp":"entra"`, `"operation":"on_behalf_of"`,
					`"alert":"` + string(c.fail.Alert) + `"`, `"reason":"` + c.reason + `"`} {
					if !strings.Contains(lines[0], want) {
						t.Errorf("the alert line lacks %s:\n%s", want, lines[0])
					}
				}
			})
		})
	}
}
