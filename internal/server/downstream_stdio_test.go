package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/downstream"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/metrics"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/upstream/stdio"
)

// #141: a stdio process's own ask for its downstream token gets the token, or only an outcome;
// the refusals the operator must act on are alerted and audited as for a request.
func TestAStdioProcessGetsItsUsersDownstreamTokenOrOnlyTheOutcome(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	alice := stdio.Identity{Subject: "tid-1:oid-a", PrincipalType: resource.PrincipalUser, Grant: "grant-a", Client: "client-a"}
	for _, tc := range []struct {
		name         string
		id           func(stdio.Identity) stdio.Identity
		assertionErr error
		expires      time.Time // of the stored IdP token; zero is an hour from now
		noExpiry     bool      // the IdP gave the stored token no expiry: only the token's own counts
		exchangeErr  error
		wantToken    string
		wantError    string
		wantAudit    bool
		exchanged    bool // an exchange with Entra ran: never without a user, a grant or a current sign-in
		wantAlert    string
	}{
		{name: "a signed-in user", wantToken: "graph-token", exchanged: true},
		{name: "a stored token without an expiry", noExpiry: true, wantToken: "graph-token", exchanged: true},
		{name: "an app-only caller", id: func(i stdio.Identity) stdio.Identity { i.PrincipalType = resource.PrincipalClient; return i }, wantError: "no_user"},
		{name: "no grant yet", id: func(i stdio.Identity) stdio.Identity { i.Grant = ""; return i }, wantError: "no_user"},
		{name: "a grant revoked or signed out since", assertionErr: store.ErrNotFound, wantError: "sign_in_expired"},
		{name: "a grant that cannot be read", assertionErr: errors.New("the store is down"), wantError: "failed", wantAudit: true},
		{name: "the stored IdP token has expired", expires: now.Add(-time.Second), wantError: "sign_in_expired"},
		{name: "consent missing", exchangeErr: &idp.Error{Code: entra.CodeConsentRequired}, wantError: "consent_required", wantAudit: true, exchanged: true},
		{name: "Conditional Access", exchangeErr: &idp.Error{OAuth: entra.OAuthInteractionNeeded}, wantError: "interaction_required", wantAudit: true, exchanged: true},
		// #204: the proxy's own credential refused needs the operator, for a process's ask as for a request.
		{name: "the client secret has expired", exchangeErr: &idp.Error{Class: idp.Unavailable, Alert: idp.AlertCredentialRejected, OperatorHint: "AADSTS7000222: renew the secret"},
			wantError: "unavailable", wantAudit: true, exchanged: true, wantAlert: "credential_rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &syncBuffer{}
			log := logging.New(logs, "json")
			var exchanges atomic.Int32
			exchange := func(_ context.Context, tid, assertion string, _ []string) (downstream.Token, error) {
				exchanges.Add(1)
				if tid != "tid-1" || assertion != "idp-token-of-grant-a" {
					t.Errorf("exchange for tenant %q with assertion %q, want tid-1 and grant-a's stored token", tid, assertion)
				}
				return downstream.Token{AccessToken: "graph-token", ExpiresAt: now.Add(time.Hour)}, tc.exchangeErr
			}
			expires := tc.expires
			if expires.IsZero() && !tc.noExpiry {
				expires = now.Add(time.Hour)
			}
			o := Observability{Audit: audit.New(log, nil, time.Now), Metrics: metrics.New()}
			d := &downstreamTokens{cache: downstream.New(alertingExchange(exchange, "entra", log, o), []string{graphUserRead}, 0, func() time.Time { return now }),
				resource: "https://graph.microsoft.com", idp: "entra", log: log, now: func() time.Time { return now }, o: o,
				assertion: func(_ context.Context, grant string) (string, time.Time, error) {
					return "idp-token-of-" + grant, expires, tc.assertionErr
				},
				consentURL: func(string) string { return "https://login.example/adminconsent" }}
			id := alice
			if tc.id != nil {
				id = tc.id(alice)
			}
			got := d.forProcess(context.Background(), id)
			if got.AccessToken != tc.wantToken || got.Error != tc.wantError {
				t.Fatalf("got token %q, error %q; want %q, %q", got.AccessToken, got.Error, tc.wantToken, tc.wantError)
			}
			if tc.wantToken != "" && !got.ExpiresAt.Equal(now.Add(time.Hour)) { // what the process re-asks by
				t.Fatalf("token expires %v, want the exchange's %v", got.ExpiresAt, now.Add(time.Hour))
			}
			if ran := exchanges.Load() > 0; ran != tc.exchanged {
				t.Fatalf("exchanged with Entra %v, want %v", ran, tc.exchanged)
			}
			if tc.wantToken != "" { // a second ask is served from the cache, with no new exchange
				if again := d.forProcess(context.Background(), id); again.AccessToken != tc.wantToken || exchanges.Load() != 1 {
					t.Fatalf("second ask got %q after %d exchanges, want the cached token after 1", again.AccessToken, exchanges.Load())
				}
			}
			line, audited := auditRecord(logs.String(), "downstream_token_refused")
			if audited != tc.wantAudit {
				t.Fatalf("audited %v, want %v: %s", audited, tc.wantAudit, logs.String())
			}
			var rec struct {
				Reason   string
				GrantID  string `json:"grant_id"`
				ClientID string `json:"client_id"`
			}
			if audited && (json.Unmarshal([]byte(line), &rec) != nil || rec.GrantID != "grant-a" || rec.ClientID != "client-a" || rec.Reason != tc.wantError) {
				t.Fatalf("audit record %s, want grant-a, client-a and %s", line, tc.wantError)
			}
			if audited && (!strings.Contains(logs.String(), "a stdio process's ask") || strings.Contains(logs.String(), "answered in the proxy's name")) {
				t.Fatal("the error log does not say the refusal was a stdio process's own ask")
			}
			if strings.Contains(logs.String(), "graph-token") || strings.Contains(logs.String(), "idp-token-of") {
				t.Fatal("a token reached the logs")
			}
			scrape := httptest.NewRecorder()
			d.o.Metrics.Handler().ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
			outcome := tc.wantError
			if outcome == "" {
				outcome = "issued"
			}
			if !strings.Contains(scrape.Body.String(), `outcome="`+outcome+`"} 1`) {
				t.Fatalf("no downstream metric with outcome %s", outcome)
			}
			if tc.wantToken != "" && !strings.Contains(scrape.Body.String(), `outcome="cached"} 1`) {
				t.Fatal("the second ask is not counted as cached")
			}
			alertLines := strings.Count(logs.String(), `"msg":"IdP alert: the operator must act"`)
			refusal := ""
			for l := range strings.Lines(logs.String()) {
				if strings.Contains(l, `"msg":"no downstream token for a stdio process's ask`) {
					refusal = l
				}
			}
			if tc.wantAlert == "" {
				if alertLines != 0 || strings.Contains(refusal, `"alert":`) {
					t.Fatalf("an alert for a refusal that is not one:\n%s", logs)
				}
			} else if alertLines != 1 || !strings.Contains(refusal, `"alert":"`+tc.wantAlert+`"`) ||
				!strings.Contains(scrape.Body.String(), `byward_idp_alerts_total{idp="entra",operation="on_behalf_of",reason="`+tc.wantAlert+`"} 1`) {
				t.Fatalf("want one alert line, %s on the refusal line and counted once:\n%s\n%s", tc.wantAlert, logs, scrape.Body)
			}
		})
	}
}
