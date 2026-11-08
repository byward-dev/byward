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
		expires      time.Time // of the stored IdP token
		exchangeErr  error
		wantToken    string
		wantError    string
		wantAudit    bool
		exchanged    bool // an exchange with Entra ran: never without a user, a grant or a current sign-in
	}{
		{name: "a signed-in user", wantToken: "graph-token", exchanged: true},
		{name: "an app-only caller", id: func(i stdio.Identity) stdio.Identity { i.PrincipalType = resource.PrincipalClient; return i }, wantError: "no_user"},
		{name: "no grant yet", id: func(i stdio.Identity) stdio.Identity { i.Grant = ""; return i }, wantError: "no_user"},
		{name: "a grant that is gone", assertionErr: errors.New("grant revoked"), wantError: "failed", wantAudit: true},
		{name: "the stored IdP token has expired", expires: now.Add(-time.Second), wantError: "sign_in_expired"},
		{name: "consent missing", exchangeErr: &idp.Error{Code: entra.CodeConsentRequired}, wantError: "consent_required", wantAudit: true, exchanged: true},
		{name: "Conditional Access", exchangeErr: &idp.Error{OAuth: entra.OAuthInteractionNeeded}, wantError: "interaction_required", wantAudit: true, exchanged: true},
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
			if expires.IsZero() {
				expires = now.Add(time.Hour)
			}
			d := &downstreamTokens{cache: downstream.New(exchange, []string{graphUserRead}, 0, func() time.Time { return now }),
				resource: "https://graph.microsoft.com", idp: "entra", log: log, now: func() time.Time { return now },
				o: Observability{Audit: audit.New(log, nil, time.Now), Metrics: metrics.New()},
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
			if ran := exchanges.Load() > 0; ran != tc.exchanged {
				t.Fatalf("exchanged with Entra %v, want %v", ran, tc.exchanged)
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
		})
	}
}
