package fakeidp

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// Workload identity federation: another issuer's token is the client assertion when a federated
// identity credential matches it exactly and its issuer signed it.
func TestAFederatedAssertionIsAcceptedOnlyWhenACredentialMatchesExactly(t *testing.T) {
	const iss, sub, aud = "https://token.actions.githubusercontent.com", "repo:o@1/r@2:environment:real-entra", "api://AzureADTokenExchange"
	github, other := NewCertificate(t), NewCertificate(t)
	f := newFixture(t, Entra)
	c := f.client
	c.Secrets = nil
	c.Federated = []FederatedCredential{{Issuer: iss, Subject: sub, Audience: aud, Signer: github}}
	f.idp.Set(WithClient(c))
	now := time.Now()
	for _, tc := range []struct {
		name       string
		signer     *Certificate
		sub        string
		exp        time.Time
		wantStatus int
		wantCode   float64
	}{
		{"a match", github, sub, now.Add(5 * time.Minute), http.StatusOK, 0},
		{"another subject (case)", github, "repo:O@1/r@2:environment:real-entra", now.Add(5 * time.Minute), http.StatusBadRequest, 70021},
		{"signed by another key", other, sub, now.Add(5 * time.Minute), http.StatusUnauthorized, 700027},
		{"expired", github, sub, now.Add(-time.Minute), http.StatusUnauthorized, 700027},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := tc.signer.SignJWT("RS256", nil, map[string]any{"iss": iss, "sub": tc.sub, "aud": aud, "iat": now.Add(-time.Minute).Unix(), "exp": tc.exp.Unix()})
			if err != nil {
				t.Fatal(err)
			}
			r := f.token(t, url.Values{"grant_type": {GrantClientCredentials}, "scope": {"api://" + c.ID + "/.default"},
				"client_assertion_type": {clientAssertionType}, "client_assertion": {tok}})
			codes, _ := r.body["error_codes"].([]any)
			if r.status != tc.wantStatus || (tc.wantCode != 0 && (len(codes) == 0 || codes[0] != tc.wantCode)) {
				t.Fatalf("status %d body %v", r.status, r.body)
			}
			if tc.wantStatus == http.StatusOK && r.str("access_token") == "" {
				t.Fatalf("no access token: %v", r.body)
			}
		})
	}
}
