package fakeidp

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// Workload identity federation: another issuer's token is the client assertion only when a federated
// identity credential matches its issuer, subject and audience exactly, its issuer signed it, and it
// is within its validity; a client with federated credentials alone is not a public client.
func TestAFederatedAssertionIsAcceptedOnlyWhenACredentialMatchesAndItsIssuerSignedItInDate(t *testing.T) {
	const iss, sub, aud = "https://token.actions.githubusercontent.com", "repo:o@1/r@2:environment:real-entra", "api://AzureADTokenExchange"
	github, other := NewCertificate(t), NewCertificate(t)
	f := newFixture(t, Entra)
	c := f.client
	c.Secrets = nil
	c.Federated = []FederatedCredential{{Issuer: iss, Subject: sub, Audience: aud, Signer: github}}
	f.idp.Set(WithClient(c))
	now := time.Now()
	type claims = map[string]any
	valid := func(over claims) claims {
		m := claims{"iss": iss, "sub": sub, "aud": aud, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name       string
		signer     *Certificate // nil: no client assertion at all
		claims     claims
		wantStatus int
	}{
		{"a match", github, valid(nil), http.StatusOK},
		{"another subject (case)", github, valid(claims{"sub": "repo:O@1/r@2:environment:real-entra"}), http.StatusBadRequest},
		{"another issuer", github, valid(claims{"iss": "https://token.actions.example.com"}), http.StatusBadRequest},
		{"another audience", github, valid(claims{"aud": "api://other"}), http.StatusBadRequest},
		{"signed by another key", other, valid(nil), http.StatusUnauthorized},
		{"expired", github, valid(claims{"exp": now.Add(-time.Minute).Unix()}), http.StatusUnauthorized},
		{"not yet valid", github, valid(claims{"nbf": now.Add(time.Minute).Unix()}), http.StatusUnauthorized},
		{"no credential", nil, nil, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"grant_type": {GrantClientCredentials}, "scope": {"api://" + c.ID + "/.default"}}
			if tc.signer != nil {
				tok, err := tc.signer.SignJWT("RS256", nil, tc.claims)
				if err != nil {
					t.Fatal(err)
				}
				form.Set("client_assertion_type", clientAssertionType)
				form.Set("client_assertion", tok)
			}
			var r tokenResult
			if tc.signer != nil {
				r = f.token(t, form)
			} else { // past the fixture's helper, which would add its client secret
				form.Set("client_id", c.ID)
				r = postToken(t, f.idp.TokenURL(f.tenant), form, nil)
			}
			if r.status != tc.wantStatus || (r.str("access_token") != "") != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("status %d body %v", r.status, r.body)
			}
			if codes, _ := r.body["error_codes"].([]any); tc.signer == nil && (len(codes) == 0 || codes[0] != float64(MissingClientCredential.Code)) {
				t.Fatalf("no credential: %v, want the missing-credential refusal, not a public client", r.body)
			}
		})
	}
}
