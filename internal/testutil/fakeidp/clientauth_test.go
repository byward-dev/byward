package fakeidp

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// authFixture is an Entra IdP with a confidential client and a resource API, on a fixed clock.
func authFixture(t *testing.T, c Client) (*fixture, string, *fakeClock) {
	t.Helper()
	clock := newClock()
	api := Client{ID: NewGUID()}
	idp := New(t, Entra, WithClock(clock.Now), WithClient(c), WithClient(api))
	return &fixture{idp: idp, client: c, tenant: idp.TenantID()}, api.ID, clock
}

func TestTokenEndpointAuthenticatesClientSecrets(t *testing.T) {
	const special = "a+b:c%"
	for name, tc := range map[string]struct {
		form   func(f *fixture) url.Values
		basic  func(f *fixture) http.Header
		status int
		err    string
		code   int
	}{
		"secret post": {form: func(f *fixture) url.Values {
			return url.Values{"client_id": {f.client.ID}, "client_secret": {testSecret}}
		}, status: 200},
		"rolled-over secret": {form: func(f *fixture) url.Values {
			return url.Values{"client_id": {f.client.ID}, "client_secret": {"previous-secret"}}
		}, status: 200},
		"secret basic":       {basic: func(f *fixture) http.Header { return basic(f.client.ID, testSecret) }, status: 200},
		"basic form-encoded": {basic: func(f *fixture) http.Header { return basic(f.client.ID, special) }, status: 200},
		"wrong secret":       {form: func(f *fixture) url.Values { return url.Values{"client_id": {f.client.ID}, "client_secret": {"nope"}} }, status: 401, err: "invalid_client", code: 7000215},
		"no credential":      {form: func(f *fixture) url.Values { return url.Values{"client_id": {f.client.ID}} }, status: 401, err: "invalid_client", code: 7000218},
		"unknown client":     {form: func(*fixture) url.Values { return url.Values{"client_id": {NewGUID()}, "client_secret": {testSecret}} }, status: 400, err: "unauthorized_client", code: 700016},
		"basic and form id differ": {
			form:  func(*fixture) url.Values { return url.Values{"client_id": {NewGUID()}} },
			basic: func(f *fixture) http.Header { return basic(f.client.ID, testSecret) }, status: 400, err: "invalid_request", code: 9002313,
		},
		"two methods": {
			form: func(f *fixture) url.Values {
				return url.Values{"client_id": {f.client.ID}, "client_secret": {testSecret}}
			},
			basic: func(f *fixture) http.Header { return basic(f.client.ID, testSecret) }, status: 400, err: "invalid_request", code: 9002313,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, api, _ := authFixture(t, Client{ID: NewGUID(), Secrets: []string{testSecret, "previous-secret", special}})
			form, h := url.Values{}, http.Header(nil)
			if tc.form != nil {
				form = tc.form(f)
			}
			if tc.basic != nil {
				h = tc.basic(f)
			}
			form.Set("grant_type", GrantClientCredentials)
			form.Set("scope", "api://"+api+"/.default")
			r := postToken(t, f.idp.TokenURL(f.tenant), form, h)
			if tc.status != 200 {
				wantEntraError(t, r, tc.status, tc.err, tc.code)
				return
			}
			wantStatus(t, r, 200)
			_, at := f.verified(t, r.str("access_token"))
			wantClaim(t, at, "azpacr", "1")
		})
	}
}

func TestTokenEndpointAuthenticatesCertificateAssertions(t *testing.T) {
	cert, rolled, stranger := NewCertificate(t), NewCertificate(t), NewCertificate(t)
	s256 := func(c *Certificate) map[string]any { return map[string]any{"x5t#S256": c.ThumbprintSHA256()} }
	for name, tc := range map[string]struct {
		signer   *Certificate
		alg      string
		header   map[string]any
		override func(f *fixture, now time.Time) map[string]any
		form     func(url.Values)
		status   int
		code     int
		err      string
	}{
		"PS256 x5t#S256":          {signer: cert, alg: "PS256", header: s256(cert), status: 200},
		"RS256 x5t (SHA-1)":       {signer: cert, alg: "RS256", header: map[string]any{"x5t": cert.ThumbprintSHA1()}, status: 200},
		"rolled-over certificate": {signer: rolled, alg: "PS256", header: s256(rolled), status: 200},
		"authority audience": {signer: cert, alg: "PS256", header: s256(cert), status: 200, override: func(f *fixture, _ time.Time) map[string]any {
			return map[string]any{"aud": "https://login.microsoftonline.com/" + f.tenant + "/oauth2/v2.0/token"}
		}},
		"audience array": {signer: cert, alg: "PS256", header: s256(cert), status: 200, override: func(f *fixture, _ time.Time) map[string]any {
			return map[string]any{"aud": []any{"https://elsewhere.example", f.idp.TokenURL(f.tenant)}}
		}},
		"client_id taken from sub": {signer: cert, alg: "PS256", header: s256(cert), status: 200, form: func(v url.Values) { v.Del("client_id") }},
		"no thumbprint":            {signer: cert, alg: "PS256", status: 401, err: "invalid_client", code: 5002723},
		"signed by another key":    {signer: stranger, alg: "PS256", header: s256(cert), status: 401, err: "invalid_client", code: 700027},
		"unregistered certificate": {signer: stranger, alg: "PS256", header: s256(stranger), status: 401, err: "invalid_client", code: 700027},
		"wrong audience": {signer: cert, alg: "PS256", header: s256(cert), status: 401, err: "invalid_client", code: 700027, override: func(*fixture, time.Time) map[string]any {
			return map[string]any{"aud": "https://elsewhere.example/token"}
		}},
		"expired": {signer: cert, alg: "PS256", header: s256(cert), status: 401, err: "invalid_client", code: 700027, override: func(_ *fixture, now time.Time) map[string]any {
			return map[string]any{"exp": now.Add(-time.Minute).Unix()}
		}},
		"not yet valid": {signer: cert, alg: "PS256", header: s256(cert), status: 401, err: "invalid_client", code: 700027, override: func(_ *fixture, now time.Time) map[string]any {
			return map[string]any{"nbf": now.Add(5 * time.Minute).Unix()}
		}},
		"for another client": {signer: cert, alg: "PS256", header: s256(cert), status: 401, err: "invalid_client", code: 700027, override: func(*fixture, time.Time) map[string]any {
			return map[string]any{"sub": NewGUID()}
		}},
		"wrong assertion type": {signer: cert, alg: "PS256", header: s256(cert), status: 400, err: "invalid_request", code: 9002313,
			form: func(v url.Values) { v.Set("client_assertion_type", "urn:example") }},
	} {
		t.Run(name, func(t *testing.T) {
			f, api, clock := authFixture(t, Client{ID: NewGUID(), Certificates: []*Certificate{cert, rolled}})
			var override map[string]any
			if tc.override != nil {
				override = tc.override(f, clock.Now())
			}
			form := assertionForm(t, f, clock.Now(), tc.signer, tc.alg, tc.header, override)
			if tc.form != nil {
				tc.form(form)
			}
			form.Set("grant_type", GrantClientCredentials)
			form.Set("scope", "api://"+api+"/.default")
			r := postToken(t, f.idp.TokenURL(f.tenant), form, nil)
			if tc.status != 200 {
				wantEntraError(t, r, tc.status, tc.err, tc.code)
				return
			}
			wantStatus(t, r, 200)
			_, at := f.verified(t, r.str("access_token"))
			wantClaim(t, at, "azpacr", "2")
		})
	}
}

func TestGenericCertificateAssertion(t *testing.T) {
	cert := NewCertificate(t)
	for name, tc := range map[string]struct {
		header map[string]any
		aud    func(f *fixture) any
		status int
	}{
		"kid is the SHA-256 thumbprint": {header: map[string]any{"kid": cert.ThumbprintSHA256()}, status: 200},
		"issuer audience":               {header: map[string]any{"kid": cert.ThumbprintSHA256()}, aud: func(f *fixture) any { return f.idp.Issuer() }, status: 200},
		"audience array": {header: map[string]any{"kid": cert.ThumbprintSHA256()}, status: 200,
			aud: func(f *fixture) any { return []any{"https://x.example", f.idp.TokenURL("")} }},
		"Entra-style audience": {header: map[string]any{"kid": cert.ThumbprintSHA256()}, status: 401,
			aud: func(*fixture) any { return "https://login.microsoftonline.com/x/oauth2/v2.0/token" }},
		"unknown kid": {header: map[string]any{"kid": "nope"}, status: 401},
	} {
		t.Run(name, func(t *testing.T) {
			clock := newClock()
			f := newFixture(t, Generic, WithClock(clock.Now))
			f.client.Certificates = []*Certificate{cert}
			f.client.Secrets = nil
			f.idp.Set(WithClient(f.client))
			var override map[string]any
			if tc.aud != nil {
				override = map[string]any{"aud": tc.aud(f)}
			}
			form := assertionForm(t, f, clock.Now(), cert, "RS256", tc.header, override)
			form.Set("grant_type", GrantAuthorizationCode)
			form.Set("code", f.code(t, nil))
			form.Set("redirect_uri", testRedirect)
			form.Set("code_verifier", testVerifier)
			r := postToken(t, f.idp.TokenURL(""), form, nil)
			wantStatus(t, r, tc.status)
			if tc.status == 401 && r.str("error") != "invalid_client" {
				t.Fatalf("error = %q", r.str("error"))
			}
		})
	}
}

func TestPublicClientLoginRequiresPKCEAndHasAzpacrZero(t *testing.T) {
	c := Client{ID: NewGUID(), RedirectURIs: []string{testRedirect}}
	idp := New(t, Entra, WithClient(c))
	f := &fixture{idp: idp, client: c, tenant: idp.TenantID()}
	form := func(verifier string) url.Values {
		v := url.Values{"grant_type": {GrantAuthorizationCode}, "client_id": {c.ID}, "code": {f.code(t, nil)}, "redirect_uri": {testRedirect}}
		if verifier != "" {
			v.Set("code_verifier", verifier)
		}
		return v
	}
	wantEntraError(t, postToken(t, idp.TokenURL(f.tenant), form(""), nil), 400, "invalid_grant", 501481)

	r := postToken(t, idp.TokenURL(f.tenant), form(testVerifier), nil)
	wantStatus(t, r, http.StatusOK)
	_, at := f.verified(t, r.str("access_token"))
	wantClaim(t, at, "azpacr", "0")
}

func basic(id, secret string) http.Header {
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	return req.Header
}

func assertionForm(t *testing.T, f *fixture, now time.Time, cert *Certificate, alg string, header, override map[string]any) url.Values {
	t.Helper()
	claims := map[string]any{
		"iss": f.client.ID, "sub": f.client.ID, "aud": f.idp.TokenURL(f.tenant),
		"jti": NewGUID(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range override {
		claims[k] = v
	}
	s, err := cert.SignJWT(alg, header, claims)
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"client_id": {f.client.ID}, "client_assertion_type": {clientAssertionType}, "client_assertion": {s}}
}
