package oidc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

var secretDiagnosis = Diagnosis{ClientIDSetting: "BYWARD_OIDC_CLIENT_ID", CredentialSetting: "BYWARD_OIDC_CLIENT_SECRET_FILE"}

// Doctor tells a refused client credential from an accepted one by redeeming a made-up code: each
// answer the presets were measured to give (#288), and what the IdP answers otherwise.
func TestDoctorTellsARefusedClientCredentialFromAnAcceptedOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		auth    idp.ClientAuth // nil: the right secret
		answer  *fakeidp.Failure
		status  doctor.Status
		message string
		fix     string
	}{
		{"the right secret", nil, nil, doctor.Pass, "accepted the client ID and credential", ""},
		{"a wrong secret", idp.ClientSecret("wrong-secret"), nil, doctor.Fail, "refused the client ID or its credential (invalid_client, HTTP 401",
			"set BYWARD_OIDC_CLIENT_SECRET_FILE to the client's current secret"},
		{"Keycloak's answer to a wrong secret", nil, &fakeidp.Failure{Status: 401, Error: "unauthorized_client"}, doctor.Fail, "(unauthorized_client, HTTP 401", "BYWARD_OIDC_CLIENT_SECRET_FILE"},
		{"Auth0's answer to a wrong secret", nil, &fakeidp.Failure{Status: 401, Error: "access_denied", Description: "Unauthorized"}, doctor.Fail,
			"(access_denied, HTTP 401: Unauthorized)", "BYWARD_OIDC_CLIENT_SECRET_FILE"},
		{"Auth0's answer to a made-up code", nil, &fakeidp.Failure{Status: 403, Error: "invalid_grant"}, doctor.Pass, "accepted the client ID and credential", ""},
		{"a user's refusal, not a 401", nil, &fakeidp.Failure{Status: 403, Error: "access_denied"}, doctor.Warn, "(access_denied, HTTP 403) does not tell", "sign in once"},
		{"an answer about the request", nil, &fakeidp.InvalidRequest, doctor.Warn, "(invalid_request, HTTP 400", "sign in once"},
		{"an IdP that is down", nil, &fakeidp.TemporarilyUnavailable, doctor.Warn, "(temporarily_unavailable, HTTP 503", "sign in once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []fakeidp.Option
			if tc.answer != nil {
				opts = append(opts, fakeidp.FailToken(fakeidp.GrantAuthorizationCode, tc.answer))
			}
			e := newEnv(t, Config{ClientAuth: tc.auth}, opts...)
			wantResult(t, e.p.DiagnoseClient(context.Background(), secretDiagnosis), tc.status, tc.message, tc.fix)
		})
	}
}

// With private_key_jwt, a key the IdP has not registered is refused, and the fix names the key.
func TestDoctorChecksAPrivateKeyJWTCredential(t *testing.T) {
	registered, other := fakeidp.NewCertificate(t), fakeidp.NewCertificate(t)
	d := Diagnosis{ClientIDSetting: "BYWARD_OIDC_CLIENT_ID", CredentialSetting: "BYWARD_OIDC_CLIENT_KEY_FILE", Key: true}
	for _, tc := range []struct {
		name   string
		key    *fakeidp.Certificate
		status doctor.Status
		fix    string
	}{
		{"the registered key", registered, doctor.Pass, ""},
		{"another key", other, doctor.Fail, "register the public key of BYWARD_OIDC_CLIENT_KEY_FILE with the client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := idp.PrivateKeyJWT(tc.key.Key, nil, tc.key.ThumbprintSHA256())
			if err != nil {
				t.Fatal(err)
			}
			e := newEnv(t, Config{ClientAuth: auth})
			c := e.client
			c.Secrets, c.Certificates = nil, []*fakeidp.Certificate{registered}
			e.fake.Set(fakeidp.WithClient(c))
			wantResult(t, e.p.DiagnoseClient(context.Background(), d), tc.status, "", tc.fix)
		})
	}
}

// A pass at plain OIDC says the IdP's order is assumed; at a measured preset it does not.
func TestAPassSaysWhenTheIdPsOrderIsAssumed(t *testing.T) {
	for _, tc := range []struct {
		preset  string
		assumed bool
	}{{"", true}, {"google", false}} {
		t.Run("preset "+tc.preset, func(t *testing.T) {
			r := newEnv(t, Config{Preset: tc.preset}).p.DiagnoseClient(context.Background(), secretDiagnosis)
			if r.Status != doctor.Pass || strings.Contains(r.Message, "assumes") != tc.assumed {
				t.Fatalf("result %+v; want a pass that says the order is assumed: %v", r, tc.assumed)
			}
		})
	}
}

// When the probe cannot run or gets no OAuth answer, doctor says so, never a pass.
func TestDoctorReportsAClientCheckItCouldNotMake(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(e *env)
		status  doctor.Status
		message string
	}{
		{"a public client", func(e *env) { e.p.cfg.ClientAuth = nil }, doctor.Skip, "public client"},
		{"discovery fails", func(e *env) { e.p.fetch.Client = &http.Client{Transport: refused{}} }, doctor.Skip, "discovery failed"},
		{"a credential the proxy cannot make", func(e *env) { e.p.cfg.ClientAuth = idp.AssertionFile(t.TempDir() + "/missing") }, doctor.Fail, "cannot make its credential"},
		{"the token endpoint is unreachable", func(e *env) { e.ready(t); e.p.fetch.Client = &http.Client{Transport: refused{}} }, doctor.Fail, "did not answer"},
		{"tokens for a made-up code", func(e *env) { e.ready(t); e.p.fetch.Client = &http.Client{Transport: tokensIssued{}} }, doctor.Warn, "issued tokens for a made-up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{})
			tc.setup(e)
			wantResult(t, e.p.DiagnoseClient(context.Background(), secretDiagnosis), tc.status, tc.message, "")
		})
	}
}

// The probe's code is made up for each check, so it never redeems a real user's code.
func TestTheProbeSendsAMadeUpCodeEachTime(t *testing.T) {
	var codes []string
	e := newEnv(t, Config{})
	e.ready(t)
	e.p.fetch.Client = &http.Client{Transport: recordCode{codes: &codes}}
	for range 2 {
		e.p.DiagnoseClient(context.Background(), secretDiagnosis)
	}
	if len(codes) != 2 || codes[0] == codes[1] || !strings.HasPrefix(codes[0], "byward-doctor-probe-") {
		t.Fatalf("codes %q; want two different made-up codes", codes)
	}
}

func wantResult(t *testing.T, r doctor.Result, status doctor.Status, message, fix string) {
	t.Helper()
	if r.Class != doctor.ClassIdP || r.Name != "client credential" || r.Status != status || !strings.Contains(r.Message, message) || !strings.Contains(r.Fix, fix) {
		t.Fatalf("result %+v; want %v with message %q and fix %q", r, status, message, fix)
	}
}

func (e *env) ready(t *testing.T) {
	t.Helper()
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// tokensIssued answers every request with tokens.
type tokensIssued struct{}

func (tokensIssued) RoundTrip(r *http.Request) (*http.Response, error) {
	return jsonResponse(r, `{"access_token":"at","token_type":"Bearer","expires_in":3600}`), nil
}

// recordCode records the code of each token request and answers invalid_grant.
type recordCode struct{ codes *[]string }

func (c recordCode) RoundTrip(r *http.Request) (*http.Response, error) {
	_ = r.ParseForm()
	*c.codes = append(*c.codes, r.PostForm.Get("code"))
	res := jsonResponse(r, `{"error":"invalid_grant"}`)
	res.StatusCode = http.StatusBadRequest
	return res, nil
}

func jsonResponse(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
