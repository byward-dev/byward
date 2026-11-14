package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

var secretDiagnosis = Diagnosis{ClientIDSetting: "BYWARD_OIDC_CLIENT_ID", CredentialSetting: "BYWARD_OIDC_CLIENT_SECRET_FILE"}

const secretFix = "set BYWARD_OIDC_CLIENT_SECRET_FILE to the IdP app's current secret, and BYWARD_OIDC_CLIENT_ID to its client ID"

// Doctor tells a refused client credential from an accepted one by redeeming a made-up code: each
// answer the presets were measured to give (#288), and what the IdP answers otherwise.
func TestDoctorTellsARefusedClientCredentialFromAnAcceptedOne(t *testing.T) {
	for _, tc := range []struct {
		name     string
		auth     idp.ClientAuth // nil: the right secret
		clientID string         // "": the IdP app's
		answer   *fakeidp.Failure
		status   doctor.Status
		message  string
		fix      string
	}{
		{"the right secret", nil, "", nil, doctor.Pass, "accepted the client ID and credential", ""},
		{"a wrong secret", idp.ClientSecret("wrong-secret"), "", nil, doctor.Fail, "refused the client ID or its credential (invalid_client, HTTP 401)", secretFix},
		{"a client ID the IdP does not know", nil, fakeidp.NewGUID(), nil, doctor.Fail, "refused the client ID or its credential", secretFix},
		{"Keycloak's answer to a wrong secret", nil, "", &fakeidp.Failure{Status: 401, Error: "unauthorized_client"}, doctor.Fail, "(unauthorized_client, HTTP 401)", secretFix},
		{"Auth0's answer to a wrong secret", nil, "", &fakeidp.Failure{Status: 401, Error: "access_denied", Description: "Unauthorized"}, doctor.Fail, "(access_denied, HTTP 401)", secretFix},
		{"Auth0's answer to a made-up code", nil, "", &fakeidp.Failure{Status: 403, Error: "invalid_grant"}, doctor.Pass, "accepted the client ID and credential", ""},
		{"a user's refusal, not a 401", nil, "", &fakeidp.Failure{Status: 403, Error: "access_denied"}, doctor.Warn, "(access_denied, HTTP 403) does not tell", "sign in once"},
		{"invalid_grant from a failing IdP", nil, "", &fakeidp.Failure{Status: 500, Error: "invalid_grant"}, doctor.Warn, "(invalid_grant, HTTP 500) does not tell", "sign in once"},
		{"invalid_grant with a success status", nil, "", &fakeidp.Failure{Status: 200, Error: "invalid_grant"}, doctor.Warn, "(invalid_grant, HTTP 200) does not tell", "sign in once"},
		{"invalid_grant with a redirect status", nil, "", &fakeidp.Failure{Status: 302, Error: "invalid_grant"}, doctor.Warn, "(invalid_grant, HTTP 302) does not tell", "sign in once"},
		{"an answer about the request", nil, "", &fakeidp.InvalidRequest, doctor.Warn, "(invalid_request, HTTP 400)", "sign in once"},
		{"an IdP that is down", nil, "", &fakeidp.TemporarilyUnavailable, doctor.Warn, "(temporarily_unavailable, HTTP 503)", "sign in once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []fakeidp.Option
			if tc.answer != nil {
				opts = append(opts, fakeidp.FailToken(fakeidp.GrantAuthorizationCode, tc.answer))
			}
			e := newEnv(t, Config{ClientAuth: tc.auth}, opts...)
			if tc.clientID != "" {
				e.p.cfg.ClientID = tc.clientID
			}
			wantResult(t, e.p.DiagnoseClient(context.Background(), secretDiagnosis), tc.status, tc.message, tc.fix)
		})
	}
}

// An IdP's error_description can echo the request, the client secret included, and its error code
// can carry control characters: doctor shows neither, only the code's plain characters (#288).
func TestDoctorNeverShowsWhatTheIdPEchoes(t *testing.T) {
	e := newEnv(t, Config{})
	e.ready(t)
	e.p.fetch.Client = &http.Client{Transport: answering{status: 401,
		body: `{"error":"invalid_client\nPASS  idp  client credential: fine\u001b[2J","error_description":"bad secret ` + secret + ` for code x"}`}}
	r := e.p.DiagnoseClient(context.Background(), secretDiagnosis)
	if r.Status != doctor.Warn || strings.Contains(r.Message+r.Fix, secret) || strings.ContainsAny(r.Message, "\n\u001b") ||
		!strings.Contains(r.Message, "(invalid_clientpassidpclientcredentialfine2j, HTTP 401)") {
		t.Fatalf("result %+v; want a warning that shows only the code's plain characters, never the description", r)
	}
}

// An IdP's error code is shown at most 64 characters long.
func TestDoctorShowsAtMost64CharactersOfTheIdPsErrorCode(t *testing.T) {
	e := newEnv(t, Config{})
	e.ready(t)
	e.p.fetch.Client = &http.Client{Transport: answering{status: 400, body: `{"error":"` + strings.Repeat("a", 65) + `"}`}}
	if r := e.p.DiagnoseClient(context.Background(), secretDiagnosis); !strings.Contains(r.Message, "("+strings.Repeat("a", 64)+", HTTP 400)") {
		t.Fatalf("message %q; want the code cut to 64 characters", r.Message)
	}
}

// With private_key_jwt, a key the IdP has not registered is refused, and the fix names the key and
// the client ID.
func TestDoctorChecksAPrivateKeyJWTCredential(t *testing.T) {
	registered, other := fakeidp.NewCertificate(t), fakeidp.NewCertificate(t)
	d := Diagnosis{ClientIDSetting: "BYWARD_OIDC_CLIENT_ID", CredentialSetting: "BYWARD_OIDC_CLIENT_KEY_FILE", KeyCredential: true}
	for _, tc := range []struct {
		name   string
		key    *fakeidp.Certificate
		status doctor.Status
		fix    string
	}{
		{"the registered key", registered, doctor.Pass, ""},
		{"another key", other, doctor.Fail, "register the public key of BYWARD_OIDC_CLIENT_KEY_FILE with the IdP app "},
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
			r := e.p.DiagnoseClient(context.Background(), d)
			wantResult(t, r, tc.status, "", tc.fix)
			if tc.status == doctor.Fail && !strings.HasSuffix(r.Fix, "with the IdP app "+e.p.cfg.ClientID+" (private_key_jwt), and check BYWARD_OIDC_CLIENT_ID") {
				t.Fatalf("fix %q; want it to name the IdP app and the client ID setting", r.Fix)
			}
		})
	}
}

// Every preset was measured to check the client before the code, so only a pass at plain OIDC says
// that order is assumed.
func TestOnlyPlainOIDCSaysTheClientBeforeCodeOrderIsAssumed(t *testing.T) {
	for name, preset := range Presets {
		if preset.ClientCheckedFirst != (name != "") {
			t.Errorf("preset %q: ClientCheckedFirst = %v; want every named preset measured, plain OIDC not", name, preset.ClientCheckedFirst)
		}
	}
	for _, tc := range []struct {
		name, preset string
		assumed      bool
	}{{"plain OIDC", "", true}, {"a measured preset", "google", false}} {
		t.Run(tc.name, func(t *testing.T) {
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
		fix     string
	}{
		{"a public client", func(e *env) { e.p.cfg.ClientAuth = nil }, doctor.Skip, "public client", ""},
		{"discovery fails", func(e *env) { e.p.fetch.Client = &http.Client{Transport: refused{}} }, doctor.Skip, "discovery failed", ""},
		{"a credential the proxy cannot make", func(e *env) { e.p.cfg.ClientAuth = idp.AssertionFile(t.TempDir() + "/missing") }, doctor.Fail,
			"cannot make its credential", "check BYWARD_OIDC_CLIENT_SECRET_FILE"},
		{"the token endpoint is unreachable", func(e *env) { e.ready(t); e.p.fetch.Client = &http.Client{Transport: refused{}} }, doctor.Fail,
			"did not answer", "/token"}, // the token endpoint, not the issuer
		{"an answer that is not JSON", func(e *env) {
			e.ready(t)
			e.p.fetch.Client = &http.Client{Transport: answering{status: 404, body: "<html>not here</html>"}}
		}, doctor.Fail,
			"gave no OAuth answer", "/token: it must be the IdP's token endpoint"},
		{"a failure without an error code", func(e *env) {
			e.ready(t)
			e.p.fetch.Client = &http.Client{Transport: answering{status: 503, body: "{}"}}
		}, doctor.Fail,
			"gave no OAuth answer", "/token: it must be the IdP's token endpoint"},
		{"a success without tokens", func(e *env) { e.ready(t); e.p.fetch.Client = &http.Client{Transport: emptySuccess{}} }, doctor.Fail,
			"gave no OAuth answer: idp: fatal: token endpoint returned a success without tokens", "/token: it must be the IdP's token endpoint"},
		{"tokens for a made-up code", func(e *env) {
			e.ready(t)
			e.p.fetch.Client = &http.Client{Transport: answering{status: 200, body: `{"access_token":"at","token_type":"Bearer","expires_in":3600}`}}
		}, doctor.Warn, "issued tokens for a made-up", "must refuse unknown codes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{})
			tc.setup(e)
			wantResult(t, e.p.DiagnoseClient(context.Background(), secretDiagnosis), tc.status, tc.message, tc.fix)
		})
	}
}

// The probe is an authorization-code request with byward's callback and a code and verifier made up
// for each check, so it never redeems a real user's code.
func TestTheProbeIsAnAuthorizationCodeRequestMadeUpEachTime(t *testing.T) {
	var forms []url.Values
	e := newEnv(t, Config{})
	e.ready(t)
	e.p.fetch.Client = &http.Client{Transport: recordForm{forms: &forms}}
	for range 2 {
		e.p.DiagnoseClient(context.Background(), secretDiagnosis)
	}
	if len(forms) != 2 {
		t.Fatalf("%d token requests; want 2", len(forms))
	}
	for _, f := range forms {
		if f.Get("grant_type") != "authorization_code" || f.Get("redirect_uri") != redirect || !strings.HasPrefix(f.Get("code"), "byward-doctor-probe-") || len(f.Get("code_verifier")) < 43 {
			t.Fatalf("form %v; want an authorization-code request with byward's callback, a made-up code and a verifier", f)
		}
	}
	if forms[0].Get("code") == forms[1].Get("code") || forms[0].Get("code_verifier") == forms[1].Get("code_verifier") {
		t.Fatalf("forms %v; want a new code and verifier for each check", forms)
	}
}

func wantResult(t *testing.T, r doctor.Result, status doctor.Status, message, fix string) {
	t.Helper()
	if r.Class != doctor.ClassIdP || r.Name != "client credential" || r.Status != status || !strings.Contains(r.Message, message) || !strings.Contains(r.Fix, fix) {
		t.Fatalf("result %+v; want %v with message %q and fix %q", r, status, message, fix)
	}
}

// answering answers every request with status and the JSON body.
type answering struct {
	status int
	body   string
}

func (a answering) RoundTrip(r *http.Request) (*http.Response, error) {
	res := jsonResponse(r, a.body)
	res.StatusCode = a.status
	return res, nil
}

// recordForm records the form of each token request and answers invalid_grant.
type recordForm struct{ forms *[]url.Values }

func (c recordForm) RoundTrip(r *http.Request) (*http.Response, error) {
	_ = r.ParseForm()
	*c.forms = append(*c.forms, r.PostForm)
	return answering{status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`}.RoundTrip(r)
}
