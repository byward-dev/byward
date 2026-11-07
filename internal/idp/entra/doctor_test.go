package entra

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

var diagnosis = Diagnosis{TenantSetting: "TENANT_SETTING", ClientIDSetting: "CLIENT_ID_SETTING", SecretSetting: "SECRET_SETTING"}

// diagnose runs Diagnose and indexes the results by check name.
func diagnose(t *testing.T, p *Provider, d Diagnosis) map[string]doctor.Result {
	t.Helper()
	out := map[string]doctor.Result{}
	for _, r := range p.Diagnose(context.Background(), d) {
		if r.Class != doctor.ClassIdP {
			t.Errorf("%s: class %q, want idp", r.Name, r.Class)
		}
		if _, dup := out[r.Name]; dup {
			t.Errorf("check %q reported twice", r.Name)
		}
		out[r.Name] = r
	}
	return out
}

// rebuild replaces the adapter with one whose configuration change alters.
func rebuild(t *testing.T, e *env, change func(*Config)) {
	t.Helper()
	cfg := Config{Tenant: e.fake.TenantID(), ClientID: e.client.ID, ClientAuth: idp.ClientSecret(secret), RedirectURL: redirect,
		HTTPClient: e.fake.HTTPClient(), Now: now}
	change(&cfg)
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.fetch.Backoff = 0
	e.p = p
}

func withClient(change func(*fakeidp.Client)) func(*testing.T, *env) {
	return func(_ *testing.T, e *env) {
		c, _ := e.fake.Client(e.client.ID)
		change(&c)
		e.fake.Set(fakeidp.WithClient(c))
	}
}

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func TestDiagnoseOfAHealthyAppPassesAndSkipsWhatNeedsGraph(t *testing.T) {
	e := newEnv(t, Config{})
	got := diagnose(t, e.p, diagnosis)
	for _, name := range []string{"entra tenant", "entra signing keys", "entra app and credential", "entra access token", "entra idtyp claim"} {
		if got[name].Status != doctor.Pass {
			t.Errorf("%s: %+v, want pass", name, got[name])
		}
	}
	for _, name := range []string{"entra redirect URI", "entra app roles"} {
		if got[name].Status != doctor.Skip || !strings.Contains(got[name].Fix, "az ad app show --id "+e.client.ID) {
			t.Errorf("%s: %+v, want a skip with the az command that checks it", name, got[name])
		}
	}
	if !strings.Contains(got["entra redirect URI"].Fix, redirect) {
		t.Errorf("redirect URI fix %q does not name %s", got["entra redirect URI"].Fix, redirect)
	}
	if len(got) != 7 {
		t.Errorf("%d checks, want 7: %v", len(got), got)
	}
}

// One fake-IdP misconfiguration per check (ADR-0024); each failing result names the fix.
func TestDiagnoseReportsEachMisconfigurationWithItsFix(t *testing.T) {
	cases := []struct {
		name      string
		opts      []fakeidp.Option
		setup     func(*testing.T, *env)
		check     string
		status    doctor.Status
		inMessage string
		inFix     string
	}{
		{name: "tenant that does not exist", opts: []fakeidp.Option{fakeidp.WithUnknownTenantsRefused(true)},
			setup: func(t *testing.T, e *env) { rebuild(t, e, func(c *Config) { c.Tenant = fakeidp.NewGUID() }) },
			check: "entra tenant", status: doctor.Fail, inMessage: "no discovery document", inFix: "set TENANT_SETTING to your tenant ID"},
		{name: "tenant that does not exist, at the token endpoint", opts: []fakeidp.Option{fakeidp.WithUnknownTenantsRefused(true)},
			setup: func(t *testing.T, e *env) { rebuild(t, e, func(c *Config) { c.Tenant = fakeidp.NewGUID() }) },
			check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS90002", inFix: "set TENANT_SETTING"},
		{name: "discovery names another issuer", opts: []fakeidp.Option{fakeidp.WithAuthority("https://login.example.net")},
			check: "entra tenant", status: doctor.Fail, inMessage: "names issuer", inFix: "TENANT_SETTING"},
		{name: "signing keys unavailable", opts: []fakeidp.Option{fakeidp.WithJWKSUnavailable(true)},
			check: "entra signing keys", status: doctor.Fail, inMessage: "cannot fetch", inFix: "can reach " + Authority},
		{name: "key set without a signing key", opts: []fakeidp.Option{fakeidp.WithEmptyJWKS(true)},
			check: "entra signing keys", status: doctor.Fail, inMessage: "no signing key", inFix: Authority},
		{name: "client ID of no app", setup: func(t *testing.T, e *env) { rebuild(t, e, func(c *Config) { c.ClientID = fakeidp.NewGUID() }) },
			check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS700016", inFix: "set CLIENT_ID_SETTING"},
		{name: "wrong client secret", setup: func(t *testing.T, e *env) {
			rebuild(t, e, func(c *Config) { c.ClientAuth = idp.ClientSecret("not-the-secret") })
		}, check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS7000215", inFix: "SECRET_SETTING must hold the secret's value"},
		{name: "expired client secret", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.ExpiredClientSecret)},
			check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS7000222", inFix: "--append"},
		{name: "no Application ID URI", setup: withClient(func(c *fakeidp.Client) { c.NoIdentifierURI = true }),
			check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS500011", inFix: "set the Application ID URI to api://"},
		{name: "assignment required: the credential passes", setup: withClient(func(c *fakeidp.Client) { c.AssignmentRequired = true }),
			check: "entra app and credential", status: doctor.Pass, inMessage: "accepted"},
		{name: "assignment required: the token is not checked", setup: withClient(func(c *fakeidp.Client) { c.AssignmentRequired = true }),
			check: "entra access token", status: doctor.Skip, inMessage: "AADSTS501051", inFix: "requestedAccessTokenVersion"},
		{name: "v1 access tokens", setup: withClient(func(c *fakeidp.Client) { c.AccessTokenVersion = 1 }),
			check: "entra access token", status: doctor.Fail, inMessage: `version "1.0"`, inFix: "requestedAccessTokenVersion to 2"},
		{name: "no idtyp claim", opts: []fakeidp.Option{fakeidp.WithIDTypClaim(false)},
			check: "entra idtyp claim", status: doctor.Warn, inMessage: "no idtyp=app", inFix: "idtyp optional claim"},
		{name: "another error code", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.BlockedByConditionalAccess)},
			check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS53003", inFix: "Conditional Access"},
		{name: "an error code without an operator hint", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.InvalidScope)},
			check: "entra app and credential", status: doctor.Fail, inMessage: "AADSTS70011", inFix: "reference-error-codes"},
		{name: "token endpoint unavailable", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.TemporarilyUnavailable)},
			check: "entra app and credential", status: doctor.Fail, inMessage: "probe failed: HTTP 503 temporarily_unavailable", inFix: "can reach " + Authority},
		{name: "Entra unreachable", setup: func(t *testing.T, e *env) {
			rebuild(t, e, func(c *Config) { c.HTTPClient = &http.Client{Transport: refusingTransport{}} })
		}, check: "entra app and credential", status: doctor.Fail, inMessage: "connection refused", inFix: "can reach " + Authority},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{}, tc.opts...)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			r := diagnose(t, e.p, diagnosis)[tc.check]
			if r.Status != tc.status || !strings.Contains(r.Message, tc.inMessage) || !strings.Contains(r.Fix, tc.inFix) {
				t.Fatalf("%s = %+v\nwant status %s, message with %q, fix with %q", tc.check, r, tc.status, tc.inMessage, tc.inFix)
			}
		})
	}
}

func TestDiagnoseEveryFailureNamesAFix(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithJWKSUnavailable(true))
	rebuild(t, e, func(c *Config) { c.ClientAuth = idp.ClientSecret("not-the-secret") })
	fails := 0
	for _, r := range e.p.Diagnose(context.Background(), diagnosis) {
		if r.Status == doctor.Fail {
			fails++
		}
		if (r.Status == doctor.Fail || r.Status == doctor.Warn || r.Status == doctor.Skip) && r.Fix == "" {
			t.Errorf("%s is %s without a fix: %s", r.Name, r.Status, r.Message)
		}
	}
	if fails < 2 {
		t.Fatalf("%d failures, want the signing keys and the credential at least", fails)
	}
}

func TestDiagnoseOfAppRolesNamesTheRolesTheGateNeeds(t *testing.T) {
	e := newEnv(t, Config{})
	d := diagnosis
	d.GateRoles = []string{"byward.user", "MCP.Admin"}
	if fix := diagnose(t, e.p, d)["entra app roles"].Fix; !strings.Contains(fix, "must include byward.user, MCP.Admin") {
		t.Fatalf("app roles fix %q does not name the gate roles", fix)
	}
}

// The probe is the documented client-credentials request for the app's own resource, sent with our
// credential and nothing a caller supplied (invariant 19 is about the MCP endpoint; this is ours).
func TestDiagnoseProbesTheAppsOwnResource(t *testing.T) {
	var form []string
	e := newEnv(t, Config{})
	rebuild(t, e, func(c *Config) {
		c.HTTPClient = &http.Client{Transport: recordForm{base: e.fake.Transport(), form: &form}}
	})
	diagnose(t, e.p, diagnosis)
	want := "grant_type=client_credentials scope=api://" + e.client.ID + "/.default"
	if !slices.Contains(form, want) {
		t.Fatalf("token requests %q, want one with %q", form, want)
	}
}

// recordForm notes the grant type and scope of every form POST.
type recordForm struct {
	base http.RoundTripper
	form *[]string
}

func (r recordForm) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		q, err := url.ParseQuery(string(b))
		if err != nil {
			return nil, err
		}
		*r.form = append(*r.form, "grant_type="+q.Get("grant_type")+" scope="+q.Get("scope"))
	}
	return r.base.RoundTrip(req)
}

// Client credentials are documented only for a tenant GUID or domain, so organizations mode does
// not probe and says how to check by hand.
func TestDiagnoseInOrganizationsModeSkipsTheCredentialProbe(t *testing.T) {
	e := newEnv(t, Config{Tenant: Organizations, AllowedTenants: []string{fakeidp.NewGUID()}})
	got := diagnose(t, e.p, diagnosis)
	if c := got["entra app and credential"]; c.Status != doctor.Skip || !strings.Contains(c.Fix, "az ad app credential list --id "+e.client.ID) {
		t.Fatalf("%+v", c)
	}
	if _, ok := got["entra access token"]; ok {
		t.Fatal("no token was requested, so none can be checked")
	}
	if got["entra tenant"].Status != doctor.Pass {
		t.Fatalf("organizations discovery: %+v", got["entra tenant"])
	}
}

// With a federated token in place of a secret, no fix talks about a secret: a failure Entra names
// gets its own fix (an operator hint), and every other one says what the federated identity
// credential must match (Microsoft's error reference lists no code for a credential that does not).
func TestDiagnoseWithAFederatedTokenNeverBlamesASecret(t *testing.T) {
	federated := Diagnosis{TenantSetting: "TENANT_SETTING", ClientIDSetting: "CLIENT_ID_SETTING", FederatedTokenSetting: "TOKEN_SETTING"}
	const mustMatch = "TOKEN_SETTING must match one of the app's federated identity credentials exactly: issuer, subject and audience"
	for _, tc := range []struct {
		name      string
		opts      []fakeidp.Option
		setup     func(*testing.T, *env)
		status    doctor.Status
		inMessage string
		inFix     string
	}{
		{name: "invalid client secret", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.InvalidClientSecret)},
			status: doctor.Fail, inMessage: "AADSTS7000215", inFix: mustMatch},
		{name: "expired client secret", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.ExpiredClientSecret)},
			status: doctor.Fail, inMessage: "AADSTS7000222", inFix: mustMatch},
		{name: "no matching federated credential", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.NoMatchingFederatedCredential)},
			status: doctor.Fail, inMessage: "the client-credentials probe failed", inFix: mustMatch},
		{name: "a failure with an operator hint", opts: []fakeidp.Option{fakeidp.FailToken(fakeidp.GrantClientCredentials, &fakeidp.BlockedByConditionalAccess)},
			status: doctor.Fail, inMessage: "AADSTS53003", inFix: "Conditional Access"},
		{name: "an empty token file", setup: func(t *testing.T, e *env) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			rebuild(t, e, func(c *Config) { c.ClientAuth = idp.AssertionFile(path) })
		}, status: doctor.Fail, inMessage: "not sent: idp: the client credential could not be made", inFix: "TOKEN_SETTING must exist, be readable by the proxy and hold the current token"},
		{name: "organizations mode", setup: func(t *testing.T, e *env) {
			rebuild(t, e, func(c *Config) { c.Tenant, c.AllowedTenants = Organizations, []string{fakeidp.NewGUID()} })
		}, status: doctor.Skip, inMessage: "not probed", inFix: "az ad app federated-credential list --id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{}, tc.opts...)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			r := diagnose(t, e.p, federated)["entra app and credential"]
			if r.Status != tc.status || !strings.Contains(r.Message, tc.inMessage) || !strings.Contains(r.Fix, tc.inFix) || strings.Contains(r.Fix, "secret") {
				t.Fatalf("%+v\nwant status %s, message with %q, fix with %q and no secret", r, tc.status, tc.inMessage, tc.inFix)
			}
		})
	}
}
