package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/oidc"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

func oidcConfig(idpName string, change func(*config.Config)) *config.Config {
	pub, _ := url.Parse("https://mcp.example.com/mcp")
	c := &config.Config{PublicURL: pub, IdP: idpName, OIDCIssuer: "https://sso.example.com/realms/acme", OIDCClientID: "byward",
		OIDCClientSecret: "s3cret", OIDCSubjectClaim: "sub"}
	if change != nil {
		change(c)
	}
	return c
}

// config.OIDCPresets is what BYWARD_IDP accepts and oidc.Presets is what the adapter knows; they are
// kept apart so config does not import the adapter, and this keeps them in step.
func TestEveryPresetCanBeSelectedNamedAndHasItsDefaults(t *testing.T) {
	var known []string
	for name, p := range oidc.Presets {
		if name == "" {
			continue
		}
		known = append(known, name)
		if p.Label == "" {
			t.Errorf("preset %s has no label for the consent page", name)
		}
	}
	sort.Strings(known)
	selectable := slices.Sorted(slices.Values(config.OIDCPresets))
	if !slices.Equal(known, selectable) {
		t.Errorf("the adapter's presets %v differ from those BYWARD_IDP accepts %v", known, selectable)
	}
	for name, p := range oidc.Presets {
		if p.DefaultIssuer != config.OIDCDefaultIssuers[name] {
			t.Errorf("%s's default issuer: adapter %q, config %q", name, p.DefaultIssuer, config.OIDCDefaultIssuers[name])
		}
	}
}

// The IdP is labelled by its preset's brand, a plain oidc IdP by its issuer's host, and
// BYWARD_OIDC_NAME wins over both; the wired-server test checks the label on the consent page.
func TestTheIdPIsLabelledByItsPresetItsIssuerHostOrItsChosenName(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg   *config.Config
		label string
	}{
		"a preset":      {oidcConfig("keycloak", nil), "Keycloak"},
		"plain oidc":    {oidcConfig("oidc", nil), "sso.example.com"},
		"a chosen name": {oidcConfig("keycloak", func(c *config.Config) { c.OIDCName = "Acme SSO" }), "Acme SSO"},
	} {
		t.Run(name, func(t *testing.T) {
			ip, err := newIdentityProvider(tc.cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if ip.label != tc.label {
				t.Fatalf("label %q, want %q", ip.label, tc.label)
			}
		})
	}
}

// Google is asked for a hosted domain (hd) only when the gate lists exactly one, and the extra
// scopes reach the IdP.
func TestGoogleIsAskedForTheExtraScopesAndAHostedDomainOnlyWhenTheGateListsOne(t *testing.T) {
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}}
	fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
	for name, tc := range map[string]struct {
		domains []string
		hd      string
	}{
		"one domain":  {[]string{"acme.example"}, "acme.example"},
		"two domains": {[]string{"a.example", "b.example"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			ip := fakeIdentityProvider(t, fake, app, "google", func(c *config.Config) { c.GateHostedDomains, c.OIDCScopes = tc.domains, []string{"groups"} })
			q := authorizeAt(t, ip)
			if q.Get("hd") != tc.hd || !strings.Contains(" "+q.Get("scope")+" ", " groups ") {
				t.Fatalf("authorization query %v: want hd %q and the groups scope", q, tc.hd)
			}
		})
	}
}

// The IdP's callback path is its name: what the operator registers at the IdP.
func TestTheCallbackPathIsTheIdPsName(t *testing.T) {
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}}
	fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
	for _, name := range []string{"oidc", "google"} { // presets without an issuer pattern, so the fake can serve them
		t.Run(name, func(t *testing.T) {
			ip := fakeIdentityProvider(t, fake, app, name, nil)
			if got, want := authorizeAt(t, ip).Get("redirect_uri"), "https://mcp.example.com/callback/"+name; got != want {
				t.Fatalf("redirect_uri %q, want %q", got, want)
			}
		})
	}
}

// With a PEM key the proxy signs in with private_key_jwt, the assertion carrying
// BYWARD_OIDC_CLIENT_KEY_ID; keys it cannot sign with name the setting.
func TestAClientKeySignsInWithItsKeyIDAndAnUnusableOneNamesTheSetting(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	der, err := x509.MarshalPKCS8PrivateKey(cert.Key)
	if err != nil {
		t.Fatal(err)
	}
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Certificates: []*fakeidp.Certificate{cert}, RedirectURIs: []string{"https://mcp.example.com/callback/oidc"}}
	fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
	ip := fakeIdentityProvider(t, fake, app, "oidc", func(c *config.Config) {
		c.OIDCClientSecret, c.OIDCClientKey, c.OIDCClientKeyID = "", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), cert.ThumbprintSHA256()
	})
	q := authorizeAt(t, ip)
	res, err := fake.HTTPClient().Get(fake.AuthorizeURL("") + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if _, _, err := ip.adapter.Callback(context.Background(), mustQuery(t, res.Header.Get("Location")), testLogin); err != nil {
		t.Fatalf("code exchange with private_key_jwt: %v", err)
	}

	pkcs8 := func(key any) string {
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, key := range map[string]string{"EC P-384": pkcs8(p384), "Ed25519": pkcs8(edKey), "not PEM": "s3cret"} {
		c := oidcConfig("keycloak", func(c *config.Config) { c.OIDCClientSecret, c.OIDCClientKey = "", key })
		if _, err := newIdentityProvider(c, nil); err == nil || !strings.Contains(err.Error(), "BYWARD_OIDC_CLIENT_KEY_FILE") {
			t.Errorf("%s: %v, want an error naming BYWARD_OIDC_CLIENT_KEY_FILE", name, err)
		}
	}
}

// check reports a subject claim users can change, naming the setting.
func TestCheckReportsAMutableSubjectClaim(t *testing.T) {
	warnings, err := CheckOffline(loadOIDC(t, "keycloak", "https://sso.example.com/realms/acme", "c", "BYWARD_OIDC_SUBJECT_CLAIM=email"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(warnings, func(w Warning) bool { return w.Setting == "BYWARD_OIDC_SUBJECT_CLAIM" }) {
		t.Fatalf("warnings %+v, want one for BYWARD_OIDC_SUBJECT_CLAIM", warnings)
	}
}

// doctor checks an oidc IdP's discovery and then its client credential (#288): a matching issuer
// passes and a mismatch fails naming the setting; the credential is checked only after discovery,
// and a wrong secret fails naming its setting. Nothing Entra's is reported.
func TestDoctorChecksAnOIDCIdPsDiscoveryAndClientCredential(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		other, secretAtTheIdP string // other: appended to the issuer
		discovery, credential doctor.Status
		fix                   string
	}{
		{"the discovered issuer and the right secret", "", "s3cret", doctor.Pass, doctor.Pass, ""},
		{"another issuer", "/other", "s3cret", doctor.Fail, doctor.Skip, "BYWARD_OIDC_ISSUER"},
		{"a secret the IdP does not hold", "", "rotated", doctor.Pass, doctor.Fail, "BYWARD_OIDC_CLIENT_SECRET_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{tc.secretAtTheIdP}}
			fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
			report, err := Doctor(context.Background(), loadOIDC(t, "oidc", fake.Issuer()+tc.other, app.ID), DoctorOptions{IdP: fake.HTTPClient()})
			if err != nil {
				t.Fatal(err)
			}
			var idpChecks []doctor.Result
			for _, r := range report.Checks {
				if strings.Contains(r.Message+r.Fix, "ENTRA") {
					t.Errorf("an oidc IdP's doctor names Entra: %+v", r)
				}
				if r.Class == doctor.ClassIdP {
					idpChecks = append(idpChecks, r)
				}
			}
			if len(idpChecks) != 2 || idpChecks[0].Name != "discovery" || idpChecks[0].Status != tc.discovery ||
				idpChecks[1].Name != "client credential" || idpChecks[1].Status != tc.credential ||
				!strings.Contains(idpChecks[0].Fix+idpChecks[1].Fix, tc.fix) {
				t.Fatalf("IdP checks %+v, want discovery %s then the client credential %s, a fix naming %q", idpChecks, tc.discovery, tc.credential, tc.fix)
			}
		})
	}
}

// doctor's fixes for an oidc client credential name the setting that holds it: the secret file, or
// the key file with private_key_jwt.
func TestTheOIDCCredentialFixNamesTheSettingThatHoldsIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		setting string
		key     bool
	}{
		{"a secret", config.Config{OIDCClientSecret: "s"}, "BYWARD_OIDC_CLIENT_SECRET_FILE", false},
		{"a key", config.Config{OIDCClientKey: "-----BEGIN PRIVATE KEY-----"}, "BYWARD_OIDC_CLIENT_KEY_FILE", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := oidcDiagnosis(&tc.cfg)
			if d.ClientIDSetting != "BYWARD_OIDC_CLIENT_ID" || d.CredentialSetting != tc.setting || d.KeyCredential != tc.key {
				t.Fatalf("diagnosis %+v, want the credential in %s (key %v)", d, tc.setting, tc.key)
			}
		})
	}
}

// authorizeAt builds the IdP authorization URL and returns its query.
func authorizeAt(t *testing.T, ip *identityProvider) url.Values {
	t.Helper()
	login, err := ip.adapter.AuthCodeURL(context.Background(), testLogin)
	if err != nil {
		t.Fatal(err)
	}
	return mustQuery(t, login)
}

// testLogin is the login state the tests sign in with.
var testLogin = idp.Login{State: "s", Nonce: "n", CodeVerifier: strings.Repeat("v", 43)}

// fakeIdentityProvider is an oidc IdP named name at fake, in development mode (the fake serves http
// on loopback); change adjusts the configuration first.
func fakeIdentityProvider(t *testing.T, fake *fakeidp.IdP, app fakeidp.Client, name string, change func(*config.Config)) *identityProvider {
	t.Helper()
	c := oidcConfig(name, func(c *config.Config) {
		c.OIDCIssuer, c.OIDCClientID, c.Dev = fake.Issuer(), app.ID, true
		if change != nil {
			change(c)
		}
	})
	ip, err := newIdentityProvider(c, fake.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	return ip
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// The gate's lists follow the IdP (ADR-0015): hosted domains are Google's, Entra's tenants are
// Entra's, verified email domains are any oidc IdP's, and an oidc IdP's empty gate needs
// BYWARD_GATE_ALLOW_EMPTY.
func TestTheGateListsFollowTheIdP(t *testing.T) {
	const keycloak = "https://sso.example.com/realms/acme"
	for name, tc := range map[string]struct {
		idp, issuer, setting string
		want                 []string // in the refusal; none: it starts
	}{
		"google with hosted domains":   {"google", config.OIDCDefaultIssuers["google"], "BYWARD_GATE_HOSTED_DOMAINS=acme.example", nil},
		"keycloak with hosted domains": {"keycloak", keycloak, "BYWARD_GATE_HOSTED_DOMAINS=acme.example", []string{"BYWARD_GATE_HOSTED_DOMAINS", "only with Google"}},
		"keycloak with email domains":  {"keycloak", keycloak, "BYWARD_GATE_EMAIL_DOMAINS=acme.example", nil},
		"keycloak with tenants":        {"keycloak", keycloak, "BYWARD_GATE_TENANTS=00000000-0000-0000-0000-000000000001", []string{"BYWARD_GATE_TENANTS", "only with Entra"}},
		"keycloak with an empty gate":  {"keycloak", keycloak, "BYWARD_GATE_ALLOW_EMPTY=false", []string{"BYWARD_GATE_ALLOW_EMPTY"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadAuthParts(loadOIDC(t, tc.idp, tc.issuer, "c", tc.setting), nil)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("want it to start: %v", err)
				}
				return
			}
			for _, w := range tc.want {
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Fatalf("err = %v, want a refusal containing %q", err, w)
				}
			}
		})
	}
}
