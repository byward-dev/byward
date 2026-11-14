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
	"time"

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

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, key := range map[string]string{"EC P-384": pkcs8PEM(t, p384), "Ed25519": pkcs8PEM(t, edKey), "not PEM": "s3cret"} {
		c := oidcConfig("keycloak", func(c *config.Config) { c.OIDCClientSecret, c.OIDCClientKey = "", key })
		if _, err := newIdentityProvider(c, nil); err == nil || !strings.Contains(err.Error(), "BYWARD_OIDC_CLIENT_KEY_FILE") {
			t.Errorf("%s: %v, want an error naming BYWARD_OIDC_CLIENT_KEY_FILE", name, err)
		}
	}
}

// Okta refuses PS256 client assertions, so an RSA key left on PS256 with the okta preset warns at
// startup and check, naming the setting; RS256, an EC key or another preset does not (#306).
// doctor's credential check names the credential, and when its probe cannot tell (here: no
// discovery) the refusal is its warning.
func TestAnOktaClientKeyOnPS256Warns(t *testing.T) {
	rsaKey := pkcs8PEM(t, fakeidp.NewCertificate(t).Key)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const notProbed = "not probed: discovery failed; the credential: "
	const oktaRefuses = ", which Okta refuses for client assertions"
	oktaWarning := Warning{Message: "the client key signs with PS256" + oktaRefuses, Setting: "BYWARD_OIDC_CLIENT_KEY_ALG", Fix: "sign with RS256, or use an EC P-256 key"}
	for _, tc := range []struct {
		name, preset, key, alg, kid string
		warns                       bool
		credential                  string // as check and doctor name it
	}{
		{name: "okta, an RSA key by default", preset: "okta", key: rsaKey, warns: true, credential: "private_key_jwt signed with PS256"},
		{name: "okta, an RSA key with PS256 and a key ID", preset: "okta", key: rsaKey, alg: "PS256", kid: "k1", warns: true, credential: "private_key_jwt signed with PS256, key ID k1"},
		{name: "okta, an RSA key with RS256 and a key ID", preset: "okta", key: rsaKey, alg: "RS256", kid: "k1", credential: "private_key_jwt signed with RS256, key ID k1"},
		{name: "okta, an EC key", preset: "okta", key: pkcs8PEM(t, p256), credential: "private_key_jwt signed with ES256"},
		{name: "keycloak, an RSA key by default", preset: "keycloak", key: rsaKey, credential: "private_key_jwt signed with PS256"},
		{name: "okta, a client secret", preset: "okta", credential: "a client secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, err := newIdentityProvider(oidcConfig(tc.preset, func(c *config.Config) {
				if tc.preset == "okta" { // the okta preset accepts only an /oauth2/ issuer
					c.OIDCIssuer = "https://acme.okta.com/oauth2/default"
				}
				if tc.key != "" {
					c.OIDCClientSecret, c.OIDCClientKey, c.OIDCClientKeyAlg, c.OIDCClientKeyID = "", tc.key, tc.alg, tc.kid
				}
			}), nil)
			if err != nil {
				t.Fatal(err)
			}
			// startup and check: a start warning, so doctor does not also list it as configuration
			var wantStart []Warning
			if tc.warns {
				wantStart = []Warning{oktaWarning}
			}
			if got := ip.startWarningsAt(time.Now()); !slices.Equal(got, wantStart) ||
				slices.ContainsFunc(ip.warnings, func(w Warning) bool { return w.Setting == "BYWARD_OIDC_CLIENT_KEY_ALG" }) {
				t.Fatalf("start warnings %+v, warnings %+v; want start warnings %+v only", got, ip.warnings, wantStart)
			}
			// doctor's credential check; a cancelled context keeps discovery off the network.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			want, wantFix, wantMessage := doctor.Skip, "", notProbed+tc.credential
			if tc.warns {
				want, wantFix, wantMessage = doctor.Warn, oktaWarning.Setting+": "+oktaWarning.Fix, notProbed+tc.credential+"; "+oktaWarning.Message
			}
			results := ip.diagnose(ctx, time.Now())
			if len(results) == 0 {
				t.Fatal("doctor returned no results")
			}
			if r := results[len(results)-1]; r.Name != "client credential" || r.Status != want ||
				r.Message != wantMessage || r.Fix != wantFix {
				t.Fatalf("doctor's last result %+v, want client credential, %s, %q, fix %q", r, want, wantMessage, wantFix)
			}
		})
	}
}

// pkcs8PEM is key as a PEM PKCS #8 private key, as BYWARD_OIDC_CLIENT_KEY_FILE holds it.
func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// doctor's credential check names the credential; unless its probe passed, a key algorithm the
// preset refuses is added to what the probe found, keeping the probe's own status (a skipped probe
// becomes a warning) and its own fix, and not repeated when the fix already gives the advice (#306).
func TestDoctorAddsARefusedKeyAlgorithmToWhatItsProbeFound(t *testing.T) {
	refused := &Warning{Message: "the client key signs with PS256, which Okta refuses for client assertions", Setting: "BYWARD_OIDC_CLIENT_KEY_ALG", Fix: "sign with RS256, or use an EC P-256 key"}
	const desc, keyAlgFix = "private_key_jwt signed with PS256", "BYWARD_OIDC_CLIENT_KEY_ALG: sign with RS256, or use an EC P-256 key"
	for _, tc := range []struct {
		name    string
		probe   doctor.Result
		refused *Warning
		want    doctor.Result
	}{
		{"no refused algorithm", doctor.Result{Status: doctor.Fail, Message: "m", Fix: "f"}, nil,
			doctor.Result{Status: doctor.Fail, Message: "m; the credential: " + desc, Fix: "f"}},
		{"a probe that passed", doctor.Result{Status: doctor.Pass, Message: "accepted"}, refused,
			doctor.Result{Status: doctor.Pass, Message: "accepted; the credential: " + desc}},
		{"a probe that could not run", doctor.Result{Status: doctor.Skip, Message: "not probed"}, refused,
			doctor.Result{Status: doctor.Warn, Message: "not probed; the credential: " + desc + "; " + refused.Message, Fix: keyAlgFix}},
		{"a probe that cannot tell", doctor.Result{Status: doctor.Warn, Message: "unclear", Fix: "sign in once"}, refused,
			doctor.Result{Status: doctor.Warn, Message: "unclear; the credential: " + desc + "; " + refused.Message, Fix: "sign in once; " + keyAlgFix}},
		{"a probe that failed for another reason", doctor.Result{Status: doctor.Fail, Message: "no answer", Fix: "check the network"}, refused,
			doctor.Result{Status: doctor.Fail, Message: "no answer; the credential: " + desc + "; " + refused.Message, Fix: "check the network; " + keyAlgFix}},
		{"a refused key whose fix gives the advice", doctor.Result{Status: doctor.Fail, Message: "refused", Fix: "Okta refuses PS256 for client assertions: set BYWARD_OIDC_CLIENT_KEY_ALG=RS256; otherwise register the key"}, refused,
			doctor.Result{Status: doctor.Fail, Message: "refused; the credential: " + desc, Fix: "Okta refuses PS256 for client assertions: set BYWARD_OIDC_CLIENT_KEY_ALG=RS256; otherwise register the key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := withCredential(tc.probe, desc, tc.refused); got != tc.want {
				t.Fatalf("result %+v\nwant   %+v", got, tc.want)
			}
		})
	}
}

// At Okta, doctor trusts its probe of a PS256 key over the preset: an IdP that accepts PS256 passes,
// one that refuses it fails, its fix leading with the refusal and naming the setting once (#306).
func TestDoctorAtOktaTrustsItsProbeOfAPS256Key(t *testing.T) {
	const issuer = "https://acme.okta.com/oauth2/default"
	const lead = "Okta refuses PS256 for client assertions: set BYWARD_OIDC_CLIENT_KEY_ALG=RS256 (or use an EC P-256 key); otherwise register the public key"
	for _, tc := range []struct {
		name string
		opts []fakeidp.Option
		want doctor.Status
	}{
		{"an IdP that accepts PS256", nil, doctor.Pass},
		{"an IdP that refuses PS256", []fakeidp.Option{fakeidp.WithClientAssertionAlgs("RS256")}, doctor.Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := fakeidp.NewCertificate(t)
			app := fakeidp.Client{ID: "byward", Certificates: []*fakeidp.Certificate{cert}}
			fake := fakeidp.New(t, fakeidp.Generic, append([]fakeidp.Option{fakeidp.WithTLS(), fakeidp.WithIssuer(issuer), fakeidp.WithClient(app)}, tc.opts...)...)
			ip, err := newIdentityProvider(oidcConfig("okta", func(c *config.Config) {
				c.OIDCIssuer, c.OIDCClientID = issuer, app.ID
				c.OIDCClientSecret, c.OIDCClientKey, c.OIDCClientKeyID = "", pkcs8PEM(t, cert.Key), cert.ThumbprintSHA256()
			}), fake.HTTPClient())
			if err != nil {
				t.Fatal(err)
			}
			results := ip.diagnose(context.Background(), time.Now())
			if len(results) == 0 {
				t.Fatal("doctor returned no results")
			}
			r := results[len(results)-1]
			if refused := tc.want == doctor.Fail; r.Name != "client credential" || r.Status != tc.want ||
				strings.HasPrefix(r.Fix, lead) != refused || (strings.Count(r.Fix, "BYWARD_OIDC_CLIENT_KEY_ALG") == 1) != refused {
				t.Fatalf("result %+v; want the credential check %s, leading with the refusal once: %v", r, tc.want, refused)
			}
		})
	}
}

// An algorithm the client key cannot sign with refuses to start, naming BYWARD_OIDC_CLIENT_KEY_ALG
// (#306); the credential each accepted one describes is TestAnOktaClientKeyOnPS256Warns's.
func TestAClientKeyAlgorithmTheKeyCannotUseRefusesToStart(t *testing.T) {
	rsaKey := pkcs8PEM(t, fakeidp.NewCertificate(t).Key)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey := pkcs8PEM(t, p256)
	for name, tc := range map[string]struct{ key, alg string }{
		"RS256 with an EC key":  {ecKey, "RS256"},
		"ES256 with an RSA key": {rsaKey, "ES256"},
	} {
		t.Run(name, func(t *testing.T) {
			c := oidcConfig("keycloak", func(c *config.Config) { c.OIDCClientSecret, c.OIDCClientKey, c.OIDCClientKeyAlg = "", tc.key, tc.alg })
			if _, err := newIdentityProvider(c, nil); err == nil || !strings.HasPrefix(err.Error(), "BYWARD_OIDC_CLIENT_KEY_ALG: ") {
				t.Fatalf("err = %v, want an error naming BYWARD_OIDC_CLIENT_KEY_ALG", err)
			}
		})
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
// and a wrong secret fails naming its setting; the result names the credential (#306). Nothing
// Entra's is reported.
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
				!strings.HasSuffix(idpChecks[1].Message, "; the credential: a client secret") ||
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
