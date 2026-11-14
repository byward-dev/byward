package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/byward-dev/byward/internal/apptoken"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/gate"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/idp/oidc"
)

// identityProvider is the IdP users sign in with (BYWARD_IDP): its adapter, the name that labels
// its callback path, audit records and metrics, and how the consent page, the gate and doctor see it.
type identityProvider struct {
	name     string // the BYWARD_IDP value: /callback/<name>
	redirect string // the callback URL to register at the IdP
	label    string // for the consent page ("You'll sign in with <label> next")
	adapter  broker.IdP
	entra    *entra.Provider // the Entra adapter, for On-Behalf-Of (ADR-0017); nil for any other IdP
	scope    string          // the scope sent to the IdP, for the consent page's technical details
	gateIdP  string          // gate.Entra, gate.Google or gate.Generic
	// warnings are logged at every start and reported by check and doctor.
	warnings []Warning
	// userKey checks and canonicalises an operator's user key for revoke-user, as the IdP's
	// subjects look.
	userKey func(string) (string, bool)
	// diagnose is doctor's check of the IdP.
	diagnose func(ctx context.Context, now time.Time) []doctor.Result
	// startWarnings are the warnings logged at startup and reported by check that doctor reports
	// through diagnose instead, as a result of the IdP class: those that depend on the time, and a
	// client key algorithm the IdP refuses (#306), unless doctor's probe shows the IdP accepted the
	// key. Nil when there are none.
	startWarnings func(now time.Time) []Warning
	// appTokens verifies app-only tokens for BYWARD_APP_TOKENS (ADR-0022); Entra only, else nil.
	appTokens apptoken.Verifier
	// startRefusal, when set, is why the proxy must not start at now (an expired certificate);
	// serving and check refuse, doctor reports it as a result and revoke-user ignores it.
	startRefusal func(now time.Time) error
	// credentialDesc describes the client credential for check and doctor (#306); "" for Entra,
	// whose doctor checks its credential itself.
	credentialDesc string
}

// refusal is ip.startRefusal at now, or nil.
func (ip *identityProvider) refusal(now time.Time) error {
	if ip.startRefusal == nil {
		return nil
	}
	return ip.startRefusal(now)
}

// startWarningsAt is ip.startWarnings at now, or none.
func (ip *identityProvider) startWarningsAt(now time.Time) []Warning {
	if ip.startWarnings == nil {
		return nil
	}
	return ip.startWarnings(now)
}

// newIdentityProvider builds the configured adapter from settings alone; discovery stays lazy.
// Errors name the settings family at fault. idpHTTP reaches the IdP (nil: the default client);
// the IdP is the operator's, so it is not behind the SSRF guard.
func newIdentityProvider(cfg *config.Config, idpHTTP *http.Client) (*identityProvider, error) {
	redirect := config.RedirectURL(cfg.PublicURL, cfg.IdP)
	if cfg.IdP == "entra" {
		return newEntraIdentityProvider(cfg, idpHTTP, redirect)
	}
	return newOIDCIdentityProvider(cfg, idpHTTP, redirect)
}

// newEntraProvider is entra.New; tests replace it to reach a fake IdP through its HTTP client
// (named IdP endpoints are never configurable).
var newEntraProvider = entra.New

// newEntraIdentityProvider is Entra (ADR-0012), with its own doctor checks, the credential's expiry
// warning, and the refusal to start with an expired certificate.
func newEntraIdentityProvider(cfg *config.Config, idpHTTP *http.Client, redirect string) (*identityProvider, error) {
	auth, diag, certExpires, err := entraClientAuth(cfg)
	if err != nil {
		return nil, err
	}
	p, err := newEntraProvider(entra.Config{Tenant: cfg.EntraTenant, ClientID: cfg.EntraClientID,
		ClientAuth: auth, RedirectURL: redirect, HTTPClient: idpHTTP})
	if err != nil {
		return nil, fmt.Errorf("entra settings (BYWARD_ENTRA_*): %w", err)
	}
	return &identityProvider{name: cfg.IdP, redirect: redirect, label: "Microsoft Entra", adapter: p, entra: p, scope: p.Scope(), gateIdP: gate.Entra, userKey: entra.UserKey, appTokens: p,
		diagnose: func(ctx context.Context, now time.Time) []doctor.Result {
			out := p.Diagnose(ctx, diag)
			switch {
			case cfg.EntraClientSecret != "": // a secret and a certificate expire; a federated token renews itself
				out = append(out, secretExpiry(cfg, now))
			case !certExpires.IsZero():
				out = append(out, doctor.CertificateExpiry(diag.CredentialSetting, certExpires, now))
			}
			return out
		},
		startWarnings: func(now time.Time) []Warning {
			w, ok := expiryWarning(cfg, now)
			if !certExpires.IsZero() {
				r := doctor.CertificateExpiry(diag.CredentialSetting, certExpires, now)
				w, ok = Warning{Message: r.Message, Setting: diag.CredentialSetting, Fix: r.Fix}, r.Status == doctor.Warn || r.Status == doctor.Fail
			}
			if ok {
				return []Warning{w}
			}
			return nil
		},
		startRefusal: func(now time.Time) error {
			if certExpires.IsZero() || now.Before(certExpires) {
				return nil
			}
			return fmt.Errorf("%s: the certificate expired on %s: make and upload a new one (docs/how-to/entra-certificate.md)", diag.CredentialSetting, certExpires.UTC().Format(time.DateOnly))
		}}, nil
}

// newOIDCIdentityProvider is the generic OIDC adapter with the configured preset (ADR-0011 §2).
func newOIDCIdentityProvider(cfg *config.Config, idpHTTP *http.Client, redirect string) (*identityProvider, error) {
	auth, credentialDesc, err := oidcClientAuth(cfg)
	if err != nil {
		return nil, err
	}
	preset := ""
	if slices.Contains(config.OIDCPresets, cfg.IdP) {
		preset = cfg.IdP
	}
	hd := ""
	if oidc.Presets[preset].HostedDomains && len(cfg.GateHostedDomains) == 1 {
		hd = cfg.GateHostedDomains[0] // also the hd hint at Google; the gate list stays the rule (ADR-0015)
	}
	keyAlgSetting := config.Setting{Name: "oidc-client-key-alg"}.Env()
	p, err := oidc.New(oidc.Config{Preset: preset, Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientAuth: auth, KeyAlgSetting: keyAlgSetting, RedirectURL: redirect,
		Scopes: cfg.OIDCScopes, SubjectClaim: cfg.OIDCSubjectClaim, RolesClaim: cfg.OIDCRolesClaim, GroupsClaim: cfg.OIDCGroupsClaim, HostedDomain: hd, AllowLoopbackHTTP: cfg.Dev, HTTPClient: idpHTTP})
	if err != nil {
		return nil, fmt.Errorf("oidc settings (BYWARD_OIDC_*): %w", err)
	}
	// An algorithm the preset's IdP refuses without advertising it, so only the preset can tell
	// (#306); signing is unchanged, startup and check warn, and doctor's credential check adds it
	// (withCredential).
	var refused *Warning
	if info, ok := auth.(idp.AssertionInfo); ok && slices.Contains(oidc.Presets[preset].RefusedAssertionAlgs, info.SigningAlgorithm()) {
		refused = &Warning{Message: "the client key signs with " + info.SigningAlgorithm() + ", which " + oidc.Presets[preset].Label +
			" refuses for client assertions", Setting: keyAlgSetting, Fix: oidc.RefusedAssertionAdvice(info.SigningAlgorithm(), oidc.Presets[preset])}
	}
	ip := &identityProvider{name: cfg.IdP, redirect: redirect, label: oidcLabel(cfg), adapter: p, scope: p.Scope(), gateIdP: gate.Generic, userKey: oidcUserKey,
		credentialDesc: credentialDesc,
		diagnose: func(ctx context.Context, _ time.Time) []doctor.Result {
			return append(diagnoseDiscovery(ctx, p, cfg.OIDCIssuer), withCredential(p.DiagnoseClient(ctx, oidcDiagnosis(cfg)), credentialDesc, refused))
		}}
	if oidc.Presets[preset].HostedDomains {
		ip.gateIdP = gate.Google // the gate's kind for an IdP with hosted domains
	}
	for _, w := range p.Warnings() {
		ip.warnings = append(ip.warnings, Warning{Message: w, Setting: "BYWARD_OIDC_SUBJECT_CLAIM", Fix: "use sub, which the IdP never reassigns (ADR-0011 §2)"})
	}
	if refused != nil { // doctor reports it through the credential check (withCredential), not twice
		ip.startWarnings = func(time.Time) []Warning { return []Warning{*refused} }
	}
	return ip, nil
}

// withCredential is doctor's probe of the oidc credential (#288) naming the credential (#306).
// Unless the probe passed, a key algorithm the preset refuses (refused, nil if none) is added to
// what the probe found, keeping its own fix: a probe that could not run becomes a warning, and a
// refused key's fix that already leads with the refusal (naming refused.Setting) is left as it is.
func withCredential(r doctor.Result, credentialDesc string, refused *Warning) doctor.Result {
	r.Message += "; the credential: " + credentialDesc
	if refused == nil || r.Status == doctor.Pass || strings.Contains(r.Fix, refused.Setting) {
		return r
	}
	if r.Status == doctor.Skip {
		r.Status = doctor.Warn
	}
	r.Message += "; " + refused.Message
	if r.Fix != "" {
		r.Fix += "; "
	}
	r.Fix += refused.Setting + ": " + refused.Fix
	return r
}

// oidcUserKey is an oidc subject as an operator gives it to revoke-user: exactly as the IdP sends it
// (sub is case-sensitive), trimmed, never empty or with control characters.
func oidcUserKey(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && !strings.ContainsFunc(s, unicode.IsControl)
}

// oidcLabel is BYWARD_OIDC_NAME, else the preset's name, else the issuer's host.
func oidcLabel(cfg *config.Config) string {
	if cfg.OIDCName != "" {
		return cfg.OIDCName
	}
	if l := oidc.Presets[cfg.IdP].Label; l != "" {
		return l
	}
	if u, err := url.Parse(cfg.OIDCIssuer); err == nil && u.Host != "" {
		return u.Host
	}
	return "your identity provider"
}

// entraClientAuth is the Entra app's credential (ADR-0012 §5), the one config allowed: the client
// secret, the federated token file or the certificate, which is loaded here; the certificate's end
// date (zero for the other kinds), for its expiry checks, so the key stays inside the ClientAuth;
// and the settings doctor names in its fixes for it.
func entraClientAuth(cfg *config.Config) (idp.ClientAuth, entra.Diagnosis, time.Time, error) {
	d := entra.Diagnosis{TenantSetting: config.Setting{Name: "entra-tenant"}.Env(), ClientIDSetting: config.Setting{Name: "entra-client-id"}.Env(),
		GateRoles: cfg.GateRoles, AppRoles: cfg.AppRoles}
	switch {
	case cfg.EntraFederatedTokenFile != "": // re-read on every request, never cached
		d.CredentialKind, d.CredentialSetting = entra.CredentialFederated, config.Setting{Name: "entra-federated-token-file"}.Env()
		return idp.AssertionFile(cfg.EntraFederatedTokenFile), d, time.Time{}, nil
	case cfg.EntraClientCertificate != "":
		d.CredentialKind, d.CredentialSetting = entra.CredentialCertificate, config.Setting{Name: "entra-client-certificate"}.Env()+"_FILE"
		cert, err := entra.LoadCertificate([]byte(cfg.EntraClientCertificate))
		if err != nil {
			return nil, d, time.Time{}, fmt.Errorf("%s: %w (docs/how-to/entra-certificate.md)", d.CredentialSetting, err)
		}
		auth, err := cert.ClientAuth()
		if err != nil {
			return nil, d, time.Time{}, fmt.Errorf("%s: %w", d.CredentialSetting, err)
		}
		return auth, d, cert.X509.NotAfter, nil
	}
	d.CredentialKind, d.CredentialSetting = entra.CredentialSecret, config.Setting{Name: "entra-client-secret"}.Env()+"_FILE"
	return idp.ClientSecret(cfg.EntraClientSecret), d, time.Time{}, nil
}

// oidcDiagnosis names the settings of the oidc client and its credential, for doctor's fixes.
func oidcDiagnosis(cfg *config.Config) oidc.Diagnosis {
	d := oidc.Diagnosis{ClientIDSetting: config.Setting{Name: "oidc-client-id"}.Env(), CredentialSetting: config.Setting{Name: "oidc-client-secret"}.Env() + "_FILE"}
	if cfg.OIDCClientKey != "" {
		d.CredentialSetting, d.KeyCredential = config.Setting{Name: "oidc-client-key"}.Env()+"_FILE", true
	}
	return d
}

// oidcClientAuth is the proxy's credential at an oidc IdP, a client secret or private_key_jwt with a
// PEM key, and its description for check and doctor, which names no secret. Config refuses neither
// or both.
func oidcClientAuth(cfg *config.Config) (idp.ClientAuth, string, error) {
	if cfg.OIDCClientKey == "" {
		return idp.ClientSecret(cfg.OIDCClientSecret), "a client secret", nil
	}
	key, err := idp.ParsePrivateKey([]byte(cfg.OIDCClientKey))
	if err != nil {
		return nil, "", fmt.Errorf("BYWARD_OIDC_CLIENT_KEY_FILE: %w", err)
	}
	auth, err := idp.PrivateKeyJWTWithAlg(key, nil, cfg.OIDCClientKeyID, cfg.OIDCClientKeyAlg)
	switch {
	case errors.Is(err, idp.ErrClientKeyAlg):
		return nil, "", fmt.Errorf("BYWARD_OIDC_CLIENT_KEY_ALG: %w", err)
	case err != nil:
		return nil, "", fmt.Errorf("BYWARD_OIDC_CLIENT_KEY_FILE: %w", err)
	}
	info, ok := auth.(idp.AssertionInfo)
	if !ok {
		return auth, "private_key_jwt", nil
	}
	return auth, describeClientAssertion(info), nil
}

// describeClientAssertion describes a private_key_jwt credential: its signing algorithm and key ID.
func describeClientAssertion(info idp.AssertionInfo) string {
	d := "private_key_jwt signed with " + info.SigningAlgorithm()
	if info.KeyID() != "" {
		d += ", key ID " + info.KeyID()
	}
	return d
}

// diagnoseDiscovery is doctor's check of an oidc IdP: discovery, and that its issuer matches
// (ADR-0011 §7).
func diagnoseDiscovery(ctx context.Context, p idp.Readiness, issuer string) []doctor.Result {
	r := doctor.CheckDiscovery.NewResult()
	if err := p.Ready(ctx); err != nil {
		r.Status, r.Message = doctor.Fail, "the IdP's discovery document at "+issuer+" failed: "+err.Error()
		r.Fix = "BYWARD_OIDC_ISSUER: set it exactly as the IdP's discovery document states its issuer, over https"
		return []doctor.Result{r}
	}
	r.Status, r.Message = doctor.Pass, "discovery at "+issuer+" matches the configured issuer"
	return []doctor.Result{r}
}
