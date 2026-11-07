package entra

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
)

// Diagnosis is what Diagnose needs besides the adapter's own configuration.
type Diagnosis struct {
	// TenantSetting, ClientIDSetting and SecretSetting name the settings, for the fixes.
	TenantSetting, ClientIDSetting, SecretSetting string
	// FederatedTokenSetting names the federated token file when it replaces the secret (ADR-0012
	// §5); SecretSetting is then "".
	FederatedTokenSetting string
	// GateRoles are the access gate's app roles, which the app registration must define.
	GateRoles []string
}

// AADSTS codes doctor names a fix for; the descriptions are Microsoft's error-code reference.
const (
	codeTenantNotFound    = 90002   // InvalidTenantName
	codeResourceNotFound  = 500011  // InvalidResourceServicePrincipalNotFound
	codeAppNotFound       = 700016  // UnauthorizedClient_DoesNotMatchRequest
	codeInvalidSecret     = 7000215 // invalid client secret
	codeExpiredSecret     = 7000222 // InvalidClientSecretExpiredKeysProvided
	codeAppNotAssigned    = 501051  // the app holds no role on a resource that requires assignment
	appIDURIPrefix        = "api://"
	defaultScopeSuffix    = "/.default"
	accessTokenVersionFix = "set api.requestedAccessTokenVersion to 2 on the app registration (docs/how-to/quickstart-entra.md step 1.2)"
	reachFix              = "check that the proxy's host can reach " + Authority + " (DNS, firewall, outbound proxy)"
)

// Diagnose is doctor's Entra part (ADR-0012 §10): the tenant's discovery document and issuer, its
// signing keys, and a client-credentials probe for the app's own resource that validates the
// tenant, the client ID and the credential without any app permission, then checks the token
// Entra issues. The redirect URI and the app roles cannot be read without Microsoft Graph, which
// the proxy never calls (ADR-0012 §8); those results are skips that say how to check by hand.
func (p *Provider) Diagnose(ctx context.Context, d Diagnosis) []doctor.Result {
	out := []doctor.Result{p.diagnoseTenant(ctx, d), p.diagnoseKeys(ctx)}
	cred, claims := p.diagnoseCredential(ctx, d)
	out = append(out, cred...)
	out = append(out, claims...)
	return append(out, p.manualChecks(d)...)
}

func result(name string, s doctor.Status, msg, fix string) doctor.Result {
	return doctor.Result{Class: doctor.ClassIdP, Name: name, Status: s, Message: msg, Fix: fix}
}

func (p *Provider) diagnoseTenant(ctx context.Context, d Diagnosis) doctor.Result {
	const name = "entra tenant"
	var m struct {
		Issuer string `json:"issuer"`
	}
	fix := "set " + d.TenantSetting + " to your tenant ID: az account show --query tenantId -o tsv"
	if err := p.fetch.GetJSON(ctx, p.endpoint("/v2.0/.well-known/openid-configuration"), &m); err != nil {
		return result(name, doctor.Fail, "no discovery document for tenant "+p.cfg.Tenant+": "+err.Error(), fix)
	}
	want := issuerFor(p.cfg.Tenant)
	if p.cfg.Tenant == Organizations {
		want = issuerFor("{tenantid}")
	}
	if m.Issuer != want {
		return result(name, doctor.Fail, fmt.Sprintf("the discovery document names issuer %q, want %q", m.Issuer, want), fix)
	}
	return result(name, doctor.Pass, "discovery document found, issuer "+m.Issuer, "")
}

func (p *Provider) diagnoseKeys(ctx context.Context) doctor.Result {
	const name = "entra signing keys"
	var set jose.JSONWebKeySet
	if err := p.fetch.GetJSON(ctx, p.endpoint("/discovery/v2.0/keys"), &set); err != nil {
		return result(name, doctor.Fail, "cannot fetch the tenant's signing keys: "+err.Error(), reachFix)
	}
	n := idp.SigningKeys(set)
	if n == 0 {
		return result(name, doctor.Fail, "the tenant's key set has no signing key", "check that the proxy's host reaches "+Authority+" directly, not through a proxy that rewrites responses")
	}
	return result(name, doctor.Pass, fmt.Sprintf("the tenant's key set has %d signing key(s)", n), "")
}

// diagnoseCredential requests an app-only token for api://<client-id>/.default. A token, or
// AADSTS501051 (assignment required, and the app holds no role on itself), means Entra accepted the
// tenant, the client ID and the credential.
func (p *Provider) diagnoseCredential(ctx context.Context, d Diagnosis) (cred, claims []doctor.Result) {
	const name = "entra app and credential"
	resource := appIDURIPrefix + p.cfg.ClientID
	if p.cfg.Tenant == Organizations {
		// Microsoft documents the client-credentials tenant only "in GUID or domain-name format",
		// and organizations mode has no home tenant setting to send instead.
		list := "az ad app credential list --id %s lists an unexpired credential"
		if d.FederatedTokenSetting != "" {
			list = "az ad app federated-credential list --id %s lists one matching the token's issuer, subject and audience"
		}
		return []doctor.Result{result(name, doctor.Skip, "not probed: client credentials need the app's home tenant, and organizations mode names none",
				fmt.Sprintf("check by hand: "+list+", and az ad app show --id %s --query api.requestedAccessTokenVersion is 2", p.cfg.ClientID, p.cfg.ClientID))},
			nil
	}
	tr, err := p.token(ctx, url.Values{"grant_type": {"client_credentials"}, "scope": {resource + defaultScopeSuffix}})
	if err == nil {
		return []doctor.Result{result(name, doctor.Pass, "Entra accepted the tenant, the client ID and the credential", "")}, p.diagnoseToken(ctx, tr.AccessToken)
	}
	var ie *idp.Error
	if !errors.As(err, &ie) {
		ie = &idp.Error{Err: err} // token wraps every failure; this keeps any other one as a code-less failure
	}
	code := fmt.Sprintf("AADSTS%d", ie.Code)
	switch ie.Code {
	case codeAppNotAssigned:
		return []doctor.Result{result(name, doctor.Pass, "Entra accepted the tenant, the client ID and the credential", "")},
			[]doctor.Result{result("entra access token", doctor.Skip,
				"Entra issued no token to check ("+code+"): assignment is required on the app, and the app holds no role on itself",
				fmt.Sprintf(`check by hand: az ad app show --id %s --query "{version:api.requestedAccessTokenVersion, claims:optionalClaims.accessToken[].name}" must show version 2`, p.cfg.ClientID))}
	case codeTenantNotFound:
		return []doctor.Result{result(name, doctor.Fail, "Entra does not know tenant "+p.cfg.Tenant+" ("+code+")",
			"set "+d.TenantSetting+" to your tenant ID: az account show --query tenantId -o tsv")}, nil
	case codeAppNotFound:
		return []doctor.Result{result(name, doctor.Fail, "Entra has no app "+p.cfg.ClientID+" in tenant "+p.cfg.Tenant+" ("+code+")",
			"set "+d.ClientIDSetting+" to the app registration's Application (client) ID, and "+d.TenantSetting+" to the tenant it is registered in")}, nil
	case codeInvalidSecret:
		if d.FederatedTokenSetting != "" {
			break // no secret: the general fix below names the federated token
		}
		return []doctor.Result{result(name, doctor.Fail, "Entra rejected the client secret ("+code+")",
			"the file named by "+d.SecretSetting+" must hold the secret's value, not its ID; create a new one: az ad app credential reset --id "+p.cfg.ClientID+" --append --display-name byward --years 1 --query password -o tsv")}, nil
	case codeExpiredSecret:
		if d.FederatedTokenSetting != "" {
			break
		}
		return []doctor.Result{result(name, doctor.Fail, "the client secret has expired ("+code+")",
			"create a new one: az ad app credential reset --id "+p.cfg.ClientID+" --append --display-name byward --years 1 --query password -o tsv, then restart the proxy with it")}, nil
	case codeResourceNotFound:
		return []doctor.Result{result(name, doctor.Fail, "Entra has no resource "+resource+" in tenant "+p.cfg.Tenant+" ("+code+"): the Application ID URI is not set, or the app has no service principal",
			"set the Application ID URI to "+resource+" (docs/how-to/quickstart-entra.md step 1.2) and create the service principal: az ad sp create --id "+p.cfg.ClientID)}, nil
	}
	if ie.Code == 0 {
		msg := "the client-credentials probe failed"
		switch {
		case ie.Err != nil:
			msg += ": " + ie.Err.Error()
		case ie.Status != 0:
			msg += fmt.Sprintf(": HTTP %d %s", ie.Status, ie.OAuth)
		}
		return []doctor.Result{result(name, doctor.Fail, msg, reachFix)}, nil
	}
	fix := ie.OperatorHint
	if d.FederatedTokenSetting != "" && (ie.Code == codeInvalidSecret || ie.Code == codeExpiredSecret) {
		fix = "" // those hints are about a secret, and there is none
	}
	switch {
	case fix != "":
	case d.FederatedTokenSetting != "":
		// Microsoft's error reference lists no code for a federated credential that does not match,
		// so the fix says what must match.
		fix = fmt.Sprintf("the token in the file named by %s must match one of the app's federated identity credentials exactly: issuer, subject and audience (az ad app federated-credential list --id %s), and must not have expired; look up %s in https://learn.microsoft.com/entra/identity-platform/reference-error-codes",
			d.FederatedTokenSetting, p.cfg.ClientID, code)
	default:
		fix = "look up " + code + " in Microsoft's error code reference: https://learn.microsoft.com/entra/identity-platform/reference-error-codes"
	}
	return []doctor.Result{result(name, doctor.Fail, "the client-credentials probe failed ("+code+")", fix)}, nil
}

// diagnoseToken checks the probe's token as the proxy checks its login tokens: signed by the
// tenant, issuer, v2, audience = the client ID; and the idtyp claim app-only callers need (ADR-0022).
func (p *Provider) diagnoseToken(ctx context.Context, raw string) []doctor.Result {
	const name = "entra access token"
	claims, err := idp.VerifySignature(ctx, raw, p.keys, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return []doctor.Result{result(name, doctor.Fail, "the probe's token does not verify with the tenant's keys: "+err.Error(), reachFix)}
	}
	if v := idp.StringClaim(claims, "ver"); v != "2.0" {
		return []doctor.Result{result(name, doctor.Fail, fmt.Sprintf("Entra issues version %q tokens for the app, the proxy accepts only 2.0", v), accessTokenVersionFix)}
	}
	if _, err := idp.VerifyJWT(ctx, raw, p.keys, p.rules("")); err != nil {
		return []doctor.Result{result(name, doctor.Fail, "the probe's token fails the proxy's checks: "+err.Error(), accessTokenVersionFix)}
	}
	out := []doctor.Result{result(name, doctor.Pass, "v2 token for audience "+p.cfg.ClientID+", issuer "+idp.StringClaim(claims, "iss"), "")}
	if idp.StringClaim(claims, "idtyp") == "app" {
		return append(out, result("entra idtyp claim", doctor.Pass, "app-only tokens carry idtyp=app", ""))
	}
	return append(out, result("entra idtyp claim", doctor.Warn, "app-only tokens carry no idtyp=app, so app-only callers (ADR-0022) would be refused",
		"add the idtyp optional claim to access tokens on the app registration (byward init entra prints the request)"))
}

// manualChecks are the app registration properties only Microsoft Graph can read.
func (p *Provider) manualChecks(d Diagnosis) []doctor.Result {
	noGraph := "byward does not call Microsoft Graph (ADR-0012 §8), so it cannot read this"
	out := []doctor.Result{result("entra redirect URI", doctor.Skip,
		noGraph+"; a wrong redirect URI fails the first sign-in with AADSTS50011",
		fmt.Sprintf("check by hand: az ad app show --id %s --query web.redirectUris must list %s", p.cfg.ClientID, p.cfg.RedirectURL))}
	roles := fmt.Sprintf(`check by hand: az ad app show --id %s --query "appRoles[].{value:value, members:allowedMemberTypes}"`, p.cfg.ClientID)
	if len(d.GateRoles) > 0 {
		roles += " must include " + strings.Join(d.GateRoles, ", ")
	}
	return append(out, result("entra app roles", doctor.Skip, noGraph, roles))
}
