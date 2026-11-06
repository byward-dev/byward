package fakeidp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Failure is an error the fake returns. For Entra, Code is the AADSTS number; it appears in
// error_codes and as the "AADSTSnnn:" prefix of error_description. The generic profile ignores
// Code and returns a plain RFC 6749 error.
//
// Entra documents the AADSTS descriptions but not which `error` value each code comes with. The
// values below follow the real-tenant runtime tests (2026-11-05 and 2026-11-06) where one was
// observed — 65001, 9002313 (bad code) and 501051 → invalid_grant; 7000215, 5002723 and 700027 →
// 401 invalid_client — and are otherwise the closest RFC 6749 value.
type Failure struct {
	// Status is the HTTP status of a token-endpoint error; 0 means 400.
	Status      int
	Error       string
	Code        int
	Description string
	// Claims is the Conditional Access claims challenge (interaction_required).
	Claims string
}

// Failures used by the fake itself, also for injection with FailAuthorize and FailToken. Treat
// them as read-only: the fake and FailAuthorize/FailToken copy them, but a write changes them for
// every later test.
var (
	ConsentRequired = Failure{Error: "invalid_grant", Code: 65001,
		Description: "The user or administrator hasn't consented to use the application. Send an interactive authorization request for this user and resource."}
	InteractionRequired = Failure{Error: "interaction_required", Code: 50079,
		Description: "Due to a configuration change made by your administrator, or because you moved to a new location, you must enroll in multifactor authentication.",
		Claims:      `{"access_token":{"polids":{"essential":true,"values":["00000000-0000-0000-0000-000000000001"]}}}`}
	MFARequired = Failure{Error: "invalid_grant", Code: 50076,
		Description: "Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access the resource."}
	RefreshTokenExpired = Failure{Error: "invalid_grant", Code: 700082,
		Description: "The refresh token has expired due to inactivity."}
	RefreshTokenRevoked = Failure{Error: "invalid_grant", Code: 50173,
		Description: "The provided grant has expired due to it being revoked, a fresh auth token is needed."}
	InvalidRefreshToken = Failure{Error: "invalid_grant", Code: 70000,
		Description: "Authentication failed. The refresh token isn't valid."}
	CodeRedeemed = Failure{Error: "invalid_grant", Code: 54005,
		Description: "OAuth2 Authorization code was already redeemed, please retry with a new valid code or use an existing refresh token."}
	CodeExpired = Failure{Error: "invalid_grant", Code: 70008,
		Description: "The provided authorization code or refresh token has expired due to inactivity."}
	InvalidCode = Failure{Error: "invalid_grant", Code: 9002313,
		Description: "Invalid request. Request is malformed or invalid."}
	PKCEMismatch = Failure{Error: "invalid_grant", Code: 501481,
		Description: "The Code_Verifier doesn't match the code_challenge supplied in the authorization request."}
	RedirectMismatch = Failure{Error: "invalid_request", Code: 50011,
		Description: "The redirect URI specified in the request does not match the redirect URIs configured for the application."}
	InvalidScope = Failure{Error: "invalid_scope", Code: 70011,
		Description: "The provided value for the input parameter 'scope' is not valid."}
	InvalidRequest = Failure{Error: "invalid_request", Code: 9002313,
		Description: "Invalid request. Request is malformed or invalid."}
	UnknownClient = Failure{Error: "unauthorized_client", Code: 700016,
		Description: "Application was not found in the directory."}
	InvalidClientSecret = Failure{Status: http.StatusUnauthorized, Error: "invalid_client", Code: 7000215,
		Description: "Invalid client secret provided."}
	ExpiredClientSecret = Failure{Status: http.StatusUnauthorized, Error: "invalid_client", Code: 7000222,
		Description: "The provided client secret keys are expired."}
	MissingClientCredential = Failure{Status: http.StatusUnauthorized, Error: "invalid_client", Code: 7000218,
		Description: "The request body must contain the following parameter: 'client_assertion' or 'client_secret'."}
	MissingThumbprint = Failure{Status: http.StatusUnauthorized, Error: "invalid_client", Code: 5002723,
		Description: "Invalid JWT token. No certificate SHA-1 thumbprint, certificate SHA-256 thumbprint, nor keyId specified in token header."}
	InvalidClientAssertion = Failure{Status: http.StatusUnauthorized, Error: "invalid_client", Code: 700027,
		Description: "Client assertion failed signature validation."}
	InvalidAssertion = Failure{Error: "invalid_grant", Code: 50013,
		Description: "Assertion failed signature validation."}
	AppNotAssigned = Failure{Error: "invalid_grant", Code: 501051,
		Description: "Application is not assigned to a role for the application."}
	// ResourceNotFound's error value is the one public reports of AADSTS500011 show; not observed
	// in this project's real-tenant tests.
	ResourceNotFound = Failure{Error: "invalid_resource", Code: 500011,
		Description: "The resource principal was not found in the tenant."}
	UnsupportedGrantType = Failure{Error: "unsupported_grant_type", Code: 70003,
		Description: "The app returned an unsupported grant type."}
	UserNotAssigned = Failure{Error: "access_denied", Code: 50105,
		Description: "The signed in user isn't assigned to a role for the signed in app."}
	UserFromOtherTenant = Failure{Error: "access_denied", Code: 50020,
		Description: "User account from identity provider does not exist in tenant and cannot access the application."}
	BlockedByConditionalAccess = Failure{Error: "access_denied", Code: 53003,
		Description: "Access has been blocked by Conditional Access policies."}
	TemporarilyUnavailable = Failure{Status: http.StatusServiceUnavailable, Error: "temporarily_unavailable",
		Description: "The service is temporarily unavailable."}
)

// failure returns a copy of f, so callers may adjust it without touching the shared value.
func failure(f Failure) *Failure { return &f }

func (p *IdP) description(f Failure, trace, corr, ts string) string {
	if p.profile != Entra {
		return f.Description
	}
	d := f.Description
	if f.Code != 0 {
		d = fmt.Sprintf("AADSTS%d: %s", f.Code, d)
	}
	return fmt.Sprintf("%s\r\nTrace ID: %s\r\nCorrelation ID: %s\r\nTimestamp: %s", d, trace, corr, ts)
}

// correlation returns the trace and correlation IDs of an Entra request. As observed in the
// real-tenant runtime test (2026-11-06), a client-request-id GUID comes back both as the
// client-request-id response header and as correlation_id, and x-ms-request-id equals trace_id.
func (p *IdP) correlation(w http.ResponseWriter, r *http.Request) (trace, corr string) {
	if p.profile != Entra {
		return "", ""
	}
	trace, corr = NewGUID(), NewGUID()
	if id := r.Header.Get("client-request-id"); isGUID(id) {
		corr = id
		w.Header().Set("client-request-id", id)
	}
	w.Header().Set("x-ms-request-id", trace)
	return trace, corr
}

// tokenError writes a token-endpoint error. Caller holds p.mu.
func (p *IdP) tokenError(w http.ResponseWriter, r *http.Request, f Failure) {
	status := f.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	body := map[string]any{"error": f.Error}
	if p.profile == Entra {
		trace, corr := p.correlation(w, r)
		ts := p.cfg.clock().UTC().Format("2006-01-02 15:04:05Z")
		body["error_description"] = p.description(f, trace, corr, ts)
		codes := []int{}
		if f.Code != 0 {
			codes = append(codes, f.Code)
			body["error_uri"] = fmt.Sprintf("%s/error?code=%d", p.cfg.authority, f.Code)
		}
		body["error_codes"] = codes
		body["timestamp"] = ts
		body["trace_id"] = trace
		body["correlation_id"] = corr
		if f.Claims != "" {
			body["claims"] = f.Claims
		}
	} else if f.Description != "" {
		body["error_description"] = f.Description
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	writeJSON(w, status, body)
}

// authorizeError redirects back to the client with an error (only once the redirect URI is
// trusted). Caller holds p.mu.
func (p *IdP) authorizeError(w http.ResponseWriter, r *http.Request, redirect, state string, f Failure) {
	trace, corr := p.correlation(w, r)
	ts := p.cfg.clock().UTC().Format("2006-01-02 15:04:05Z")
	q := url.Values{"error": {f.Error}}
	if d := p.description(f, trace, corr, ts); d != "" {
		q.Set("error_description", d)
	}
	if state != "" {
		q.Set("state", state)
	}
	if p.cfg.issParam {
		q.Set("iss", p.issuerFor(p.cfg.user.TenantID))
	}
	http.Redirect(w, r, withQuery(redirect, q), http.StatusFound) //nolint:gosec // G710: callers pass only an exact-match registered URI
}

// errorPage is what the IdP shows when it cannot trust the redirect URI: no redirect at all.
func (p *IdP) errorPage(w http.ResponseWriter, r *http.Request, f Failure) {
	trace, corr := p.correlation(w, r)
	ts := p.cfg.clock().UTC().Format("2006-01-02 15:04:05Z")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, "%s: %s\n", f.Error, p.description(f, trace, corr, ts))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withQuery(base string, q url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	merged := u.Query()
	for k, v := range q {
		merged[k] = v
	}
	u.RawQuery = merged.Encode()
	return u.String()
}
