package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/token"
)

// grantTypes are the grant types /token serves (registration owns the list); metadata and errors
// list them from here.
var grantTypes = registration.GrantTypes()

// cannotIssue answers a store or sealing failure after the client authenticated: the code or refresh
// token may still be good, so it is not the client's fault.
var cannotIssue = tokenError{http.StatusInternalServerError, "server_error", "the proxy could not issue a token"}

// tokenError is an RFC 6749 §5.2 error. Descriptions are fixed strings plus the request ID, never
// IdP or store text (ADR-0013 §4, ADR-0021 §2).
type tokenError struct {
	status int
	code   string
	desc   string
}

func (b *Broker) token(w http.ResponseWriter, r *http.Request) {
	if !allowPost(w, r) {
		return
	}
	if retry, limited := b.throttled(w, r, ratelimit.Token); limited {
		// RFC 6749 §5.2 has no rate-limit code; the 429 and Retry-After carry the meaning (as in babs).
		writeTokenError(w, r, tokenError{http.StatusTooManyRequests, "temporarily_unavailable",
			"too many requests from this address; retry after " + strconv.Itoa(retry) + " s"})
		return
	}
	if err := r.ParseForm(); err != nil {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "the request body is not a valid form"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		b.redeemCode(w, r)
	case "refresh_token":
		b.refresh(w, r)
	case "":
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "grant_type is required"})
	default:
		// client_credentials and jwt-bearer are not offered (ADR-0022 §9).
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "unsupported_grant_type", "supported: " + strings.Join(grantTypes, ", ")})
	}
}

// authenticateClient finds and authenticates the calling client (ADR-0008 §6), for /token and
// /revoke. On failure it has already answered: 401 invalid_client, or 503 temporarily_unavailable
// when a client's metadata or keys could not be fetched for now (draft -03 §6.1) or the proxy's
// store could not read a DCR registration.
//
// onRefused, when set, runs before the 401 with the lookup error if the client was definitely
// refused: its metadata document (registration.ErrMetadataRefused; never for a transient failure,
// a disabled CIMD or a host off the allowlist) or its client ID on the operator's denylist
// (registration.ErrClientDenied). Refresh uses it to revoke what the refused client holds.
func (b *Broker) authenticateClient(w http.ResponseWriter, r *http.Request, now time.Time, onRefused func(r *http.Request, clientID string, now time.Time, refusal error)) (registration.Client, bool) {
	ctx := r.Context()
	f := r.PostForm
	clientID := f.Get("client_id")
	if user, _, ok := r.BasicAuth(); ok {
		// RFC 6749 §2.3.1: the Basic user is form-encoded, as registration compares it.
		u, err := url.QueryUnescape(user)
		if err != nil {
			b.tokenFail(w, r, tokenError{http.StatusUnauthorized, "invalid_client", "client authentication failed"})
			return nil, false
		}
		clientID = u
	}
	if clientID == "" && f.Get("client_assertion") != "" {
		// RFC 7523 §3: with an assertion, client_id is optional and the assertion's sub names the
		// client. It is only used to find the client; Authenticate verifies the assertion.
		clientID = assertionSubject(f.Get("client_assertion"))
	}
	client, err := b.cfg.Clients.Client(ctx, clientID)
	if err != nil {
		if errors.Is(err, registration.ErrStoreUnavailable) { // a DCR registration could not be read: the store, not the client
			b.unavailable(w, r, "loading a client registration failed", err)
			return nil, false
		}
		b.clientLookupFailed(ctx, clientID, nil, err)
		if errors.Is(err, registration.ErrUnavailable) { // draft -03 §6.1: 503 for a transient failure
			w.Header().Set("Retry-After", cimdRetryAfter)
			b.tokenFail(w, r, tokenError{http.StatusServiceUnavailable, "temporarily_unavailable", "the client's metadata could not be fetched"})
			return nil, false
		}
		if onRefused != nil && (errors.Is(err, registration.ErrClientDenied) || errors.Is(err, registration.ErrMetadataRefused)) {
			onRefused(r, clientID, now, err)
		}
		b.tokenFail(w, r, tokenError{http.StatusUnauthorized, "invalid_client", "unknown client"})
		return nil, false
	}
	if err := client.Authenticate(ctx, f, r.Header, b.tokenEndpoint(), now); err != nil {
		if errors.Is(err, registration.ErrReplayCheckUnavailable) { // the store, not the client, failed
			b.unavailable(w, r, "client assertion replay check failed", err)
			return nil, false
		}
		if errors.Is(err, registration.ErrUnavailable) { // the client's jwks_uri could not be fetched for now
			b.clientLookupFailed(ctx, clientID, client, err)
			w.Header().Set("Retry-After", cimdRetryAfter)
			b.tokenFail(w, r, tokenError{http.StatusServiceUnavailable, "temporarily_unavailable", "the client's keys could not be fetched"})
			return nil, false
		}
		if errors.Is(err, registration.ErrKeysRefused) { // the client's jwks_uri is unusable, not its assertion
			b.clientLookupFailed(ctx, clientID, client, err)
		}
		b.tokenFail(w, r, tokenError{http.StatusUnauthorized, "invalid_client", "client authentication failed"})
		return nil, false
	}
	return client, true
}

// redeemCode applies ADR-0008 §6: client ID, exact redirect URI, S256 verifier and client
// authentication are all re-checked; a code is used once, and a reused code revokes its grant.
func (b *Broker) redeemCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := r.PostForm
	now := b.cfg.Now()
	client, ok := b.authenticateClient(w, r, now, nil)
	if !ok {
		return
	}
	if desc, foreign := b.foreignResource(f.Get("resource")); foreign {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_target", desc})
		return
	}
	claims, err := b.cfg.Sealer.Open(token.Code, f.Get("code"))
	if err != nil || !now.Before(claims.ExpiresAt) {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired"})
		return
	}
	pc, err := b.cfg.Store.ConsumeCode(ctx, claims.GrantID, now)
	switch {
	case errors.Is(err, store.ErrConsumed):
		// ADR-0006 §5: a reused code revokes the tokens it produced.
		b.revoke(r, client.ID(), claims.GrantID, now, "authorization code reused; grant revoked")
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the authorization code was already used"})
		return
	case errors.Is(err, store.ErrNotFound):
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired"})
		return
	case err != nil:
		// An outage is not the client's fault: the code may still be good.
		b.cfg.Log.ErrorContext(ctx, "redeeming an authorization code failed", "error", err)
		b.tokenFail(w, r, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not redeem the code; try again"})
		return
	}
	// The operator denied the app (ADR-0008 §9, #338) after the user signed in: end the grant as a
	// refresh does, with the denylist's reason, rather than as a misused code. Only the code's own
	// client: another client's code is a wrong binding below.
	if d, ok := client.(redirectDenier); ok && pc.ClientID == client.ID() && d.Denied() {
		b.revoke(r, client.ID(), claims.GrantID, now, reasonClientDenied)
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired"})
		return
	}
	// The code is used up now: any binding failure below means it is being misused, so the grant
	// it stands for is revoked, as for a reused code (RFC 9700 §4.5).
	redirect := f.Get("redirect_uri")
	var mismatch string
	switch {
	case pc.ClientID != client.ID():
		mismatch = "the code was issued to another client"
	case redirect != pc.RedirectURI || client.RedirectAllowed(redirect) != nil:
		mismatch = "redirect_uri does not match the authorization request"
	case !pkceMatches(f.Get("code_verifier"), pc.CodeChallenge):
		mismatch = "code_verifier does not match the code challenge"
	}
	if mismatch != "" {
		b.revoke(r, client.ID(), claims.GrantID, now, "authorization code redeemed with the wrong binding; grant revoked")
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", mismatch})
		return
	}
	// The grant was created short-lived at the callback, so an abandoned login expires soon; now
	// that the code is redeemed it lives as long as its tokens can (ADR-0006 §5).
	// A refresh token needs offline_access in the grant (grantScopes: a client that registered the
	// refresh_token grant, and an IdP refresh token) and a client that still allows refresh.
	offline := slices.Contains(pc.Scopes, offlineAccess) && client.AllowsRefresh()
	expires := now.Add(AccessLifetime)
	if offline {
		expires = now.Add(GrantLifetime)
	}
	if err := b.cfg.Store.UpdateGrant(ctx, claims.GrantID, expires); err != nil {
		b.cfg.Log.ErrorContext(ctx, "extending a grant failed", "error", err)
		b.tokenFail(w, r, cannotIssue)
		return
	}
	var refresh string
	if offline {
		var hash [sha256.Size]byte
		refresh, hash = token.NewRefreshToken()
		if err := b.cfg.Store.PutRefreshToken(ctx, store.RefreshToken{Hash: hash, GrantID: claims.GrantID, ClientID: client.ID(),
			CreatedAt: now, IdleExpiresAt: minTime(now.Add(RefreshIdleLifetime), expires)}); err != nil {
			b.cfg.Log.ErrorContext(ctx, "storing a refresh token failed", "error", err)
			b.tokenFail(w, r, cannotIssue)
			return
		}
	}
	scopes := pc.Scopes
	if !offline { // the response reports the scope actually granted (RFC 6749 §5.1)
		scopes = withoutOffline(scopes)
	}
	asserted, idpExpiry, err := b.grantClaims(ctx, claims.GrantID)
	if err != nil {
		b.cfg.Log.ErrorContext(ctx, "reading a grant's identity claims failed", "error", err)
		b.tokenFail(w, r, cannotIssue)
		return
	}
	b.recordUse(ctx, client, now)
	b.issue(w, r, client.ID(), claims.GrantID, claims.Subject, asserted, idpExpiry, now, expires, scopes, refresh)
}

// grantClaims are the identity claims kept with a grant at sign-in, for its first access token,
// and the expiry of the IdP access token kept with them (zero if unknown).
func (b *Broker) grantClaims(ctx context.Context, grantID string) (assertedClaims, time.Time, error) {
	g, err := b.cfg.Store.Grant(ctx, grantID)
	if err != nil {
		return assertedClaims{}, time.Time{}, err
	}
	if len(g.IdPTokens) == 0 {
		return assertedClaims{}, time.Time{}, nil
	}
	s, err := b.openSecrets(g.IdPTokens)
	return s.Claims, s.Tokens.Expiry, err
}

// issue seals an access token (capped at the grant's expiry and, with CapAccessToIdPToken, at the
// IdP access token's) carrying the client and the asserted identity claims, and writes the token
// response.
func (b *Broker) issue(w http.ResponseWriter, r *http.Request, clientID, grantID, subject string, asserted assertedClaims, idpExpiry, now, grantExpires time.Time, scopes []string, refresh string) {
	ctx := r.Context()
	exp := minTime(now.Add(AccessLifetime), grantExpires)
	if b.cfg.CapAccessToIdPToken && !idpExpiry.IsZero() {
		// On-Behalf-Of presents the stored IdP token; an access token that outlived it would reach
		// the upstream without a downstream token (ADR-0017 amendment 2026-11-07).
		// An IdP token that ends within the margin plus MinCappedLifetime is not a cap: the code or refresh token is
		// already spent, so failing here would strand the client; On-Behalf-Of refuses instead.
		if capped := idpExpiry.Add(-IdPTokenMargin); !capped.Before(now.Add(MinCappedLifetime)) {
			exp = minTime(exp, capped)
		} else {
			b.cfg.Log.WarnContext(ctx, "the IdP access token expires too soon to cap the access token to it (within the margin plus the shortest capped lifetime)", "idp_token_expires_in", idpExpiry.Sub(now).String(), "margin", IdPTokenMargin.String())
		}
	}
	c := token.Claims{GrantID: grantID, Subject: subject, IssuedAt: now, ExpiresAt: exp, ClientID: clientID, Claims: resource.Claims(asserted)}
	access, err := b.cfg.Sealer.Seal(token.Access, c)
	if errors.Is(err, token.ErrTooLong) && len(c.Groups) > 0 {
		// Too many groups for a token: assert none rather than fail the sign-in; the upstream then
		// sees no groups claim, as with Entra's groups overage.
		b.cfg.Log.WarnContext(ctx, "the user's groups do not fit in an access token; the assertion carries no groups", "groups", len(c.Groups), "setting", "BYWARD_ASSERTION_CLAIMS")
		c.Groups = nil
		access, err = b.cfg.Sealer.Seal(token.Access, c)
	}
	if err != nil {
		b.cfg.Log.ErrorContext(ctx, "sealing an access token failed", "error", err)
		b.tokenFail(w, r, cannotIssue)
		return
	}
	b.cfg.Audit.Record(r, audit.Event{Name: audit.TokenIssued, Outcome: audit.Success, ClientID: clientID, UserKey: subject, GrantID: grantID})
	body := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(exp.Sub(now).Seconds()),
		"scope":        strings.Join(scopes, " "),
	}
	if refresh != "" {
		body["refresh_token"] = refresh
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// assertionSubject returns the unverified sub claim of a JWT client assertion, or "".
func assertionSubject(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 || len(parts[1]) > 8<<10 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.Sub
}

// revoke ends a grant (store and deny list) and logs why, on one line with attrs. A store failure is
// logged: the deny list still ends the grant's access tokens on this replica.
func (b *Broker) revoke(r *http.Request, clientID, grantID string, now time.Time, why string, attrs ...any) {
	ctx := r.Context()
	if err := b.cfg.Store.RevokeGrant(ctx, grantID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		b.cfg.Log.ErrorContext(ctx, "revoking a grant failed", "error", err)
	}
	b.revoked(r, clientID, grantID, why)
	b.cfg.Log.WarnContext(ctx, why, attrs...)
}

// revoked is the end of every grant revocation, once the store has revoked the grant (or failed to,
// by the caller's policy): the deny list stops its access tokens now, and the audit stream records why.
func (b *Broker) revoked(r *http.Request, clientID, grantID, why string) {
	b.deny.Add(grantID)
	b.cfg.Audit.Record(r, audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: why, ClientID: clientID, GrantID: grantID})
}

// pkceMatches checks S256 (RFC 7636 §4.6) in constant time; verifiers are 43–128 characters.
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || challenge == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(idp.CodeChallenge(verifier)), []byte(challenge)) == 1
}

// allowPost applies the preamble of the POST endpoints (/token, /revoke, /register): the discovery
// CORS policy, 204 to a preflight, 405 to any method but POST. It reports whether to go on.
func allowPost(w http.ResponseWriter, r *http.Request) bool {
	resource.DiscoveryCORS(w, r, "POST, OPTIONS")
	switch r.Method {
	case http.MethodPost:
		return true
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, "POST, OPTIONS")
	}
	return false
}

// foreignResource reports whether res, an RFC 8707 resource parameter, names another resource
// than ours, with the invalid_target description to send. A missing resource means ours (ADR-0005 §4).
func (b *Broker) foreignResource(res string) (desc string, foreign bool) {
	if res == "" || res == b.cfg.Resource.String() {
		return "", false
	}
	return "this server only issues tokens for " + b.cfg.Resource.String(), true
}

func (b *Broker) tokenFail(w http.ResponseWriter, r *http.Request, e tokenError) {
	// The caller may not have authenticated, so the event is rate-limited per source.
	b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.TokenRejected, Outcome: audit.Failure, Reason: e.code})
	writeTokenError(w, r, e)
}

// writeTokenError writes an OAuth error response (RFC 6749 §5.2) with the request ID as reference.
func writeTokenError(w http.ResponseWriter, r *http.Request, e tokenError) {
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.code,
		"error_description": e.desc + " (reference " + logging.RequestID(r.Context()) + ")"})
}

// Retry-After for store and admission 503s from /token and /revoke (ADR-0007 §7); a CIMD client whose
// metadata cannot be fetched gets 60 s instead (authenticateClient).
const retryAfter = "5"

// cimdRetryAfter is the Retry-After for a CIMD client whose metadata or keys could not be fetched
// for now: about one per-URL retry gap and cache minimum (docs/how-to/cimd.md).
const cimdRetryAfter = "60"

// unavailable answers 503 with Retry-After for a store failure (ADR-0007 §7); the refresh token is
// not spent.
func (b *Broker) unavailable(w http.ResponseWriter, r *http.Request, what string, err error) {
	ctx := r.Context()
	b.cfg.Log.ErrorContext(ctx, what, "error", err)
	w.Header().Set("Retry-After", retryAfter)
	b.tokenFail(w, r, tokenError{http.StatusServiceUnavailable, "temporarily_unavailable", "the proxy's store is unavailable; try again"})
}

// useRecorder is a client whose registration slides with use (a DCR client).
type useRecorder interface {
	RecordUse(ctx context.Context, now time.Time) error
}

// recordUse renews a DCR client's registration after a code redemption or a refresh; a failure is
// logged, never a reason to fail the token request.
func (b *Broker) recordUse(ctx context.Context, client registration.Client, now time.Time) {
	if u, ok := client.(useRecorder); ok {
		if err := u.RecordUse(ctx, now); err != nil {
			b.cfg.Log.WarnContext(ctx, "renewing a client registration failed", "client_id", client.ID(), "error", err.Error())
		}
	}
}
