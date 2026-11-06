package broker

import (
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

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/ratelimit"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/token"
)

// grantTypes are the grant types /token serves; metadata and errors list them from here.
var grantTypes = []string{"authorization_code", "refresh_token"}

// tokenError is an RFC 6749 §5.2 error. Descriptions are fixed strings plus the request ID, never
// IdP or store text (ADR-0013 §4, ADR-0021 §2).
type tokenError struct {
	status int
	code   string
	desc   string
}

func (b *Broker) token(w http.ResponseWriter, r *http.Request) {
	cors(w, r, "POST, OPTIONS")
	switch r.Method {
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
// /revoke. On failure it has already answered with 401 invalid_client.
func (b *Broker) authenticateClient(w http.ResponseWriter, r *http.Request, now time.Time) (registration.Client, bool) {
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
		b.tokenFail(w, r, tokenError{http.StatusUnauthorized, "invalid_client", "unknown client"})
		return nil, false
	}
	if err := client.Authenticate(ctx, f, r.Header, b.tokenEndpoint(), now); err != nil {
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
	client, ok := b.authenticateClient(w, r, now)
	if !ok {
		return
	}
	if res := f.Get("resource"); res != "" && res != b.cfg.Resource.String() {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_target", "this server only issues tokens for " + b.cfg.Resource.String()})
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
		b.cfg.Log.ErrorContext(ctx, "redeeming an authorization code failed", "request_id", logging.RequestID(ctx), "error", err)
		b.tokenFail(w, r, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not redeem the code; try again"})
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
	offline := slices.Contains(pc.Scopes, "offline_access")
	expires := now.Add(AccessLifetime)
	if offline {
		expires = now.Add(GrantLifetime)
	}
	if err := b.cfg.Store.UpdateGrant(ctx, claims.GrantID, expires); err != nil {
		b.cfg.Log.ErrorContext(ctx, "extending a grant failed", "request_id", logging.RequestID(ctx), "error", err)
		b.tokenFail(w, r, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not issue a token"})
		return
	}
	var refresh string
	if offline {
		var hash [sha256.Size]byte
		refresh, hash = token.NewRefreshToken()
		if err := b.cfg.Store.PutRefreshToken(ctx, store.RefreshToken{Hash: hash, GrantID: claims.GrantID, ClientID: client.ID(),
			CreatedAt: now, IdleExpiresAt: minTime(now.Add(RefreshIdleLifetime), expires)}); err != nil {
			b.cfg.Log.ErrorContext(ctx, "storing a refresh token failed", "request_id", logging.RequestID(ctx), "error", err)
			b.tokenFail(w, r, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not issue a token"})
			return
		}
	}
	b.issue(w, r, client.ID(), claims.GrantID, claims.Subject, now, expires, pc.Scopes, refresh)
}

// issue seals an access token (capped at the grant's expiry) and writes the token response.
func (b *Broker) issue(w http.ResponseWriter, r *http.Request, clientID, grantID, subject string, now, grantExpires time.Time, scopes []string, refresh string) {
	ctx := r.Context()
	exp := minTime(now.Add(AccessLifetime), grantExpires)
	access, err := b.cfg.Sealer.Seal(token.Access, token.Claims{GrantID: grantID, Subject: subject, IssuedAt: now, ExpiresAt: exp})
	if err != nil {
		b.cfg.Log.ErrorContext(ctx, "sealing an access token failed", "request_id", logging.RequestID(ctx), "error", err)
		b.tokenFail(w, r, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not issue a token"})
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

// revoke ends a grant (store and deny list) and logs why.
func (b *Broker) revoke(r *http.Request, clientID, grantID string, now time.Time, why string) {
	ctx := r.Context()
	if err := b.cfg.Store.RevokeGrant(ctx, grantID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		b.cfg.Log.ErrorContext(ctx, "revoking a grant failed", "request_id", logging.RequestID(ctx), "error", err)
	}
	b.deny.Add(grantID)
	b.cfg.Log.WarnContext(ctx, why, "request_id", logging.RequestID(ctx))
	b.cfg.Audit.Record(r, audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: why, ClientID: clientID, GrantID: grantID})
}

// pkceMatches checks S256 (RFC 7636 §4.6) in constant time; verifiers are 43–128 characters.
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
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

// Retry-After for 503s from /token and /revoke (ADR-0007 §7).
const retryAfter = "5"

// unavailable answers 503 with Retry-After for a store failure (ADR-0007 §7); the refresh token is
// not spent.
func (b *Broker) unavailable(w http.ResponseWriter, r *http.Request, what string, err error) {
	ctx := r.Context()
	b.cfg.Log.ErrorContext(ctx, what, "request_id", logging.RequestID(ctx), "error", err)
	w.Header().Set("Retry-After", retryAfter)
	b.tokenFail(w, r, tokenError{http.StatusServiceUnavailable, "temporarily_unavailable", "the proxy's store is unavailable; try again"})
}
