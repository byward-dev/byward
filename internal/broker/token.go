package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/token"
)

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
	if err := r.ParseForm(); err != nil {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "the request body is not a valid form"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		b.redeemCode(w, r)
	case "":
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "grant_type is required"})
	default:
		// refresh_token arrives with slice 1.6; client_credentials and jwt-bearer are not offered
		// (ADR-0022 §9).
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported"})
	}
}

// redeemCode applies ADR-0008 §6: client ID, exact redirect URI, S256 verifier and client
// authentication are all re-checked; a code is used once, and a reused code revokes its grant.
func (b *Broker) redeemCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := r.PostForm
	clientID := f.Get("client_id")
	if user, _, ok := r.BasicAuth(); ok {
		clientID = user
	}
	client, err := b.cfg.Clients.Client(ctx, clientID)
	if err != nil {
		b.tokenFail(w, r, tokenError{http.StatusUnauthorized, "invalid_client", "unknown client"})
		return
	}
	now := b.cfg.Now()
	if err := client.Authenticate(ctx, f, r.Header, b.tokenEndpoint(), now); err != nil {
		b.tokenFail(w, r, tokenError{http.StatusUnauthorized, "invalid_client", "client authentication failed"})
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
		if rerr := b.cfg.Store.RevokeGrant(ctx, claims.GrantID, now); rerr != nil && !errors.Is(rerr, store.ErrNotFound) {
			b.cfg.Log.ErrorContext(ctx, "revoking a grant after code reuse failed", "request_id", logging.RequestID(ctx), "error", rerr)
		}
		b.deny.add(claims.GrantID)
		b.cfg.Log.WarnContext(ctx, "authorization code reused; grant revoked", "request_id", logging.RequestID(ctx))
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the authorization code was already used"})
		return
	case err != nil:
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired"})
		return
	}
	redirect := f.Get("redirect_uri")
	switch {
	case pc.ClientID != client.ID():
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the code was issued to another client"})
		return
	case redirect != pc.RedirectURI || client.RedirectAllowed(redirect) != nil:
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request"})
		return
	case !pkceMatches(f.Get("code_verifier"), pc.CodeChallenge):
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code challenge"})
		return
	}
	access, err := b.cfg.Sealer.Seal(token.Access, token.Claims{GrantID: claims.GrantID, Subject: claims.Subject, IssuedAt: now, ExpiresAt: now.Add(AccessLifetime)})
	if err != nil {
		b.cfg.Log.ErrorContext(ctx, "sealing an access token failed", "request_id", logging.RequestID(ctx), "error", err)
		b.tokenFail(w, r, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not issue a token"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(AccessLifetime.Seconds()),
		"scope":        strings.Join(pc.Scopes, " "),
	})
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
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.code,
		"error_description": e.desc + " (reference " + logging.RequestID(r.Context()) + ")"})
}
