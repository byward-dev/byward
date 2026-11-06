package broker

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/token"
)

// revokeEndpoint is RFC 7009 token revocation (ADR-0006 §7). Revoking either token revokes the
// grant. Unknown, malformed or already revoked tokens get 200 (RFC 7009 §2.2); a token issued to
// another client is refused (§2.1) and its grant left alone; a store failure is 503 with
// Retry-After, never a false 200. The IdP's tokens are deleted with the grant; revoking them at
// the IdP is not possible (no adapter has a revocation endpoint), so they simply expire there.
func (b *Broker) revokeEndpoint(w http.ResponseWriter, r *http.Request) {
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
	if retry, limited := b.throttled(w, r, ratelimit.Revoke); limited {
		writeTokenError(w, r, tokenError{http.StatusTooManyRequests, "temporarily_unavailable",
			"too many requests from this address; retry after " + strconv.Itoa(retry) + " s"})
		return
	}
	if err := r.ParseForm(); err != nil {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "the request body is not a valid form"})
		return
	}
	now := b.cfg.Now()
	client, ok := b.authenticateClient(w, r, now, nil)
	if !ok {
		return
	}
	tok := r.PostForm.Get("token")
	if tok == "" {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "token is required"})
		return
	}
	ctx := r.Context()
	var grantID, owner string
	switch {
	case strings.HasPrefix(tok, token.RefreshPrefix):
		hash, ok := token.HashRefreshToken(tok)
		if !ok {
			break
		}
		rt, err := b.cfg.Store.RefreshToken(ctx, hash, now)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			b.unavailable(w, r, "looking up a token to revoke failed", err)
			return
		default:
			grantID, owner = rt.GrantID, rt.ClientID
		}
	case strings.HasPrefix(tok, token.AccessPrefix):
		// An expired access token still names its grant; revoking it ends the grant's refresh
		// tokens, which is what a client revoking "its tokens" wants.
		claims, err := b.cfg.Sealer.Open(token.Access, tok)
		if err != nil {
			break
		}
		g, err := b.cfg.Store.Grant(ctx, claims.GrantID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			b.unavailable(w, r, "looking up a token to revoke failed", err)
			return
		default:
			grantID, owner = g.ID, g.ClientID
		}
	}
	if grantID != "" {
		if owner != client.ID() {
			b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the token was issued to another client"})
			return
		}
		if err := b.cfg.Store.RevokeGrant(ctx, grantID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			b.unavailable(w, r, "revoking a grant failed", err)
			return
		}
		b.deny.Add(grantID)
		b.cfg.Audit.Record(r, audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: "the client revoked a token (RFC 7009)", ClientID: client.ID(), GrantID: grantID})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}
