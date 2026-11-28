package broker

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/shutdown"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/token"
)

// revokeEndpoint is RFC 7009 token revocation (ADR-0006 §7). Revoking either token revokes the
// grant; an expired access token still names its grant, and revoking it ends the grant's refresh
// tokens, which is what a client revoking "its tokens" wants. Unknown, malformed or already
// revoked tokens get 200 (RFC 7009 §2.2); a token issued to another client is refused (§2.1) and
// its grant left alone; for an authenticated client, a store failure is 503 with Retry-After,
// never a false 200. A client refused at lookup (refusalReason) is 401 invalid_client, and the
// grant behind its own token still ends (revokeForRefusedRevocation). The IdP's tokens are
// deleted with the grant; revoking them at the IdP is not possible (no adapter has a revocation
// endpoint), so they simply expire there.
func (b *Broker) revokeEndpoint(w http.ResponseWriter, r *http.Request) {
	if !allowPost(w, r) {
		return
	}
	if retry, limited := b.throttled(w, r, ratelimit.Revoke); limited {
		writeTokenError(w, r, tokenError{http.StatusTooManyRequests, "temporarily_unavailable",
			"too many requests from this address; retry after " + strconv.Itoa(retry) + " s"})
		return
	}
	if err := r.ParseForm(); err != nil {
		if shutdown.AnswerIfEnded(w, r) { // a request that ended as its body was read is answered by how it ended, and is no failed request (#672)
			return
		}
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "the request body is not a valid form"})
		return
	}
	now := b.cfg.Now()
	// Detached: a revocation whose form was read finishes whatever the request's end, so a client
	// that closes as it signs out, or a shutdown, cannot leave the grant live in the store. The
	// client's lookup is part of it: a DCR client's is a store read (#693).
	ctx, cancel := detached(r.Context())
	defer cancel()
	client, ok := b.authenticateClient(ctx, w, r, now, b.revokeForRefusedRevocation)
	if !ok {
		return
	}
	tok := r.PostForm.Get("token")
	if tok == "" {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_request", "token is required"})
		return
	}
	grantID, owner, err := b.tokenGrant(ctx, tok, now)
	if err != nil {
		b.unavailable(w, r, "looking up a token to revoke failed", err)
		return
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
		b.revoked(r, client.ID(), grantID, "the client revoked a token (RFC 7009)")
	}
	if shutdown.AnswerIfEnded(w, r) { // the revocation is done; an ended request is answered by how it ended
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// revokeForRefusedRevocation revokes, with why, the grant behind the token a client refused at
// lookup (refusalReason) asks to revoke. The answer stays 401 (RFC 7009 §2.1), but the grant ends
// as the client asked and as a refresh by the same client would end it. Only the token's own
// client's grant is revoked; a store failure leaves it to the next request.
func (b *Broker) revokeForRefusedRevocation(r *http.Request, clientID string, now time.Time, why string) {
	ctx, cancel := detached(r.Context()) // the revocation's lookup finishes whatever the request's end (#693)
	defer cancel()
	grantID, owner, err := b.tokenGrant(ctx, r.PostForm.Get("token"), now)
	if err != nil || grantID == "" || owner != clientID {
		return
	}
	b.revoke(r, clientID, grantID, now, why)
}

// tokenGrant is the grant a refresh or access token names, and the client it was issued to. An
// unknown, malformed or already revoked token names none (empty grantID, nil error); err is a store
// failure. An expired access token still names its grant.
func (b *Broker) tokenGrant(ctx context.Context, tok string, now time.Time) (grantID, owner string, err error) {
	switch {
	case strings.HasPrefix(tok, token.RefreshPrefix):
		hash, ok := token.HashRefreshToken(tok)
		if !ok {
			return "", "", nil
		}
		rt, err := b.cfg.Store.RefreshToken(ctx, hash, now)
		if errors.Is(err, store.ErrNotFound) {
			return "", "", nil
		}
		return rt.GrantID, rt.ClientID, err
	case strings.HasPrefix(tok, token.AccessPrefix):
		claims, err := b.cfg.Sealer.Open(token.Access, tok)
		if err != nil {
			return "", "", nil
		}
		g, err := b.cfg.Store.Grant(ctx, claims.GrantID)
		if errors.Is(err, store.ErrNotFound) {
			return "", "", nil
		}
		return g.ID, g.ClientID, err
	}
	return "", "", nil
}
