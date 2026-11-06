package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/token"
)

// refresh is grant_type=refresh_token (ADR-0006 §4–6). Every refresh also refreshes the IdP tokens,
// so a grant never outlives the IdP session, and re-runs the access gate with the fresh claims.
// An IdP outage answers 503 without spending the refresh token.
func (b *Broker) refresh(w http.ResponseWriter, r *http.Request) {
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
	invalid := tokenError{http.StatusBadRequest, "invalid_grant", "the refresh token is invalid or expired"}
	hash, ok := token.HashRefreshToken(f.Get("refresh_token"))
	if !ok {
		b.tokenFail(w, r, invalid)
		return
	}
	rt, err := b.cfg.Store.RefreshToken(ctx, hash, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b.tokenFail(w, r, invalid)
		return
	case err != nil:
		b.unavailable(w, r, "looking up a refresh token failed", err)
		return
	}
	if rt.ClientID != client.ID() {
		// RFC 6749 §6: bound to the client it was issued to. Not a reason to revoke: the caller
		// may simply be another client holding a leaked token.
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_grant", "the refresh token was issued to another client"})
		return
	}
	unlock := b.lockGrant(rt.GrantID)
	defer unlock()
	if !rt.RotatedAt.IsZero() && now.Sub(rt.RotatedAt) >= b.cfg.RefreshGrace {
		// Clear reuse: revoke without calling the IdP. Retries within the window go on, and the
		// store decides atomically below.
		b.revoke(r, client.ID(), rt.GrantID, now, "refresh token reused; grant revoked")
		b.tokenFail(w, r, invalid)
		return
	}
	g, err := b.cfg.Store.Grant(ctx, rt.GrantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b.tokenFail(w, r, invalid)
		return
	case err != nil:
		b.unavailable(w, r, "loading a grant failed", err)
		return
	case !now.Before(g.ExpiresAt):
		b.tokenFail(w, r, invalid)
		return
	}
	scopes, ok := narrowScopes(f.Get("scope"), g.Scopes)
	if !ok {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "invalid_scope", "the requested scope exceeds the grant"})
		return
	}
	sealed, e, ok := b.refreshIdP(r, g, now)
	if !ok {
		b.tokenFail(w, r, e)
		return
	}
	next, nextHash := token.NewRefreshToken()
	err = b.cfg.Store.RotateRefreshToken(ctx, store.RotateRequest{Old: hash, Now: now, Grace: b.cfg.RefreshGrace, IdPTokens: sealed,
		Next: store.RefreshToken{Hash: nextHash, GrantID: g.ID, ClientID: client.ID(), CreatedAt: now,
			IdleExpiresAt: minTime(now.Add(RefreshIdleLifetime), g.ExpiresAt)}})
	switch {
	case errors.Is(err, store.ErrReused):
		b.deny.Add(g.ID) // the store revoked it in the same step
		b.cfg.Log.WarnContext(ctx, "refresh token reused; grant revoked", "request_id", logging.RequestID(ctx))
		b.cfg.Audit.Record(r, audit.Event{Name: audit.GrantRevoked, Outcome: audit.Success, Reason: "refresh token reused; grant revoked", ClientID: client.ID(), GrantID: g.ID})
		b.tokenFail(w, r, invalid)
		return
	case errors.Is(err, store.ErrNotFound):
		b.tokenFail(w, r, invalid)
		return
	case err != nil:
		b.unavailable(w, r, "rotating a refresh token failed", err)
		return
	}
	b.issue(w, r, client.ID(), g.ID, g.Subject, now, g.ExpiresAt, scopes, next)
}

// refreshIdP renews the grant's IdP tokens and re-checks the user (ADR-0006 §6, ADR-0012). It
// returns the new sealed IdP tokens, or the error to send; when the IdP says the user must sign in
// again, or the identity no longer matches or passes the gate, the grant is revoked.
func (b *Broker) refreshIdP(r *http.Request, g store.Grant, now time.Time) ([]byte, tokenError, bool) {
	ctx := r.Context()
	signInAgain := tokenError{http.StatusBadRequest, "invalid_grant", "sign in again"}
	end := func(why, hint string) ([]byte, tokenError, bool) {
		b.revoke(r, g.ClientID, g.ID, now, why)
		if hint != "" {
			b.cfg.Log.WarnContext(ctx, why, "request_id", logging.RequestID(ctx), "reason", hint)
		}
		return nil, signInAgain, false
	}
	plain, err := b.cfg.IdPTokenBox.Open(string(g.IdPTokens))
	var old idp.Tokens
	if err != nil || json.Unmarshal(plain, &old) != nil || old.RefreshToken == "" {
		return end("the grant holds no usable IdP refresh token; grant revoked", "")
	}
	start := time.Now()
	id, fresh, err := b.cfg.IdP.Refresh(idp.WithRequestID(ctx, logging.RequestID(ctx)), old.RefreshToken)
	b.cfg.ObserveIdP("refresh", idpOutcome(err), time.Since(start))
	if err != nil {
		var ie *idp.Error
		switch {
		case errors.As(err, &ie) && ie.Class == idp.SignInAgain:
			return end("the IdP ended the session; grant revoked", ie.OperatorHint)
		case errors.As(err, &ie) && ie.Class == idp.Unavailable:
			b.cfg.Log.WarnContext(ctx, "IdP refresh unavailable", "request_id", logging.RequestID(ctx), "error", err, "reason", ie.OperatorHint)
			return nil, tokenError{http.StatusServiceUnavailable, "temporarily_unavailable", "the identity provider is unavailable; try again"}, false
		default:
			b.cfg.Log.ErrorContext(ctx, "IdP refresh failed", "request_id", logging.RequestID(ctx), "error", err)
			return nil, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not refresh the sign-in"}, false
		}
	}
	switch {
	case id == nil:
		return end("the IdP returned no ID token on refresh; grant revoked",
			"check that openid is in the scopes the IdP app requests")
	case id.Subject != g.Subject || id.Issuer != g.Issuer:
		return end("the IdP returned another user on refresh; grant revoked", "OIDC Core §12.2: sub and iss must not change")
	}
	if err := b.cfg.Gate.Allow(ctx, *id); err != nil {
		var d Denial
		if !errors.As(err, &d) {
			// A failure to decide is not a denial (the Gate contract): keep the grant and our refresh
			// token. The IdP's new tokens are dropped, so with an IdP whose refresh tokens are single
			// use the next refresh fails and the user signs in again.
			b.cfg.Log.ErrorContext(ctx, "the access gate could not decide on refresh", "request_id", logging.RequestID(ctx), "error", err)
			return nil, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not refresh the sign-in"}, false
		}
		b.cfg.Audit.Record(r, audit.Event{Name: audit.AccessDenied, Outcome: audit.Failure, Reason: d.DeniedRule(),
			ClientID: g.ClientID, UserKey: id.Subject, IdP: b.cfg.IdPName, GrantID: g.ID})
		return end("the access gate refused the user on refresh; grant revoked", "")
	}
	if fresh.RefreshToken == "" {
		fresh.RefreshToken = old.RefreshToken // the IdP kept its refresh token (idp.Refresher)
	}
	tokJSON, _ := json.Marshal(fresh) //nolint:gosec // G117: marshalled only to be sealed below
	sealed, err := b.cfg.IdPTokenBox.Seal(tokJSON, g.ExpiresAt)
	if err != nil {
		b.cfg.Log.ErrorContext(ctx, "sealing IdP tokens failed", "request_id", logging.RequestID(ctx), "error", err)
		return nil, tokenError{http.StatusInternalServerError, "server_error", "the proxy could not refresh the sign-in"}, false
	}
	return []byte(sealed), tokenError{}, true
}

// narrowScopes returns the requested scopes when they are a subset of the grant's (RFC 6749 §6),
// or the grant's when none were requested.
func narrowScopes(requested string, granted []string) ([]string, bool) {
	if requested == "" {
		return granted, true
	}
	want := strings.Fields(requested)
	for _, s := range want {
		if !slices.Contains(granted, s) {
			return nil, false
		}
	}
	return want, true
}
