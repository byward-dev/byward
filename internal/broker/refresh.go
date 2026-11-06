package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/token"
)

// refresh is grant_type=refresh_token (ADR-0006 §4–6). Every refresh also refreshes the IdP tokens,
// so a grant never outlives the IdP session, and re-runs the access gate with the fresh claims.
// An IdP outage answers 503 without spending the refresh token.
func (b *Broker) refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := r.PostForm
	now := b.cfg.Now()
	client, ok := b.authenticateClient(w, r, now, b.revokeForRefusedMetadata)
	if !ok {
		return
	}
	if !client.AllowsRefresh() {
		b.tokenFail(w, r, tokenError{http.StatusBadRequest, "unauthorized_client", "this client did not register the refresh_token grant"})
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
		if sealed != nil {
			b.keepIdPTokens(r, g.ID, sealed)
		}
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
		b.keepIdPTokens(r, g.ID, sealed) // the IdP may have revoked the tokens the grant holds
		b.unavailable(w, r, "rotating a refresh token failed", err)
		return
	}
	b.recordUse(ctx, client, now)
	b.issue(w, r, client.ID(), g.ID, g.Subject, now, g.ExpiresAt, scopes, next)
}

// refreshIdP renews the grant's IdP tokens and re-checks the user (ADR-0006 §6, ADR-0012). It
// returns the new sealed IdP tokens, or the error to send; when the IdP says the user must sign in
// again, or the identity no longer matches or passes the gate, the grant is revoked. When the gate
// cannot decide, it returns the error together with the sealed new tokens, for the caller to keep.
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
	if fresh.RefreshToken == "" {
		fresh.RefreshToken = old.RefreshToken // the IdP kept its refresh token (idp.Refresher)
	}
	failed := tokenError{http.StatusInternalServerError, "server_error", "the proxy could not refresh the sign-in"}
	if err := b.cfg.Gate.Allow(ctx, *id); err != nil {
		var d Denial
		if !errors.As(err, &d) {
			// A failure to decide is not a denial (the Gate contract): keep the grant and our refresh
			// token, and the IdP's new tokens, since the IdP may have revoked the ones the grant holds.
			// That grants nothing: only a refresh reads them, and it runs the gate again.
			b.cfg.Log.ErrorContext(ctx, "the access gate could not decide on refresh", "request_id", logging.RequestID(ctx), "error", err)
			sealed, _ := b.sealIdPTokens(ctx, g, fresh) // nil when sealing fails: nothing to keep
			return sealed, failed, false
		}
		b.cfg.Audit.Record(r, audit.Event{Name: audit.AccessDenied, Outcome: audit.Failure, Reason: d.DeniedRule(),
			ClientID: g.ClientID, UserKey: id.Subject, IdP: b.cfg.IdPName, GrantID: g.ID})
		return end("the access gate refused the user on refresh; grant revoked", "")
	}
	sealed, err := b.sealIdPTokens(ctx, g, fresh)
	if err != nil {
		// The IdP's new tokens are lost: nothing safe is left to store. With an IdP whose refresh
		// tokens are single use, the next refresh fails and the user signs in again (#92).
		return nil, failed, false
	}
	return sealed, tokenError{}, true
}

// sealIdPTokens seals the grant's IdP tokens for the store (ADR-0006 §8), logging a failure.
func (b *Broker) sealIdPTokens(ctx context.Context, g store.Grant, t idp.Tokens) ([]byte, error) {
	tokJSON, _ := json.Marshal(t) //nolint:gosec // G117: marshalled only to be sealed below
	sealed, err := b.cfg.IdPTokenBox.Seal(tokJSON, g.ExpiresAt)
	if err != nil {
		b.cfg.Log.ErrorContext(ctx, "sealing IdP tokens failed", "request_id", logging.RequestID(ctx), "error", err)
		return nil, err
	}
	return []byte(sealed), nil
}

// keepIdPTokensTimeout bounds the detached store write in keepIdPTokens.
const keepIdPTokensTimeout = 5 * time.Second

// keepIdPTokens stores the IdP's new tokens for a refresh that renewed them but failed afterwards,
// so an IdP that revoked the old refresh token does not force a new sign-in (#92). It is best
// effort: the refresh fails either way, and a grant revoked meanwhile stays revoked.
func (b *Broker) keepIdPTokens(r *http.Request, grantID string, sealed []byte) {
	ctx := r.Context()
	// Detached from cancellation: a client that gave up is a common reason the refresh failed, and
	// the IdP has already spent the old token either way.
	keep, cancel := context.WithTimeout(context.WithoutCancel(ctx), keepIdPTokensTimeout)
	defer cancel()
	if err := b.cfg.Store.SetIdPTokens(keep, grantID, sealed); err != nil && !errors.Is(err, store.ErrNotFound) {
		b.cfg.Log.WarnContext(ctx, "keeping the IdP's new tokens failed", "request_id", logging.RequestID(ctx), "error", err)
	}
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

// revokeForRefusedMetadata applies draft-ietf-oauth-client-id-metadata-document-03 §6.1: when a CIMD
// client's metadata is now definitely refused (its document mismatches, is invalid or gone), the
// grant behind the refresh token it presents is revoked, so restoring the document cannot revive
// it. Only a terminal failure gets here; a transient fetch failure never revokes.
func (b *Broker) revokeForRefusedMetadata(r *http.Request, clientID string, now time.Time) {
	hash, ok := token.HashRefreshToken(r.PostForm.Get("refresh_token"))
	if !ok {
		return
	}
	rt, err := b.cfg.Store.RefreshToken(r.Context(), hash, now)
	if err != nil || rt.ClientID != clientID {
		return
	}
	unlock := b.lockGrant(rt.GrantID)
	defer unlock()
	b.revoke(r, clientID, rt.GrantID, now, "client metadata no longer valid")
}
