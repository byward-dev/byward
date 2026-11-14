package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
)

// Remembered consent (ADR-0010 §2-3). Static clients and trusted CIMD hosts are asked once; the
// answer is kept in the store per user, client, redirect key and resource for ConsentLifetime.
// Before the IdP sign-in the user is not known, so a sealed hint cookie names the user the browser
// last signed in as. It only lets /authorize skip the page: the callback checks the registry again
// for the user who actually signed in, and on any mismatch issues nothing and shows the page.

// Why a remembered consent did not hold after the sign-in (the audit reason).
const (
	hintUserMismatch  = "user_mismatch"  // someone else signed in than the hint named
	hintNotRemembered = "not_remembered" // no live consent covers the request any more, or it could not be checked
)

// hint names a user of an IdP; it is sealed in the hint cookie and carried in the login.
type hint struct {
	Issuer  string `json:"i"`
	Subject string `json:"s"`
}

// remembers reports whether consent for client may be remembered: only for clients whose identity
// is assured (ADR-0008 trust levels; ASVS 5.0.0 10.7.1). Trust is read live, so an operator who
// removes a host from the trusted list makes its users answer again.
func (b *Broker) remembers(client registration.Client) bool {
	return b.cfg.ConsentHintBox != nil && client.Trust() == registration.Verified
}

// forcesConsent reports whether the request asks for the page whatever is remembered (OIDC Core
// 1.0 §3.1.2.1 prompt=consent). Other prompt values are ignored.
func forcesConsent(prompt string) bool { return slices.Contains(strings.Fields(prompt), "consent") }

func (b *Broker) consentKey(h hint, l login) store.ConsentKey {
	return store.ConsentKey{Issuer: h.Issuer, Subject: h.Subject, ClientID: l.ClientID, Redirect: registration.RedirectKey(l.RedirectURI),
		Resource: b.cfg.Resource.String()}
}

// remembered reports whether a live consent of h covers l's request: same key, every scope the page
// would approve (consentScopes, for a client that may refresh or not) approved, not expired.
func (b *Broker) remembered(ctx context.Context, h hint, l login, allowsRefresh bool, now time.Time) (bool, error) {
	c, err := b.cfg.Store.Consent(ctx, b.consentKey(h, l))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	if !now.Before(c.ExpiresAt) {
		return false, nil
	}
	for _, s := range consentScopes(l.Scopes, allowsRefresh) {
		if !slices.Contains(c.Scopes, s) {
			return false, nil
		}
	}
	return true, nil
}

// skipConsent decides at /authorize whether the page may be skipped: a client whose consent is
// remembered, no prompt=consent, and a hint naming a user with a live consent for this request.
// It sets l.Hint for the callback's check. A store failure shows the page.
func (b *Broker) skipConsent(r *http.Request, client registration.Client, l *login) bool {
	if !b.remembers(client) || forcesConsent(r.URL.Query().Get("prompt")) {
		return false
	}
	h, ok := b.readHint(r)
	if !ok {
		return false
	}
	ok, err := b.remembered(r.Context(), h, *l, l.Refresh, b.cfg.Now())
	if err != nil {
		b.cfg.Log.WarnContext(r.Context(), "checking remembered consent failed; asking", "request_id", logging.RequestID(r.Context()), "error", err.Error())
		return false
	}
	if ok {
		l.Hint = &h
	}
	return ok
}

// confirmRemembered is the callback's check of a login that skipped the page: the user who signed
// in is the one the hint named, the client is still one whose consent is remembered, and a live
// consent still covers the request. It returns the client when it holds, or the audit reason, with
// the lookup error when the check could not be made (a store or registry failure).
func (b *Broker) confirmRemembered(ctx context.Context, l login, id idp.Identity) (registration.Client, string, error) {
	if l.Hint.Issuer != id.Issuer || l.Hint.Subject != id.Subject {
		return nil, hintUserMismatch, nil
	}
	client, err := b.cfg.Clients.Client(ctx, l.ClientID)
	switch {
	case err != nil && !errors.Is(err, registration.ErrUnknownClient):
		return nil, hintNotRemembered, err
	case err != nil || !b.remembers(client) || client.RedirectAllowed(l.RedirectURI) != nil:
		return nil, hintNotRemembered, nil
	}
	// The registration now, not l.Refresh: a client that registered the grant since /authorize is
	// asked again, on a page that still states the lifetime the login started with (#287).
	ok, err := b.remembered(ctx, hint{Issuer: id.Issuer, Subject: id.Subject}, l, client.AllowsRefresh(), b.cfg.Now())
	if err != nil {
		b.cfg.Log.WarnContext(ctx, "checking remembered consent failed", "request_id", logging.RequestID(ctx), "error", err.Error())
		return nil, hintNotRemembered, err
	}
	if !ok {
		return nil, hintNotRemembered, nil
	}
	return client, "", nil
}

// askAfterMismatch handles a login that skipped the page when the callback's check failed: it
// issues nothing (the IdP tokens of this sign-in are dropped), forgets the hint and shows the page
// for the same request, which leads to a new IdP sign-in after Allow. A prompt=none login gets no
// page: consent_required, or temporarily_unavailable keeping the hint when lookupErr says the
// check could not be made.
func (b *Broker) askAfterMismatch(w http.ResponseWriter, r *http.Request, l login, id idp.Identity, reason string, lookupErr error) {
	b.cfg.Audit.Record(r, audit.Event{Name: audit.ConsentRemembered, Outcome: audit.Failure, Reason: reason, ClientID: l.ClientID,
		UserKey: id.Subject, IdP: b.cfg.IdPName})
	if l.Silent && lookupErr != nil {
		b.refuseSilently(w, r, "", l, "temporarily_unavailable", "the proxy could not check the consent; try again")
		return
	}
	b.clearHint(w)
	if l.Silent {
		b.refuseSilently(w, r, "", l, "consent_required", "the user has not approved this request")
		return
	}
	client, ok := b.loadClient(w, r, l.ClientID, l.RedirectURI)
	if !ok {
		return
	}
	// A fresh IdP login: the one just used is spent.
	l.Hint, l.IdPState, l.Nonce, l.Verifier = nil, randomID()+randomID(), randomID(), randomID()+randomID()
	b.showConsent(w, r, client, l)
}

// afterGrant records the consent side of a sign-in once its grant exists: a remembered consent is
// audited and counted (and not renewed: its 30 days run from the Allow); an Allow on the page is
// remembered for a client whose consent may be.
func (b *Broker) afterGrant(w http.ResponseWriter, r *http.Request, l login, id idp.Identity, grantID string, remembered registration.Client, now time.Time) {
	if remembered != nil {
		b.cfg.Audit.Record(r, audit.Event{Name: audit.ConsentRemembered, Outcome: audit.Success, ClientID: l.ClientID,
			ClientTrust: string(remembered.Trust()), UserKey: id.Subject, GrantID: grantID, IdP: b.cfg.IdPName})
		b.observeConsent(remembered.Trust(), ConsentOutcomeRemembered)
		return
	}
	b.rememberAllow(w, r, l, id, now)
}

// consentScopes are what the user approves on the page: the requested scopes but offline_access, and
// offline_access exactly when the page says "up to 30 days" (allowsRefresh: a client that registered
// the refresh_token grant), whether or not it was requested (#287). A consent given while the page
// said "up to 1 hour" so never covers a grant that refreshes.
func consentScopes(scopes []string, allowsRefresh bool) []string {
	out := slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == "offline_access" })
	if allowsRefresh {
		out = append(out, "offline_access")
	}
	return out
}

// rememberAllow keeps the user's Allow, for a client whose consent is remembered, and points the
// hint at this user. A failure only means asking next time.
func (b *Broker) rememberAllow(w http.ResponseWriter, r *http.Request, l login, id idp.Identity, now time.Time) {
	ctx := r.Context()
	client, err := b.cfg.Clients.Client(ctx, l.ClientID)
	if err != nil || !b.remembers(client) {
		return
	}
	h := hint{Issuer: id.Issuer, Subject: id.Subject}
	if err := b.cfg.Store.RememberConsent(ctx, store.Consent{Key: b.consentKey(h, l), Scopes: consentScopes(l.Scopes, l.Refresh), ApprovedAt: now,
		ExpiresAt: now.Add(ConsentLifetime)}); err != nil {
		b.cfg.Log.WarnContext(ctx, "remembering consent failed; the user will be asked again", "request_id", logging.RequestID(ctx), "error", err.Error())
		return
	}
	b.setHint(w, h, now)
}

// hintCookie is the hint cookie's name; like the binding cookie's it carries the instance ID.
func (b *Broker) hintCookie() string {
	sum := sha256.Sum256([]byte(b.cfg.Issuer))
	name := "byw_hint_" + hex.EncodeToString(sum[:4])
	if b.cfg.SecureCookies {
		return "__Host-" + name
	}
	return name
}

func (b *Broker) readHint(r *http.Request) (hint, bool) {
	c, err := r.Cookie(b.hintCookie())
	if err != nil {
		return hint{}, false
	}
	plain, err := b.cfg.ConsentHintBox.Open(c.Value)
	var h hint
	if err != nil || json.Unmarshal(plain, &h) != nil { // a hint naming nobody matches no consent
		return hint{}, false
	}
	return h, true
}

func (b *Broker) setHint(w http.ResponseWriter, h hint, now time.Time) {
	plain, _ := json.Marshal(h)
	sealed, err := b.cfg.ConsentHintBox.Seal(plain, now.Add(ConsentLifetime))
	if err != nil {
		return
	}
	//nolint:gosec // G124: Secure is false only in development mode on loopback http (ADR-0010 §10)
	http.SetCookie(w, &http.Cookie{Name: b.hintCookie(), Value: sealed, Path: "/", MaxAge: int(ConsentLifetime.Seconds()),
		HttpOnly: true, Secure: b.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
}

func (b *Broker) clearHint(w http.ResponseWriter) {
	//nolint:gosec // G124: as above
	http.SetCookie(w, &http.Cookie{Name: b.hintCookie(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: b.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode})
}
