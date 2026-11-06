package broker

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// silentAnswer is where a prompt=none request ended: the error the client got at its redirect URI
// (or "" for a code), with the state and iss that came with it.
type silentAnswer struct {
	error, state, iss, code string
}

func answerOf(t *testing.T, res *http.Response) silentAnswer {
	t.Helper()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), clientCB) {
		t.Fatalf("%d to %q, want a redirect to the client %s", res.StatusCode, res.Header.Get("Location"), clientCB)
	}
	q := loc.Query()
	return silentAnswer{error: q.Get("error"), state: q.Get("state"), iss: q.Get("iss"), code: q.Get("code")}
}

func silent(extra url.Values) url.Values {
	q := url.Values{"prompt": {"none"}}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

// prompt=none never shows the consent page: a request that cannot finish without the user gets an
// OAuth error at its validated redirect URI, with state and iss, before anything goes to the IdP.
// Without a hint the user is unknown before the IdP, so it is login_required (ADR-0010 §1).
func TestPromptNoneThatNeedsTheUserIsAnsweredWithoutAPage(t *testing.T) {
	for _, tc := range []struct {
		name, want, trust string
		extra             url.Values
		hint              bool
		storeDown         bool
		detrusted         bool // a consent was remembered while the client was trusted
	}{
		{"a client asked every time is refused with consent_required", "consent_required", "not-verified", url.Values{"client_id": {unverifiedID}}, true, false, false},
		{"a client no longer trusted is refused with consent_required, whatever is remembered", "consent_required", "not-verified", url.Values{"client_id": {unverifiedID}}, true, false, true},
		{"no hint cookie is refused with login_required", "login_required", "verified", nil, false, false, false},
		{"a hint without a consent covering the request is refused with consent_required", "consent_required", "verified", url.Values{"scope": {"mcp offline_access"}}, true, false, false},
		{"a store failure is answered with temporarily_unavailable", "temporarily_unavailable", "verified", nil, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counted := &consentOutcomes{}
			e := newEnv(t, withRemember(t, counted))
			var h *http.Cookie
			if tc.hint {
				h = e.remember(t, url.Values{"scope": {"mcp"}})
			}
			if tc.detrusted {
				g := user(e)
				if err := e.st.RememberConsent(context.Background(), store.Consent{Key: store.ConsentKey{Issuer: g.Issuer, Subject: g.Subject,
					ClientID: unverifiedID, Redirect: registration.RedirectKey(clientCB), Resource: resourceID}, Scopes: []string{"mcp"},
					ApprovedAt: e.now, ExpiresAt: e.now.Add(ConsentLifetime)}); err != nil {
					t.Fatal(err)
				}
			}
			e.st.down.Store(tc.storeDown)
			before := counted.list()
			res := e.authorizeWith(t, silent(tc.extra), h)
			if got := answerOf(t, res); got != (silentAnswer{error: tc.want, state: "client-state", iss: e.b.cfg.Issuer}) {
				t.Fatalf("answer %+v, want error %s with state and iss", got, tc.want)
			}
			e.oneAuditEvent(t, "consent_silent", map[string]any{"outcome": "failure", "reason": tc.want, "client_id": "*", "client_trust": tc.trust})
			if got := counted.list()[len(before):]; !slices.Equal(got, []string{tc.trust + " silent_refused"}) {
				t.Fatalf("consent outcomes %v, want only %q", got, tc.trust+" silent_refused")
			}
		})
	}
}

// prompt=none goes with no other prompt value (OIDC Core 1.0 §3.1.2.1).
func TestPromptNoneWithAnotherValueIsAnInvalidRequest(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	if got := answerOf(t, e.authorizeWith(t, url.Values{"prompt": {"none consent"}}, nil)); got.error != "invalid_request" {
		t.Fatalf("answer %+v, want invalid_request", got)
	}
}

// On a remembered consent prompt=none signs in without any page: the IdP is asked with its own
// prompt=none, and an IdP session gives the client a code.
func TestPromptNoneOnARememberedConsentSignsInSilently(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, nil)
	e.fake.Set(fakeidp.WithSilentSession())
	res := e.authorizeWith(t, silent(nil), h)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if !skipped(res) || loc.Query().Get("prompt") != "none" {
		t.Fatalf("authorize: %d to %s, want the IdP with prompt=none", res.StatusCode, loc)
	}
	if got := answerOf(t, e.finish(t, res)); got.error != "" || got.code == "" {
		t.Fatalf("callback answer %+v, want a code", got)
	}
}

// When the IdP's own prompt=none needs the user, the client gets the IdP's answer as it is and
// nothing is issued. The fake answers login_required unless told otherwise (it fails closed).
func TestPromptNonePassesTheIdPsSilentAnswerThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		idp  fakeidp.Option
		want string
	}{
		{"no IdP session", nil, "login_required"},
		{"the IdP needs interaction", fakeidp.WithSilentError("interaction_required"), "interaction_required"},
		{"the IdP needs an account choice", fakeidp.WithSilentError("account_selection_required"), "account_selection_required"},
		{"the IdP needs its own consent", fakeidp.WithSilentError("consent_required"), "consent_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, withRemember(t, nil))
			h := e.remember(t, nil)
			if tc.idp != nil {
				e.fake.Set(tc.idp)
			}
			grants := len(e.st.ids)
			res := e.authorizeWith(t, silent(nil), h)
			if got := answerOf(t, e.finish(t, res)); got != (silentAnswer{error: tc.want, state: "client-state", iss: e.b.cfg.Issuer}) {
				t.Fatalf("answer %+v, want %s with state and iss", got, tc.want)
			}
			if len(e.st.ids) != grants {
				t.Fatal("a grant was created")
			}
			e.oneAuditEvent(t, "consent_silent", map[string]any{"outcome": "failure", "reason": tc.want, "client_id": clientID})
		})
	}
}

// Someone else signing in silently behind a stale hint gets consent_required and no code, never the
// page; the hint is cleared and the mismatch audited as for an interactive sign-in.
func TestPromptNoneForAnotherUserBehindAStaleHintGetsConsentRequired(t *testing.T) {
	e := newEnv(t, withRemember(t, nil))
	h := e.remember(t, nil)
	grants := len(e.st.ids)
	e.fake.Set(fakeidp.WithUser(fakeidp.User{OID: fakeidp.NewGUID(), Name: "Mallory"}), fakeidp.WithSilentSession())
	back := e.finish(t, e.authorizeWith(t, silent(nil), h))
	if got := answerOf(t, back); got.error != "consent_required" || got.code != "" {
		t.Fatalf("answer %+v, want consent_required and no code", got)
	}
	if c := hintIn(e, back); c == nil || c.MaxAge >= 0 {
		t.Fatalf("hint not cleared: %+v", c)
	}
	if len(e.st.ids) != grants {
		t.Fatal("a grant was created for the user behind a stale hint")
	}
	e.oneAuditEvent(t, "consent_remembered", map[string]any{"outcome": "failure", "reason": hintUserMismatch, "client_id": clientID, "user_key": "*"})
	e.oneAuditEvent(t, "consent_silent", map[string]any{"outcome": "failure", "reason": "consent_required", "client_id": clientID})
}
