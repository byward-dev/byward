package broker

import (
	"net/http"
	"slices"
	"strings"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
)

// Silent sign-in (#126; OIDC Core 1.0 §3.1.2.1 prompt=none). The consent page is never shown:
// a request that needs the user gets an OAuth error at its validated redirect URI instead. Only a
// remembered consent for the user the hint cookie names lets it proceed, and then the IdP is asked
// with its own prompt=none. Without a hint the user is unknown before the IdP, and nothing goes to
// the IdP before consent is established (ADR-0010 §1), so the answer is login_required.

// ConsentOutcomeSilentRefused counts a prompt=none request answered with an error.
const ConsentOutcomeSilentRefused = "silent_refused"

// silentIdPErrors are the IdP's answers to its own prompt=none that are passed to the client as
// they are (OIDC Core 1.0 §3.1.2.6).
var silentIdPErrors = []string{"login_required", "interaction_required", "consent_required", "account_selection_required"}

// promptValues returns the prompt parameter's space-separated values.
func promptValues(prompt string) []string { return strings.Fields(prompt) }

// wantsSilent reports whether the request asks for prompt=none.
func wantsSilent(prompt string) bool { return slices.Contains(promptValues(prompt), "none") }

// authorizeSilently handles prompt=none once the request is valid: it starts a silent IdP sign-in
// on a remembered consent, or answers the error that says why it cannot.
func (b *Broker) authorizeSilently(w http.ResponseWriter, r *http.Request, client registration.Client, l login) {
	if !b.remembers(client) { // a client asked every time (ASVS 5.0.0 10.7.1)
		b.refuseSilently(w, r, client, l, "consent_required", "this client must be approved by the user each time")
		return
	}
	h, ok := b.readHint(r)
	if !ok {
		b.refuseSilently(w, r, client, l, "login_required", "the user must sign in")
		return
	}
	ok, err := b.remembered(r.Context(), h, l, b.cfg.Now())
	switch {
	case err != nil:
		b.cfg.Log.WarnContext(r.Context(), "checking remembered consent failed", "request_id", logging.RequestID(r.Context()), "error", err.Error())
		b.refuseSilently(w, r, client, l, "temporarily_unavailable", "the proxy could not check the consent; try again")
		return
	case !ok:
		b.refuseSilently(w, r, client, l, "consent_required", "the user has not approved this request")
		return
	}
	l.Hint, l.Silent = &h, true
	b.startLogin(w, r, l, b.cfg.Now())
}

// refuseSilently answers a prompt=none request with code at its validated redirect URI, audited
// and counted. client may be nil after the callback, when the request's client is not re-read.
func (b *Broker) refuseSilently(w http.ResponseWriter, r *http.Request, client registration.Client, l login, code, desc string) {
	ev := audit.Event{Name: audit.ConsentSilent, Outcome: audit.Failure, Reason: code, ClientID: l.ClientID, IdP: b.cfg.IdPName}
	trust := registration.TrustLevel("")
	if client != nil {
		trust = client.Trust()
		ev.ClientTrust = string(trust)
	}
	b.cfg.Audit.Record(r, ev)
	b.observeConsent(trust, ConsentOutcomeSilentRefused)
	b.redirectError(w, r, l.RedirectURI, l.State, code, desc)
}
